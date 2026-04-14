// SPDX-License-Identifier: GPL-2.0-only
/*
 * MediaTek PPE Hardware NAT offload engine
 *
 * Hooks into NF_INET_FORWARD to learn established flows and program them
 * into the PPE FOE table for zero-CPU hardware acceleration.
 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_ppe.h>
#include <net/dsa.h>
#include <net/dst.h>
#include <net/neighbour.h>

#include "mtk_eth_soc.h"
#include "mtk_ppe.h"
#include "mtk_ppe_hnat.h"

/* HNAT offload context */
struct mtk_ppe_hnat {
	struct mtk_eth *eth;
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	struct nf_ct_event_notifier ct_nb;
#endif
};

static struct mtk_ppe_hnat *hnat_ctx;

#ifdef CONFIG_NF_CONNTRACK_EVENTS
/*
 * Conntrack destroy notifier — clean up our FOE entry when the
 * conntrack dies, preventing memory leaks.
 */
static int mtk_ppe_nf_ct_event(unsigned int events, const struct nf_ct_event *item)
{
	struct nf_conn *ct = item->ct;
	struct nf_conn_ppe *ppe;
	int i;

	if (!hnat_ctx || !ct)
		return 0;

	if (!(events & (1 << IPCT_DESTROY)))
		return 0;

	ppe = nf_ct_ppe_find(ct);
	if (!ppe)
		return 0;

	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		if (ppe->entries[i]) {
			mtk_foe_entry_clear(hnat_ctx->eth->ppe[0], ppe->entries[i]);
			kfree(ppe->entries[i]);
			ppe->entries[i] = NULL;
		}
	}

	return 0;
}
#endif

static int mtk_ppe_resolve_path(struct mtk_eth *eth, struct mtk_foe_entry *foe,
				struct net_device *dev, u8 *mac)
{
	struct net_device_path_stack stack;
	struct net_device *lower;
	struct list_head *iter;
	struct dsa_port *dp;
	int i;

	/*
	 * Primary path: walk the full forwarding path stack. Works for direct
	 * DSA slaves (e.g. wan, lan3) and for bridge devices when the FDB has
	 * already learned the destination MAC (i.e. established LAN flows).
	 */
	if (!dev_fill_forward_path(dev, mac, &stack)) {
		for (i = 0; i < stack.num_paths; i++) {
			struct net_device_path *path = &stack.path[i];

			if (path->type == DEV_PATH_DSA) {
				pr_debug("PPE resolve: dev=%s DSA port=%d (path)\n",
					 dev->name, path->dsa.port);
				mtk_foe_entry_set_dsa(eth, foe, path->dsa.port);
			} else if (path->type == DEV_PATH_VLAN) {
				mtk_foe_entry_set_vlan(eth, foe, path->encap.id);
			}
		}
		return 0;
	}

	/*
	 * Bridge fallback: dev_fill_forward_path() fails when the bridge FDB
	 * has no entry for the destination MAC, which happens in the REPLY
	 * direction when state->in is br0 and the destination is a WAN-side
	 * MAC not learned by the LAN bridge.
	 *
	 * In this case, pick the first active DSA slave of the bridge. The
	 * MT7531 switch handles within-LAN forwarding in hardware, so any
	 * active member port is a valid egress for PPE purposes.
	 */
	if (!netif_is_bridge_master(dev))
		return -EINVAL;

	rcu_read_lock();
	netdev_for_each_lower_dev(dev, lower, iter) {
		if (!dsa_user_dev_check(lower))
			continue;
		if (!netif_running(lower) || !netif_carrier_ok(lower))
			continue;
		dp = dsa_port_from_netdev(lower);
		if (IS_ERR_OR_NULL(dp))
			continue;
		pr_debug("PPE resolve: dev=%s bridge fallback DSA port=%d (via %s)\n",
			 dev->name, dp->index, lower->name);
		mtk_foe_entry_set_dsa(eth, foe, dp->index);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	return -ENODEV;
}

static unsigned int mtk_ppe_nf_hook(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	struct mtk_eth *eth = hnat_ctx->eth;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_ppe *ppe;
	struct mtk_flow_entry *entries[2] = { NULL, NULL };
	struct net_device *in_dev = state->in;
	struct net_device *out_dev = state->out;
	int i, l4proto;
	u8 pse_port = 1; /* GMAC1 / Switch */
	u8 dest_mac[2][ETH_ALEN];
	struct dst_entry *dst;
	struct neighbour *n;
	bool is_ipv4 = false;

	if (!eth || !in_dev || !out_dev)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;

	/* Pre-allocate extension if missing */
	ppe = nf_ct_ppe_find(ct);
	if (!ppe) {
		if (nf_ct_is_confirmed(ct))
			return NF_ACCEPT;
		ppe = nf_ct_ext_add(ct, NF_CT_EXT_PPE, GFP_ATOMIC);
		return NF_ACCEPT;
	}

	/* Skip if already offloaded or not yet assured */
	if (ppe->entries[0] || ppe->entries[1])
		return NF_ACCEPT;

	if (!test_bit(IPS_ASSURED_BIT, &ct->status))
		return NF_ACCEPT;

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		l4proto = iph->protocol;
		if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
			return NF_ACCEPT;
		is_ipv4 = true;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		l4proto = ip6h->nexthdr;
		if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
			return NF_ACCEPT;
	} else {
		return NF_ACCEPT;
	}

	/* Resolve Forward Direction MAC */
	dst = skb_dst(skb);
	if (!dst)
		return NF_ACCEPT;

	if (is_ipv4)
		n = dst_neigh_lookup(dst, &ip_hdr(skb)->daddr);
	else
		n = dst_neigh_lookup(dst, &ipv6_hdr(skb)->daddr);

	if (!n)
		return NF_ACCEPT;

	read_lock_bh(&n->lock);
	if (!(n->nud_state & NUD_VALID)) {
		read_unlock_bh(&n->lock);
		neigh_release(n);
		return NF_ACCEPT;
	}
	memcpy(dest_mac[0], n->ha, ETH_ALEN);
	read_unlock_bh(&n->lock);
	neigh_release(n);

	/* Use original skb source MAC for Reply Direction dest_mac */
	memcpy(dest_mac[1], eth_hdr(skb)->h_source, ETH_ALEN);

	/* Resolve both directions */
	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		struct mtk_foe_entry *foe;
		struct net_device *tdev = i == 0 ? out_dev : in_dev;
		int type;

		entries[i] = kzalloc(sizeof(*entries[i]), GFP_ATOMIC);
		if (!entries[i])
			goto err_out;

		entries[i]->type = MTK_FLOW_TYPE_L4;
		foe = &entries[i]->data;

		type = is_ipv4 ? MTK_PPE_PKT_TYPE_IPV4_HNAPT :
				 MTK_PPE_PKT_TYPE_IPV6_ROUTE_5T;

		mtk_foe_entry_prepare(eth, foe, type, l4proto, pse_port,
				      (u8 *)tdev->dev_addr, dest_mac[i]);

		if (is_ipv4) {
			int dir = (i == 0) ? IP_CT_DIR_ORIGINAL : IP_CT_DIR_REPLY;
			int rev = (i == 0) ? IP_CT_DIR_REPLY : IP_CT_DIR_ORIGINAL;

			mtk_foe_entry_set_ipv4_tuple(eth, foe, false,
				ct->tuplehash[dir].tuple.src.u3.ip,
				ct->tuplehash[dir].tuple.src.u.all,
				ct->tuplehash[dir].tuple.dst.u3.ip,
				ct->tuplehash[dir].tuple.dst.u.all);

			mtk_foe_entry_set_ipv4_tuple(eth, foe, true,
				ct->tuplehash[rev].tuple.dst.u3.ip,
				ct->tuplehash[rev].tuple.dst.u.all,
				ct->tuplehash[rev].tuple.src.u3.ip,
				ct->tuplehash[rev].tuple.src.u.all);
		} else {
			int dir = (i == 0) ? IP_CT_DIR_ORIGINAL : IP_CT_DIR_REPLY;

			mtk_foe_entry_set_ipv6_tuple(eth, foe,
				ct->tuplehash[dir].tuple.src.u3.in6.s6_addr32,
				ct->tuplehash[dir].tuple.src.u.all,
				ct->tuplehash[dir].tuple.dst.u3.in6.s6_addr32,
				ct->tuplehash[dir].tuple.dst.u.all);
		}

		if (mtk_ppe_resolve_path(eth, foe, tdev, dest_mac[i]))
			goto err_out;

		if (mtk_foe_entry_commit(eth->ppe[0], entries[i]))
			goto err_out;

		ppe->entries[i] = entries[i];
	}

	return NF_ACCEPT;

err_out:
	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		if (entries[i]) {
			if (ppe->entries[i] == entries[i])
				ppe->entries[i] = NULL;
			mtk_foe_entry_clear(eth->ppe[0], entries[i]);
			kfree(entries[i]);
		}
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops mtk_ppe_nf_ops[] = {
	{
		.hook		= mtk_ppe_nf_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_LAST,
	},
	{
		.hook		= mtk_ppe_nf_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_FORWARD,
		.priority	= NF_IP_PRI_LAST,
	},
};

int mtk_ppe_hnat_init(struct mtk_eth *eth)
{
	int ret;

	hnat_ctx = kzalloc(sizeof(*hnat_ctx), GFP_KERNEL);
	if (!hnat_ctx)
		return -ENOMEM;

	hnat_ctx->eth = eth;

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	/* Register conntrack event notifier for flow cleanup */
	hnat_ctx->ct_nb.ct_event = mtk_ppe_nf_ct_event;
	nf_conntrack_register_notifier(&init_net, &hnat_ctx->ct_nb);
#endif

	/* Register on init_net only — this driver targets dedicated router
	 * hardware (BPI-R4/MT7988A) where network namespaces are not used.
	 * Multi-namespace support can be added if needed.
	 */
	ret = nf_register_net_hooks(&init_net, mtk_ppe_nf_ops,
				    ARRAY_SIZE(mtk_ppe_nf_ops));
	if (ret) {
#ifdef CONFIG_NF_CONNTRACK_EVENTS
		nf_conntrack_unregister_notifier(&init_net);
#endif
		kfree(hnat_ctx);
		hnat_ctx = NULL;
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mtk_ppe_hnat_init);

void mtk_ppe_hnat_exit(void)
{
	if (hnat_ctx) {
		nf_unregister_net_hooks(&init_net, mtk_ppe_nf_ops,
					ARRAY_SIZE(mtk_ppe_nf_ops));
#ifdef CONFIG_NF_CONNTRACK_EVENTS
		nf_conntrack_unregister_notifier(&init_net);
#endif
		kfree(hnat_ctx);
		hnat_ctx = NULL;
	}
}
EXPORT_SYMBOL_GPL(mtk_ppe_hnat_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Antigravity");
MODULE_DESCRIPTION("MediaTek PPE HNAT Extension");
