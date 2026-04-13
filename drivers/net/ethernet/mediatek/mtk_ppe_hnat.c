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
	struct nf_conntrack_notifier ct_nb;
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

	if (!hnat_ctx || !ct)
		return 0;

	if (!(events & (1 << IPCT_DESTROY)))
		return 0;

	/* Only care about entries we offloaded */
	if (!test_bit(IPS_OFFLOAD_BIT, &ct->status))
		return 0;

	/*
	 * The entry is on the PPE's foe_flow hlist. The PPE aging
	 * mechanism will eventually invalidate the hardware slot and
	 * call __mtk_foe_entry_clear(), which removes it from the
	 * hlist and frees L2_SUBFLOW entries. For our L4 entries,
	 * clear_bit is sufficient — the PPE garbage collector handles
	 * the rest on next aging pass.
	 */
	clear_bit(IPS_OFFLOAD_BIT, &ct->status);

	return 0;
}
#endif

static unsigned int mtk_ppe_nf_hook(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	struct mtk_eth *eth = hnat_ctx->eth;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct mtk_flow_entry *entry;
	struct mtk_foe_entry *foe;
	struct net_device *in_dev = state->in;
	struct net_device *out_dev = state->out;
	int type, l4proto;
	u8 pse_port = 1; /* default GMAC1 */
	u8 dest_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	struct dst_entry *dst;
	struct neighbour *n;
	bool is_ipv4 = false;

	if (!eth || !in_dev || !out_dev)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || !nf_ct_is_confirmed(ct))
		return NF_ACCEPT;

#ifdef CONFIG_NF_CONNTRACK_EVENTS
	/* Only offload each conntrack once — prevents duplicate entry flooding */
	if (test_and_set_bit(IPS_OFFLOAD_BIT, &ct->status))
		return NF_ACCEPT;
#endif

	if (ctinfo != IP_CT_ESTABLISHED && ctinfo != IP_CT_ESTABLISHED_REPLY)
		goto clear_offload;

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		l4proto = iph->protocol;
		if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
			goto clear_offload;
		type = MTK_PPE_PKT_TYPE_IPV4_HNAPT;
		is_ipv4 = true;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		l4proto = ip6h->nexthdr;
		if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
			goto clear_offload;
		type = MTK_PPE_PKT_TYPE_IPV6_ROUTE_5T;
	} else {
		goto clear_offload;
	}

	/* Resolve next-hop MAC via neighbour subsystem */
	dst = skb_dst(skb);
	if (!dst)
		goto clear_offload;

	if (is_ipv4)
		n = dst_neigh_lookup(dst, &ip_hdr(skb)->daddr);
	else
		n = dst_neigh_lookup(dst, &ipv6_hdr(skb)->daddr);

	if (!n)
		goto clear_offload;

	/* Read neighbour MAC under lock, reject incomplete ARP/NDP entries */
	read_lock_bh(&n->lock);
	if (!(n->nud_state & NUD_VALID)) {
		read_unlock_bh(&n->lock);
		neigh_release(n);
		goto clear_offload;
	}
	memcpy(dest_mac, n->ha, ETH_ALEN);
	read_unlock_bh(&n->lock);
	neigh_release(n);

	memcpy(src_mac, out_dev->dev_addr, ETH_ALEN);

	/* Determine PSE destination port */
	if (eth->netdev[1] &&
	    out_dev->ifindex == eth->netdev[1]->ifindex)
		pse_port = 2; /* GMAC2 */

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		goto clear_offload;

	entry->type = MTK_FLOW_TYPE_L4;
	foe = &entry->data;

	mtk_foe_entry_prepare(eth, foe, type, l4proto, pse_port,
			      src_mac, dest_mac);

	if (is_ipv4) {
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
			mtk_foe_entry_set_ipv4_tuple(eth, foe, false,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);

			mtk_foe_entry_set_ipv4_tuple(eth, foe, true,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all);
		} else {
			mtk_foe_entry_set_ipv4_tuple(eth, foe, false,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all);

			mtk_foe_entry_set_ipv4_tuple(eth, foe, true,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all);
		}
	} else {
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
			mtk_foe_entry_set_ipv6_tuple(eth, foe,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.in6.s6_addr32,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.in6.s6_addr32,
				ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all);
		} else {
			mtk_foe_entry_set_ipv6_tuple(eth, foe,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.in6.s6_addr32,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.in6.s6_addr32,
				ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all);
		}
	}

	/* Resolve DSA/VLAN paths AFTER tuple setup so l2->etype isn't overwritten */
#if IS_ENABLED(CONFIG_NET_DSA)
	{
		struct net_device_path_stack stack;

		rcu_read_lock();
		if (dev_fill_forward_path(out_dev, dest_mac, &stack) == 0) {
			int i;
			for (i = 0; i < stack.num_paths; i++) {
				struct net_device_path *path = &stack.path[i];
				if (path->type == DEV_PATH_DSA)
					mtk_foe_entry_set_dsa(eth, foe, path->dsa.port);
				else if (path->type == DEV_PATH_VLAN)
					mtk_foe_entry_set_vlan(eth, foe, path->encap.id);
			}
		}
		rcu_read_unlock();
	}
#endif

	if (mtk_foe_entry_commit(eth->ppe[0], entry)) {
		kfree(entry);
		goto clear_offload;
	}

	return NF_ACCEPT;

clear_offload:
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	clear_bit(IPS_OFFLOAD_BIT, &ct->status);
#endif
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
	ret = nf_conntrack_register_notifier(&init_net, &hnat_ctx->ct_nb);
	if (ret) {
		kfree(hnat_ctx);
		hnat_ctx = NULL;
		return ret;
	}
#endif

	ret = nf_register_net_hooks(&init_net, mtk_ppe_nf_ops,
				    ARRAY_SIZE(mtk_ppe_nf_ops));
	if (ret) {
#ifdef CONFIG_NF_CONNTRACK_EVENTS
		nf_conntrack_unregister_notifier(&init_net, &hnat_ctx->ct_nb);
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
		nf_conntrack_unregister_notifier(&init_net, &hnat_ctx->ct_nb);
#endif
		kfree(hnat_ctx);
		hnat_ctx = NULL;
	}
}
EXPORT_SYMBOL_GPL(mtk_ppe_hnat_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Antigravity");
MODULE_DESCRIPTION("MediaTek PPE HNAT Extension");
