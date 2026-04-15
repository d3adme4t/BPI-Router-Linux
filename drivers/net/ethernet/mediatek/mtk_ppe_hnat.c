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
static int mtk_ppe_nf_ct_event(unsigned int events,
			       const struct nf_ct_event *item)
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
			mtk_foe_entry_clear(hnat_ctx->eth->ppe[0],
					    ppe->entries[i]);
			kfree(ppe->entries[i]);
			ppe->entries[i] = NULL;
		}
	}

	return 0;
}
#endif
/*
 * Resolve the egress path for a FOE entry and program the three mandatory
 * hardware fields that the PPE requires to forward a packet:
 *
 *   1. DSA tag   — written to etype via mtk_foe_entry_set_dsa()
 *   2. TX queue  — written to ib2.QID via mtk_foe_entry_set_queue()
 *   3. PSE port  — written to ib2.PSE_PORT via mtk_foe_entry_set_pse_port()
 *
 * Mirrors mtk_flow_set_output_device() from mtk_ppe_offload.c.
 *
 * DSA port vs PSE port — they are different things:
 *   DSA port (0-6):  MT7531 switch port index, encoded in etype as BIT(port)
 *   PSE port (0-2):  GMAC egress selector in the FOE entry
 *                    (PSE_GDM1_PORT=1, PSE_GDM2_PORT=2, PSE_GDM3_PORT=15)
 *
 * mtk_foe_entry_set_dsa() overwrites ib2.DEST_PORT_V2 with the DSA port
 * index, so mtk_foe_entry_set_pse_port() MUST be called afterwards to
 * restore the correct GMAC port in that field.
 */
static int mtk_ppe_resolve_path(struct mtk_eth *eth, struct mtk_foe_entry *foe,
				struct net_device *dev, const u8 *dest_mac)
{
	struct net_device *conduit = NULL;
	struct net_device *lower;
	struct list_head *iter;
	struct dsa_port *dp;
	int dsa_port_idx = -1;
	int pse_port, queue;

	/*
	 * Case 1: dev is already a DSA user port (wan, lan1, lan2, ...).
	 * Obtain the conduit (eth0/GMAC1) directly from the dsa_port.
	 */
	if (dsa_user_dev_check(dev)) {
		dp = dsa_port_from_netdev(dev);
		if (!IS_ERR_OR_NULL(dp) &&
		    dp->cpu_dp->tag_ops->proto == DSA_TAG_PROTO_MTK) {
			dsa_port_idx = dp->index;
			conduit = dsa_port_to_conduit(dp);
		}

	/*
	 * Case 2: dev is a bridge (br0). Walk its lower devices to find a
	 * DSA slave that uses the MTK tag protocol. The first active member
	 * is used — the MT7531 switch handles within-LAN L2 forwarding in
	 * hardware, so any member port is a valid HNAT egress target.
	 *
	 * Note: netdev_for_each_lower_dev() is safe without an explicit
	 * rcu_read_lock() here because NF_INET_FORWARD hooks already execute
	 * within an RCU read-side critical section.
	 */
	} else {
		netdev_for_each_lower_dev(dev, lower, iter) {
			if (!dsa_user_dev_check(lower))
				continue;
			dp = dsa_port_from_netdev(lower);
			if (IS_ERR_OR_NULL(dp))
				continue;
			if (dp->cpu_dp->tag_ops->proto != DSA_TAG_PROTO_MTK)
				continue;
			dsa_port_idx = dp->index;
			conduit = dsa_port_to_conduit(dp);
			break;
		}
	}

	if (!conduit || dsa_port_idx < 0)
		return -EOPNOTSUPP;

	/*
	 * Map the conduit's GMAC index to its PSE port number.
	 *
	 * Using netdev_priv(conduit)->id instead of pointer comparison
	 * (conduit == eth->netdev[x]) because dsa_port_to_conduit() may
	 * return a pointer that doesn't match eth->netdev[] entries.
	 *
	 * mac->id (0, 1, 2) != PSE port (1, 2, 15) — a lookup table is
	 * required because GDM3's PSE port (15) is non-contiguous.
	 */
	{
		static const u8 gmac_to_pse[] = {
			[MTK_GMAC1_ID] = PSE_GDM1_PORT,  /* 0 → 1  */
			[MTK_GMAC2_ID] = PSE_GDM2_PORT,  /* 1 → 2  */
			[MTK_GMAC3_ID] = PSE_GDM3_PORT,  /* 2 → 15 */
		};
		struct mtk_mac *mac = netdev_priv(conduit);

		if (mac->id >= ARRAY_SIZE(gmac_to_pse))
			return -EOPNOTSUPP;
		pse_port = gmac_to_pse[mac->id];
	}

	/* Program DSA tag into etype/ib2 — clobbers ib2.DEST_PORT_V2. */
	mtk_foe_entry_set_dsa(eth, foe, dsa_port_idx);

	/* DSA TX queues are offset by 3 from the DSA port index. */
	queue = 3 + dsa_port_idx;
	mtk_foe_entry_set_queue(eth, foe, queue);

	/*
	 * Restore PSE GMAC port in ib2 — must come after set_dsa() since
	 * set_dsa() writes the DSA port index into ib2.DEST_PORT_V2,
	 * overwriting the value set by mtk_foe_entry_prepare(). Without this
	 * call the PPE has no valid egress target and silently drops every
	 * matched packet (packets=0, bytes=0 on all BIND entries).
	 */
	mtk_foe_entry_set_pse_port(eth, foe, pse_port);

	pr_debug("PPE resolve: dev=%s conduit=%s dsa=%d pse=%d queue=%d\n",
		 dev->name, conduit->name, dsa_port_idx, pse_port, queue);
	return 0;
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
	/* PSE port is set by mtk_ppe_resolve_path(); use neutral default here */
	u8 pse_port = PSE_GDM1_PORT;
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

	/* Only offload assured, TCP/UDP flows. Check these before claiming
	 * the atomic bit so a flow that isn't ready yet remains claimable
	 * on a future packet once conditions are met.
	 */
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

	/*
	 * Atomically claim this conntrack for hardware offload. Only the
	 * first CPU to succeed proceeds to create FOE entries; all others
	 * (including retries on the same CPU) return immediately.
	 * err_out clears this bit if entry creation fails, allowing retry.
	 */
	if (test_and_set_bit(IPS_HW_OFFLOAD_BIT, &ct->status))
		return NF_ACCEPT;

	/* Safety check: entries already populated means we somehow raced
	 * past the bit guard. Leave the bit set (flow is offloaded). */
	if (ppe->entries[0] || ppe->entries[1])
		return NF_ACCEPT;

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
			int dir = (i == 0) ? IP_CT_DIR_ORIGINAL :
					     IP_CT_DIR_REPLY;
			int rev = (i == 0) ? IP_CT_DIR_REPLY :
					     IP_CT_DIR_ORIGINAL;

			mtk_foe_entry_set_ipv4_tuple(
				eth, foe, false,
				ct->tuplehash[dir].tuple.src.u3.ip,
				ct->tuplehash[dir].tuple.src.u.all,
				ct->tuplehash[dir].tuple.dst.u3.ip,
				ct->tuplehash[dir].tuple.dst.u.all);

			mtk_foe_entry_set_ipv4_tuple(
				eth, foe, true,
				ct->tuplehash[rev].tuple.dst.u3.ip,
				ct->tuplehash[rev].tuple.dst.u.all,
				ct->tuplehash[rev].tuple.src.u3.ip,
				ct->tuplehash[rev].tuple.src.u.all);
		} else {
			int dir = (i == 0) ? IP_CT_DIR_ORIGINAL :
					     IP_CT_DIR_REPLY;

			mtk_foe_entry_set_ipv6_tuple(
				eth, foe,
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
	/*
	 * Clear IPS_HW_OFFLOAD_BIT so the flow can be retried on a future
	 * packet. If we leave it set after a failed commit, the atomic guard
	 * at the top of this function permanently blocks this conntrack from
	 * ever being offloaded.
	 */
	clear_bit(IPS_HW_OFFLOAD_BIT, &ct->status);
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
		.hook = mtk_ppe_nf_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_ppe_nf_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_LAST,
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
