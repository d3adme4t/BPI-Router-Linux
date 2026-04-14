/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NF_CONNTRACK_PPE_H
#define _NF_CONNTRACK_PPE_H

#include <net/netfilter/nf_conntrack.h>

struct mtk_flow_entry;

struct nf_conn_ppe {
	struct mtk_flow_entry *entries[IP_CT_DIR_MAX];
};

static inline struct nf_conn_ppe *nf_ct_ppe_find(const struct nf_conn *ct)
{
#if IS_ENABLED(CONFIG_NF_CONNTRACK_EVENTS)
	return nf_ct_ext_find(ct, NF_CT_EXT_PPE);
#else
	return NULL;
#endif
}

#endif /* _NF_CONNTRACK_PPE_H */
