#ifndef __MTK_PPE_HNAT_H
#define __MTK_PPE_HNAT_H

#include "mtk_eth_soc.h"

#ifdef CONFIG_NET_MEDIATEK_PPE_HNAT
int mtk_ppe_hnat_init(struct mtk_eth *eth);
void mtk_ppe_hnat_exit(void);
#else
static inline int mtk_ppe_hnat_init(struct mtk_eth *eth) { return 0; }
static inline void mtk_ppe_hnat_exit(void) {}
#endif

#endif
