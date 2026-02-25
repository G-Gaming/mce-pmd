#include <assert.h>
#include <stdio.h>

#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_tailq.h>
#include <rte_version.h>
#include "base/mce_eth_regs.h"
#include "base/mce_fdir.h"
#include "base/mce_profile_mask.h"

#include "mce_flow.h"
#include "mce_fdir_flow.h"
#include "mce_pattern.h"
#include "mce_parse.h"
#include "mce_logs.h"
#include "mce_rxtx.h"
#include "mce.h"

#define MCE_ATR_BUCKET_HASH_KEY	   0x3DAD14E2
#define MCE_ATR_SIGNATURE_HASH_KEY 0x174D3614

#define MCE_HASH_VALID_BIT	   GENMASK_U32(11, 0)
#define MCE_SIGN_HASH_VALID_BIT	   GENMASK_U32(15, 0)

/* L2 */
enum rte_flow_item_type fdir_compose_eth[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_END,
};
/* L2 VLAN */
enum rte_flow_item_type fdir_compose_eth_vlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv4 VXLAN */
enum rte_flow_item_type fdir_compose_eth_inner_ipv4_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv4 VXLAN vlan  */
enum rte_flow_item_type fdir_compose_eth_inner_ipv4_vxlan_vlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv4 NVGRE */
enum rte_flow_item_type fdir_compose_eth_inner_ipv4_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_END,
};
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
/* L2-inner IPv4 GRE */
enum rte_flow_item_type fdir_compose_eth_inner_ipv4_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_GRE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv6 GRE */
enum rte_flow_item_type fdir_compose_eth_inner_ipv6_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6, RTE_FLOW_ITEM_TYPE_GRE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE TCP */
enum rte_flow_item_type fdir_compose_ipv4_tcp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE UDP */
enum rte_flow_item_type fdir_compose_ipv4_udp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE SCTP */
enum rte_flow_item_type fdir_compose_ipv4_sctp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_SCTP, RTE_FLOW_ITEM_TYPE_END,
};
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
/* inner IPV4-GRE ESP */
enum rte_flow_item_type fdir_compose_ipv4_esp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GRE UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv4_udp_esp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GRE ESP */
enum rte_flow_item_type fdir_compose_ipv6_esp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GRE inner UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv6_gre_inner_ipv6_udp_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-ESP */
enum rte_flow_item_type fdir_compose_ipv4_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-UDP ESP */
enum rte_flow_item_type fdir_compose_ipv4_udp_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};
#endif
/* inner IPV4-GRE */
enum rte_flow_item_type fdir_compose_ipv4_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};

/* inner IPV6-GRE TCP */
enum rte_flow_item_type fdir_compose_ipv6_tcp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP, RTE_FLOW_ITEM_TYPE_END,
}; /* inner IPV6-GRE UDP */
enum rte_flow_item_type fdir_compose_ipv6_udp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GRE SCTP */
enum rte_flow_item_type fdir_compose_ipv6_sctp_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE,	 RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_SCTP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GRE */
enum rte_flow_item_type fdir_compose_ipv6_inner_gre[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};
#endif
/* L2-inner IPv6 NVGRE */
enum rte_flow_item_type fdir_compose_eth_inner_ipv6_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4 */
enum rte_flow_item_type fdir_compose_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-TCP */
enum rte_flow_item_type fdir_compose_ipv4_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-UDP */
enum rte_flow_item_type fdir_compose_ipv4_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-SCTP */
enum rte_flow_item_type fdir_compose_ipv4_sctp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-VXLAN */
enum rte_flow_item_type fdir_compose_ipv4_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-NVGRE*/
enum rte_flow_item_type fdir_compose_ipv4_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN TCP */
enum rte_flow_item_type fdir_compose_ipv4_tcp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE TCP */
enum rte_flow_item_type fdir_compose_ipv4_tcp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP,	  RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN UDP */
enum rte_flow_item_type fdir_compose_ipv4_udp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE UDP */
enum rte_flow_item_type fdir_compose_ipv4_udp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	  RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN SCTP */
enum rte_flow_item_type fdir_compose_ipv4_sctp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_SCTP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE SCTP */
enum rte_flow_item_type fdir_compose_ipv4_sctp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_SCTP,  RTE_FLOW_ITEM_TYPE_END,
};
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
/* inner IPV4-UDP-ESP SCTP */
enum rte_flow_item_type fdir_compose_ipv4_sctp_inner_udp_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN ESP */
enum rte_flow_item_type fdir_compose_ipv4_esp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};

/* inner IPV4-NVGRE ESP */
enum rte_flow_item_type fdir_compose_ipv4_esp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_ESP,	  RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-VXLAN UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv4_udp_esp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv4_udp_esp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	  RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE ESP */
enum rte_flow_item_type fdir_compose_ipv6_esp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ESP,	  RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-VXLAN inner UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv6_vxlan_inner_ipv6_udp_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};

/* IPV6-NVGRE inner UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv6_nvgre_inner_ipv6_udp_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP,	  RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-ESP */
enum rte_flow_item_type fdir_compose_ipv6_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-UDP ESP */
enum rte_flow_item_type fdir_compose_ipv6_udp_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6, RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN ESP */
enum rte_flow_item_type fdir_compose_ipv6_vxlan_inner_ipv6_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};
#endif /* RTE_VERSION >17.11 HAVE ITEM_TYPE_ESP */
/* inner IPV4-VXLAN */
enum rte_flow_item_type fdir_compose_ipv4_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-NVGRE */
enum rte_flow_item_type fdir_compose_ipv4_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPtunnel ipv4 */
enum rte_flow_item_type fdir_compose_ipv4_iptun_inner_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
/* IPV4-GTPU-IPV4 */
enum rte_flow_item_type fdir_compose_ipv4_gtpu_inner_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GTPU TCP */
enum rte_flow_item_type fdir_compose_ipv4_tcp_inner_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GTPU UDP */
enum rte_flow_item_type fdir_compose_ipv4_udp_inner_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GTPU SCTP */
enum rte_flow_item_type fdir_compose_ipv4_sctp_inner_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU */
enum rte_flow_item_type fdir_compose_ipv4_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GTPU */
enum rte_flow_item_type fdir_compose_ipv6_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU-IPV6 */
enum rte_flow_item_type fdir_compose_ipv4_gtpu_inner_ipv6[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_IPV6, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GTPU UDP */
enum rte_flow_item_type fdir_compose_ipv6_udp_inner_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_IPV6, RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPC */
enum rte_flow_item_type fdir_compose_ipv4_gtpc[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GTPC,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GTPC */
enum rte_flow_item_type fdir_compose_ipv6_gtpc[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GTPC,
	RTE_FLOW_ITEM_TYPE_END,
};
#endif /* RTE_VERSION >= 18.02 */
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
/* IPV4-GTPU GPDU */
enum rte_flow_item_type fdir_compose_ipv4_gtpu_gpdu[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	    RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	    RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_GTP_PSC, RTE_FLOW_ITEM_TYPE_END,
};
#endif
/* IPV6 */
enum rte_flow_item_type fdir_compose_ipv6[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
/* IPV6_FRAG */
enum rte_flow_item_type fdir_compose_ipv6_frag[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
	RTE_FLOW_ITEM_TYPE_END,
};
#endif
/* IPV6-TCP */
enum rte_flow_item_type fdir_compose_ipv6_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-UDP */
enum rte_flow_item_type fdir_compose_ipv6_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-SCTP */
enum rte_flow_item_type fdir_compose_ipv6_sctp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-VXLAN */
enum rte_flow_item_type fdir_compose_ipv6_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_END,
};

/* IPV6-NVGRE*/
enum rte_flow_item_type fdir_compose_ipv6_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_NVGRE,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN TCP */
enum rte_flow_item_type fdir_compose_ipv6_tcp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE TCP */
enum rte_flow_item_type fdir_compose_ipv6_tcp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP,	  RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN UDP */
enum rte_flow_item_type fdir_compose_ipv6_udp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE UDP */
enum rte_flow_item_type fdir_compose_ipv6_udp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP,	  RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-VXLAN SCTP */
enum rte_flow_item_type fdir_compose_ipv6_sctp_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_SCTP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE SCTP */
enum rte_flow_item_type fdir_compose_ipv6_sctp_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_SCTP,  RTE_FLOW_ITEM_TYPE_END,
};
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
/* L2-inner IPv4 GENEVE */
enum rte_flow_item_type fdir_compose_eth_inner_ipv4_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_END,
};
/* L2-inner IPv6 GENEVE */
enum rte_flow_item_type fdir_compose_eth_inner_ipv6_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GENEVE */
enum rte_flow_item_type fdir_compose_ipv4_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE TCP */
enum rte_flow_item_type fdir_compose_ipv4_tcp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE UDP */
enum rte_flow_item_type fdir_compose_ipv4_udp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE SCTP */
enum rte_flow_item_type fdir_compose_ipv4_sctp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_SCTP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE ESP */
enum rte_flow_item_type fdir_compose_ipv4_esp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv4_udp_esp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV4-GENEVE */
enum rte_flow_item_type fdir_compose_ipv4_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GENEVE */
enum rte_flow_item_type fdir_compose_ipv6_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE */
enum rte_flow_item_type fdir_compose_ipv6_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};

/* inner IPV6-GENEVE TCP */
enum rte_flow_item_type fdir_compose_ipv6_tcp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE UDP */
enum rte_flow_item_type fdir_compose_ipv6_udp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE SCTP */
enum rte_flow_item_type fdir_compose_ipv6_sctp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_SCTP, RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE ESP */
enum rte_flow_item_type fdir_compose_ipv6_esp_inner_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_ESP, RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-GENEVE inner UDP-ESP */
enum rte_flow_item_type fdir_compose_ipv6_geneve_inner_ipv6_udp_esp[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_ESP,
	RTE_FLOW_ITEM_TYPE_END,
};
#endif
/* inner IPV6-VXLAN */
enum rte_flow_item_type fdir_compose_ipv6_inner_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
/* ip VXLAN in ipv6 frag*/
enum rte_flow_item_type fdir_compose_ipv4_vxlan_inner_ipv6_frag[] = {
	RTE_FLOW_ITEM_TYPE_ETH,		  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,		  RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,		  RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GRE-IPV6-FRAG */
enum rte_flow_item_type fdir_ipv4_gre_inner_ipv6_frag[] = {
	RTE_FLOW_ITEM_TYPE_ETH,		  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_GRE,		  RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-NVGRE-IPV6-FRAG */
enum rte_flow_item_type fdir_ipv4_nvgre_inner_ipv6_frag[] = {
	RTE_FLOW_ITEM_TYPE_ETH,		  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE,	  RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-GTPU-IPV6-EXT_FRAG */
enum rte_flow_item_type fdir_compose_ipv4_gtpu_inner_ipv6_frag[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,	 RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_IPV6, RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-GENEVE */
enum rte_flow_item_type fdir_compose_ipv4_geneve_inner_ipv6_frag[] = {
	RTE_FLOW_ITEM_TYPE_ETH,		  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,		  RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_ETH,		  RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT, RTE_FLOW_ITEM_TYPE_END,
};
#endif /* RTE_VERSION >= 20.11 */
/* inner IPV6-NVGRE */
enum rte_flow_item_type fdir_compose_ipv6_inner_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};
/* inner IPV6-NVGRE */
enum rte_flow_item_type fdir_compose_ipv4_nvgre_inner_ipv6[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE, RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};
#define MCE_MAX_FDIR_ENTRY (4096)

/**
 * @brief Convert parsed metadata to an FDIR L2-mode filter.
 *
 * Allocates and populates a `mce_fdir_filter` suitable for L2/ethertype
 * matching using the provided metadata entries.
 *
 * @param h_ptr Engine handle (cast to `struct mce_fdir_handle *`).
 * @param meta_num Number of metadata entries present.
 * @param mask_info Optional pointer to field bitmask info (may be NULL).
 * @param actions Pointer to action configuration to attach to the filter.
 * @param options Option bitmask describing which fields are enabled.
 * @param is_ipv6 True when parsing IPv6 metadata (unused for L2).
 * @param is_tunnel True when parsing tunnel metadata (unused for L2).
 * @return Pointer to allocated `mce_fdir_filter` on success, NULL on failure.
 */
static void *
mce_meta_to_fdir_rule_l2_mode(void *h_ptr, uint16_t meta_num,
			      struct mce_field_bitmask_info *mask_info,
			      struct mce_flow_action *actions, uint64_t options,
			      bool is_ipv6, bool is_tunnel)
{
	struct mce_fdir_handle *handle = (struct mce_fdir_handle *)h_ptr;
	struct mce_fdir_filter *filter = NULL;
	union mce_fdir_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	int i = 0, j = 0;

	filter = rte_zmalloc(NULL, sizeof(struct mce_fdir_filter), 0);
	if (filter == NULL)
		return NULL;
	lkup_pattern = &filter->lkup_pattern;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		switch (meta->type) {
		case MCE_ETH_META:
			for (j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
				lkup_pattern->formatted.src_mac[j] =
					meta->hdr.eth_meta.src_addr[j] &
					meta->mask.eth_meta.src_addr[j];
				lkup_pattern->formatted.dst_mac[j] =
					meta->hdr.eth_meta.dst_addr[j] &
					meta->mask.eth_meta.dst_addr[j];
			}
			break;
		case MCE_VLAN_META:
			lkup_pattern->formatted.vlan_id =
				meta->hdr.vlan_meta.vlan_id &
				meta->mask.vlan_meta.vlan_id;
			break;
		default:
			PMD_DRV_LOG(ERR, "the rule is not exist options");
		}
	}
	if (mask_info)
		filter->mask_info = mask_info;
	filter->meta_num = meta_num;
	filter->options = options;
	filter->actions = *actions;
	filter->is_ipv6 = is_ipv6;

	return filter;
}

/**
 * @brief Convert parsed metadata to an FDIR filter for L3/L4/tunnel matches.
 *
 * Allocates and fills a `mce_fdir_filter` from the provided metadata entries
 * covering IPv4/IPv6/L4 and various tunnel encapsulations.
 *
 * @param h_ptr Engine handle (cast to `struct mce_fdir_handle *`).
 * @param meta_num Number of metadata entries present.
 * @param mask_info Optional pointer to field bitmask info (may be NULL).
 * @param actions Pointer to action configuration to attach to the filter.
 * @param options Option bitmask describing which fields are enabled.
 * @param is_ipv6 True when parsing IPv6 metadata.
 * @param is_tunnel True when parsing tunnel-encapsulated metadata.
 * @return Pointer to allocated `mce_fdir_filter` on success, NULL on failure.
 */
static void *mce_meta_to_fdir_rule(void *h_ptr, uint16_t meta_num,
				   struct mce_field_bitmask_info *mask_info,
				   struct mce_flow_action *actions,
				   uint64_t options, bool is_ipv6,
				   bool is_tunnel)
{
	struct mce_fdir_handle *handle = (struct mce_fdir_handle *)h_ptr;
	struct mce_fdir_filter *filter = NULL;
	union mce_fdir_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	int i = 0;

	filter = rte_zmalloc(NULL, sizeof(struct mce_fdir_filter), 0);
	if (filter == NULL)
		return NULL;
	lkup_pattern = &filter->lkup_pattern;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		switch (meta->type) {
		case MCE_ETH_META:
			lkup_pattern->formatted.ether_type =
				meta->hdr.eth_meta.ethtype_id &
				meta->mask.eth_meta.ethtype_id;
			break;
		case MCE_IPV4_META:
			lkup_pattern->formatted.src_addr[0] =
				meta->hdr.ipv4_meta.src_addr &
				meta->mask.ipv4_meta.src_addr;
			lkup_pattern->formatted.dst_addr[0] =
				meta->hdr.ipv4_meta.dst_addr &
				meta->mask.ipv4_meta.dst_addr;
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv4_meta.protocol &
				meta->mask.ipv4_meta.protocol;
			lkup_pattern->formatted.ip_tos =
				meta->hdr.ipv4_meta.dscp &
				meta->mask.ipv4_meta.dscp;
			break;
		case MCE_IPV6_META:
			lkup_pattern->formatted.src_addr[0] =
				meta->hdr.ipv6_meta.src_addr[0] &
				meta->mask.ipv6_meta.src_addr[0];
			lkup_pattern->formatted.src_addr[1] =
				meta->hdr.ipv6_meta.src_addr[1] &
				meta->mask.ipv6_meta.src_addr[1];
			lkup_pattern->formatted.src_addr[2] =
				meta->hdr.ipv6_meta.src_addr[2] &
				meta->mask.ipv6_meta.src_addr[2];
			lkup_pattern->formatted.src_addr[3] =
				meta->hdr.ipv6_meta.src_addr[3] &
				meta->mask.ipv6_meta.src_addr[3];
			lkup_pattern->formatted.dst_addr[0] =
				meta->hdr.ipv6_meta.dst_addr[0] &
				meta->mask.ipv6_meta.dst_addr[0];
			lkup_pattern->formatted.dst_addr[1] =
				meta->hdr.ipv6_meta.dst_addr[1] &
				meta->mask.ipv6_meta.dst_addr[1];
			lkup_pattern->formatted.dst_addr[2] =
				meta->hdr.ipv6_meta.dst_addr[2] &
				meta->mask.ipv6_meta.dst_addr[2];
			lkup_pattern->formatted.dst_addr[3] =
				meta->hdr.ipv6_meta.dst_addr[3] &
				meta->mask.ipv6_meta.dst_addr[3];
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv6_meta.protocol &
				meta->mask.ipv6_meta.protocol;
			lkup_pattern->formatted.ip_tos =
				meta->hdr.ipv6_meta.dscp &
				meta->mask.ipv6_meta.dscp;
			break;
		case MCE_UDP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.udp_meta.dst_port &
				meta->mask.udp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.udp_meta.src_port &
				meta->mask.udp_meta.src_port;
			break;
		case MCE_TCP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.tcp_meta.dst_port &
				meta->mask.tcp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.tcp_meta.src_port &
				meta->mask.tcp_meta.src_port;
			break;
		case MCE_SCTP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.sctp_meta.dst_port &
				meta->mask.sctp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.sctp_meta.src_port &
				meta->mask.sctp_meta.src_port;
			break;
		case MCE_ESP_META:
			lkup_pattern->formatted.esp_spi =
				meta->hdr.esp_meta.spi &
				meta->mask.esp_meta.spi;
			break;
		case MCE_VXLAN_META:
			lkup_pattern->formatted.vni = meta->hdr.vxlan_meta.vni &
						      meta->mask.vxlan_meta.vni;
			break;
		case MCE_GENEVE_META:
			lkup_pattern->formatted.vni =
				meta->hdr.geneve_meta.vni &
				meta->mask.geneve_meta.vni;
			break;
		case MCE_NVGRE_META:
			lkup_pattern->formatted.key = meta->hdr.nvgre_meta.key &
						      meta->mask.nvgre_meta.key;
			break;
		case MCE_GTPU_META:
		case MCE_GTPC_META:
			lkup_pattern->formatted.teid = meta->hdr.gtp_meta.teid &
						       meta->mask.gtp_meta.teid;
			break;
		default:
			PMD_DRV_LOG(ERR, "the rule is not exist options");
		}
	}
	if (mask_info)
		filter->mask_info = mask_info;
	filter->meta_num = meta_num;
	filter->options = options;
	filter->actions = *actions;
	filter->is_ipv6 = is_ipv6;

	return filter;
}

#define MCE_FDIR_OPT_IPV4                                         \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_L4_PROTO | \
	 MCE_OPT_IPV4_DSCP)
#define MCE_FDIR_OPT_IPV4_FRAG                                     \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_IPV4_FRAG | \
	 MCE_OPT_IPV4_DSCP)
#define MCE_FDIR_OPT_IPV4_TCP_SYNC \
	(MCE_OPT_IPV4_DIP | MCE_OPT_TCP_DPORT | MCE_OPT_TCP_SYNC)
#define MCE_FDIR_OPT_IPV4_TCP                                      \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_TCP_SPORT | \
	 MCE_OPT_TCP_DPORT)
#define MCE_FDIR_OPT_IPV4_UDP                                      \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_UDP_SPORT | \
	 MCE_OPT_UDP_DPORT)
#define MCE_FDIR_OPT_IPV4_SCTP                                      \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_SCTP_SPORT | \
	 MCE_OPT_SCTP_DPORT)
#define MCE_FDIR_OPT_IPV4_ESP \
	(MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_ESP_SPI)
#define MCE_FDIR_OPT_IPV4_VXLAN \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_VXLAN_VNI)
#define MCE_FDIR_OPT_IPV4_GENEVE \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_GENEVE_VNI)
#define MCE_FDIR_OPT_IPV4_NVGRE \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_NVGRE_TNI)
#define MCE_FDIR_OPT_IPV4_GTP_U_GPDU \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_GTP_U_TEID)
#define MCE_FDIR_OPT_IPV4_GTP_C_TEID \
	(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_OUT_IPV4_SIP | MCE_OPT_GTP_C_TEID)
#define MCE_FDIR_OPT_IPV4_GTP_C_NOTEID (MCE_OPT_OUT_IPV4_DIP | MCE_OPT_IPV4_SIP)
#define MCE_FDIR_OPT_IPV6                                         \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_L4_PROTO | \
	 MCE_OPT_IPV6_DSCP)
#define MCE_FDIR_OPT_IPV6_FRAG                                     \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_FRAG | \
	 MCE_OPT_IPV6_DSCP)
#define MCE_FDIR_OPT_IPV6_TCP_SYNC \
	(MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | MCE_OPT_TCP_DPORT)
#define MCE_FDIR_OPT_IPV6_TCP                                      \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_TCP_SPORT | MCE_OPT_TCP_DPORT)
#define MCE_FDIR_OPT_IPV6_UDP                                      \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_UDP_SPORT | MCE_OPT_UDP_DPORT)
#define MCE_FDIR_OPT_IPV6_SCTP                                     \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_SCTP_SPORT | MCE_OPT_SCTP_DPORT)
#define MCE_FDIR_OPT_IPV6_ESP                                      \
	(MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP | MCE_OPT_IPV6_DSCP | \
	 MCE_OPT_ESP_SPI)
#define MCE_FDIR_OPT_IPV6_VXLAN \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_VXLAN_VNI)
#define MCE_FDIR_OPT_IPV6_GENEVE \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_GENEVE_VNI)
#define MCE_FDIR_OPT_IPV6_NVGRE \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_NVGRE_TNI)
#define MCE_FDIR_OPT_IPV6_GTP_U_GPDU \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_GTP_U_TEID)
#define MCE_FDIR_OPT_IPV6_GTP_C_TEID \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | MCE_OPT_GTP_C_TEID)
#define MCE_FDIR_OPT_IPV6_GTP_C_NOTEID \
	(MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP)
#define MCE_FDIR_L2_MAC	    (MCE_OPT_SMAC | MCE_OPT_DMAC)
#define MCE_FDIR_L2_MACVLAN (MCE_FDIR_L2_MAC | MCE_OPT_VLAN_VID)
static struct mce_flow_ptype_match mce_fdir_l2_mode_support[] = {
	{ fdir_compose_eth, MCE_PTYPE_L2_ONLY, MCE_FDIR_L2_MAC,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
	{ fdir_compose_eth_vlan, MCE_PTYPE_L2_ONLY, MCE_FDIR_L2_MACVLAN,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
};
static struct mce_flow_ptype_match mce_fdir_inner_l2_mode_support[] = {
	{ fdir_compose_eth, MCE_PTYPE_L2_ONLY, MCE_FDIR_L2_MAC,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
	{ fdir_compose_eth_vlan, MCE_PTYPE_L2_ONLY, MCE_FDIR_L2_MACVLAN,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
	/* tunnel ipv4 inner eth */
	{ fdir_compose_eth_inner_ipv4_vxlan, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
	{ fdir_compose_eth_inner_ipv4_vxlan_vlan, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MACVLAN, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode},
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_eth_inner_ipv4_geneve, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
	{ fdir_compose_eth_inner_ipv4_gre, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
#endif /* HAVE_ITEM_TYPE_GRE */
	{ fdir_compose_eth_inner_ipv4_nvgre, MCE_PTYPE_TUN_INNER_L2_ONLY,
	  MCE_FDIR_L2_MAC, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule_l2_mode },
};
static struct mce_flow_ptype_match mce_fdir_ptype_tun_inner_sup[] = {
	/* normal non-tunnel ipv6 ipv4 */
	{ fdir_compose_eth, MCE_PTYPE_L2_ETHTYPE, MCE_OPT_ETHTYPE,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* nromal ipv4 */
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_PAY, MCE_FDIR_OPT_IPV4,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_FRAG, MCE_FDIR_OPT_IPV4_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_tcp, MCE_PTYPE_IPV4_TCP, MCE_FDIR_OPT_IPV4_TCP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_udp, MCE_PTYPE_IPV4_UDP, MCE_FDIR_OPT_IPV4_UDP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_sctp, MCE_PTYPE_IPV4_SCTP, MCE_FDIR_OPT_IPV4_SCTP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* normal ipv6 */
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_PAY, MCE_FDIR_OPT_IPV6,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_frag, MCE_PTYPE_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv6_tcp, MCE_PTYPE_IPV6_TCP, MCE_FDIR_OPT_IPV6_TCP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_udp, MCE_PTYPE_IPV6_UDP, MCE_FDIR_OPT_IPV6_UDP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_sctp, MCE_PTYPE_IPV6_SCTP, MCE_FDIR_OPT_IPV6_SCTP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel ipv4 inner eth */
	{ fdir_compose_eth_inner_ipv4_vxlan, MCE_PTYPE_TUN_INNER_L2_ETHTYPE,
	  MCE_OPT_ETHTYPE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_eth_inner_ipv4_geneve, MCE_PTYPE_TUN_INNER_L2_ETHTYPE,
	  MCE_OPT_ETHTYPE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_eth_inner_ipv4_nvgre, MCE_PTYPE_TUN_INNER_L2_ETHTYPE,
	  MCE_OPT_ETHTYPE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv6 pay or frag */
	{ fdir_compose_ipv6_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_vxlan_inner_ipv6_frag,
	  MCE_PTYPE_TUN_INNER_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_geneve_inner_ipv6_frag,
	  MCE_PTYPE_TUN_INNER_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	{ fdir_ipv4_gre_inner_ipv6_frag, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_ipv4_nvgre_inner_ipv6_frag, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	/* tunnel inner is ipv6 tcp */
	{ fdir_compose_ipv6_tcp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_tcp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif

	{ fdir_compose_ipv6_tcp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv6 udp */
	{ fdir_compose_ipv6_udp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_udp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv6_udp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv6 sctp */
	{ fdir_compose_ipv6_sctp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV6_SCTP,
	  MCE_FDIR_OPT_IPV6_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_sctp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_SCTP,
	  MCE_FDIR_OPT_IPV6_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
	{ fdir_compose_eth_inner_ipv4_gre, MCE_PTYPE_TUN_INNER_L2_ETHTYPE,
	  MCE_OPT_ETHTYPE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_tcp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_TCP,
	  MCE_FDIR_OPT_IPV6_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_udp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_UDP,
	  MCE_FDIR_OPT_IPV6_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_sctp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_SCTP,
	  MCE_FDIR_OPT_IPV6_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif /* HAVE_ITEM_TYPE_GRE */
	{ fdir_compose_ipv6_sctp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_SCTP,
	  MCE_FDIR_OPT_IPV6_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_esp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_esp_inner_gre, MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_esp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv6 udp esp */
	{ fdir_compose_ipv6_vxlan_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv6 esp */
	{ fdir_compose_ipv6_vxlan_inner_ipv6_esp, MCE_PTYPE_TUN_INNER_IPV6_ESP,
	  MCE_FDIR_OPT_IPV6_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_gre_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_nvgre_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel out ipv6 */
	{ fdir_compose_ipv6_esp, MCE_PTYPE_IPV6_ESP, MCE_FDIR_OPT_IPV6_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_udp_esp, MCE_PTYPE_IPV6_UDP_ESP,
	  MCE_FDIR_OPT_IPV6_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_udp_esp_inner_nvgre,
	  MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP, MCE_FDIR_OPT_IPV4_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv4 udp esp */
	{ fdir_compose_ipv4_esp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_esp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv4 esp */
	{ fdir_compose_ipv4_udp_esp_inner_vxlan,
	  MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP, MCE_FDIR_OPT_IPV4_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel out ipv4 */
	{ fdir_compose_ipv4_esp, MCE_PTYPE_IPV4_ESP, MCE_FDIR_OPT_IPV4_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_udp_esp, MCE_PTYPE_IPV4_UDP_ESP,
	  MCE_FDIR_OPT_IPV4_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif /* RTE_VERSION >= 17.11 HAVE_ITEM_TYPE_ESP */
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_geneve_inner_ipv6_udp_esp,
	  MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP, MCE_FDIR_OPT_IPV6_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif /* HAVE_GENEVE_ITEM */
	/* tunnel inner is ipv4 pay or frag */
	{ fdir_compose_ipv4_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv4_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_iptun_inner_ipv4, MCE_PTYPE_TUN_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_iptun_inner_ipv4, MCE_PTYPE_TUN_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner ipv4 tcp */
	{ fdir_compose_ipv4_tcp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_tcp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv4_tcp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv4 udp */
	{ fdir_compose_ipv4_udp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_udp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv4_udp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel inner is ipv4 sctp */
	{ fdir_compose_ipv4_sctp_inner_vxlan, MCE_PTYPE_TUN_INNER_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_sctp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv4_sctp_inner_nvgre, MCE_PTYPE_TUN_INNER_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_esp_inner_geneve, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_tcp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_udp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_sctp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
	{ fdir_compose_ipv4_esp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_ESP,
	  MCE_FDIR_OPT_IPV4_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_udp_esp_inner_gre, MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP,
	  MCE_FDIR_OPT_IPV4_ESP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
#endif /* HAVE_GTR_ITEM RTE_VERSION >= 17.05 */
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_udp_esp_inner_geneve,
	  MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP, MCE_FDIR_OPT_IPV4_ESP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif

#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	/* tunnel gtp inner ipv4/ipv6 */
	{ fdir_compose_ipv4_gtpu_inner_ipv4, MCE_PTYPE_GTP_U_INNER_IPV4_PAY,
	  MCE_FDIR_OPT_IPV4, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_gtpu_inner_ipv4, MCE_PTYPE_GTP_U_INNER_IPV4_FRAG,
	  MCE_FDIR_OPT_IPV4_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_gtpu_inner_ipv6, MCE_PTYPE_GTP_U_INNER_IPV6_PAY,
	  MCE_FDIR_OPT_IPV6, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_tcp_inner_gtpu, MCE_PTYPE_GTP_U_INNER_IPV4_TCP,
	  MCE_FDIR_OPT_IPV4_TCP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_udp_inner_gtpu, MCE_PTYPE_GTP_U_INNER_IPV4_UDP,
	  MCE_FDIR_OPT_IPV4_UDP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_sctp_inner_gtpu, MCE_PTYPE_GTP_U_INNER_IPV4_SCTP,
	  MCE_FDIR_OPT_IPV4_SCTP, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif /* RTE_VERSION >= 18.02 */
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_gtpu_inner_ipv6, MCE_PTYPE_GTP_U_INNER_IPV6_FRAG,
	  MCE_FDIR_OPT_IPV6_FRAG, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_gtpu_inner_ipv6_frag,
	  MCE_PTYPE_GTP_U_INNER_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif /* RTE_VERSION >= 20.11 */
};
static struct mce_flow_ptype_match mce_fdir_ptype_support[] = {
	{ fdir_compose_eth, MCE_PTYPE_L2_ETHTYPE, MCE_OPT_ETHTYPE,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* nromal ipv4 */
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_PAY, MCE_FDIR_OPT_IPV4,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4, MCE_PTYPE_IPV4_FRAG, MCE_FDIR_OPT_IPV4_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_tcp, MCE_PTYPE_IPV4_TCP, MCE_FDIR_OPT_IPV4_TCP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_udp, MCE_PTYPE_IPV4_UDP, MCE_FDIR_OPT_IPV4_UDP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_sctp, MCE_PTYPE_IPV4_SCTP, MCE_FDIR_OPT_IPV4_SCTP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* normal ipv6 */
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_PAY, MCE_FDIR_OPT_IPV6,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6, MCE_PTYPE_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_frag, MCE_PTYPE_IPV6_FRAG, MCE_FDIR_OPT_IPV6_FRAG,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv6_tcp, MCE_PTYPE_IPV6_TCP, MCE_FDIR_OPT_IPV6_TCP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_udp, MCE_PTYPE_IPV6_UDP, MCE_FDIR_OPT_IPV6_UDP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_sctp, MCE_PTYPE_IPV6_SCTP, MCE_FDIR_OPT_IPV6_SCTP,
	  MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_vxlan, MCE_PTYPE_TUN_IPV4_VXLAN,
	  MCE_FDIR_OPT_IPV4_VXLAN, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv4_geneve, MCE_PTYPE_TUN_IPV4_GENEVE,
	  MCE_FDIR_OPT_IPV4_GENEVE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#endif
	{ fdir_compose_ipv4_nvgre, MCE_PTYPE_TUN_IPV4_GRE,
	  MCE_FDIR_OPT_IPV4_NVGRE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_vxlan, MCE_PTYPE_TUN_IPV6_VXLAN,
	  MCE_FDIR_OPT_IPV6_VXLAN, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	{ fdir_compose_ipv6_geneve, MCE_PTYPE_TUN_IPV6_GENEVE,
	  MCE_FDIR_OPT_IPV6_GENEVE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_nvgre, MCE_PTYPE_TUN_IPV6_GRE,
	  MCE_FDIR_OPT_IPV6_NVGRE, MCE_FDIR_PERFECT, mce_meta_to_fdir_rule },
	/* tunnel out gtp */
	{ fdir_compose_ipv4_gtpc, MCE_PTYPE_GTP_C_TEID_IPV4,
	  MCE_FDIR_OPT_IPV4_GTP_C_TEID, MCE_FDIR_PERFECT,
	  mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_gtpc, MCE_PTYPE_GTP_C_TEID_IPV6,
	  MCE_FDIR_OPT_IPV6_GTP_C_TEID, MCE_FDIR_PERFECT,
	  mce_meta_to_fdir_rule },
	{ fdir_compose_ipv4_gtpu, MCE_PTYPE_GTP_U_GPDU_IPV4,
	  MCE_FDIR_OPT_IPV4_GTP_U_GPDU, MCE_FDIR_PERFECT,
	  mce_meta_to_fdir_rule },
	{ fdir_compose_ipv6_gtpu, MCE_PTYPE_GTP_U_GPDU_IPV6,
	  MCE_FDIR_OPT_IPV6_GTP_U_GPDU, MCE_FDIR_PERFECT,
	  mce_meta_to_fdir_rule },
#endif
};

#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
#define MCE_FLOW_ITEM_TUNNEL_MASK               \
	(RTE_BIT64(RTE_FLOW_ITEM_TYPE_VXLAN) |  \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_NVGRE) |  \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_GRE) |    \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_GENEVE) | \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_GTPC) |   \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_GTPU))
#elif RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#define MCE_FLOW_ITEM_TUNNEL_MASK              \
	(RTE_BIT64(RTE_FLOW_ITEM_TYPE_VXLAN) | \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_NVGRE))
#else /* RTE_VERSION >= 17.5 && RTE_VERSION < 18.2 */
#define MCE_FLOW_ITEM_TUNNEL_MASK              \
	(RTE_BIT64(RTE_FLOW_ITEM_TYPE_VXLAN) | \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_NVGRE) | \
	 RTE_BIT64(RTE_FLOW_ITEM_TYPE_GRE))
#endif /* RTE_VERSION > 18.02 */

/**
 * @brief Parse a flow pattern and actions into FDIR filter rules.
 *
 * Validates the flow pattern against supported tuple types, parses lookup
 * metadata and action configuration, and creates a FDIR rule structure.
 *
 * @param vport
 *   VPort being configured.
 * @param o_parm
 *   Out-parameter pointing to a `struct mce_fdir_rule *` to be populated.
 * @param attr
 *   Flow rule attributes (unused).
 * @param pattern
 *   Flow pattern items to parse.
 * @param actions
 *   Flow actions to apply.
 * @param error
 *   Error reporting structure.
 * @return
 *   0 on success, negative errno on failure.
 */
static int mce_fdir_flow_parse(struct mce_vport *vport, void **o_parm,
			       const struct rte_flow_attr *attr __rte_unused,
			       const struct rte_flow_item pattern[],
			       const struct rte_flow_action actions[],
			       struct rte_flow_error *error)
{
	struct mce_fdir_rule **rule = (struct mce_fdir_rule **)o_parm;
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_field_bitmask_info *mask_info = NULL;
	struct mce_flow_ptype_match *support = NULL;
	const struct rte_flow_action *act = actions;
	const struct rte_flow_item *item = pattern;
	struct mce_fdir_handle *handle = NULL;
	struct mce_flow_action action_conf;
	struct mce_lkup_meta *meta = NULL;
	struct mce_fdir_rule *tmp;
	uint16_t field_bitmask_num = 0;
	uint64_t item_compose = 0;
	uint8_t act_mark_cnt = 0;
	uint16_t block_size = 0;
	bool is_tunnel = false;
	uint16_t meta_num = 0;
	uint8_t act_q_cnt = 0;
	uint16_t tun_type = 0;
	uint64_t inset = 0;
	bool is_ipv6 = false;
	uint32_t reg = 0;
	uint16_t hi_bit = 0;
	int ret = 0;

	/* 1.define filter enging can support pattern compose */
	/* 2.check the pattern input options flow engine can deal */
	if (pattern == NULL)
		return -EINVAL;
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++)
		item_compose |= RTE_BIT64(item->type);
	item_compose |= RTE_BIT64(RTE_FLOW_ITEM_TYPE_END);
	handle = (struct mce_fdir_handle *)mce_get_engine_handle(vport,
								 MCE_FLOW_FDIR);
	if (handle == NULL)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, handle,
					  "fdir_handle get failed");
	item = pattern;
	reg = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
	if (reg & MCE_FDIR_MATCH_L2_EN) { /* L2 mode*/
		if (vport->attr.inner_rss_en) {
			support = mce_check_pattern_support(
				item, mce_fdir_inner_l2_mode_support,
				RTE_DIM(mce_fdir_inner_l2_mode_support));
		} else {
			support = mce_check_pattern_support(
				item, mce_fdir_l2_mode_support,
				RTE_DIM(mce_fdir_l2_mode_support));
		}
	} else {
		if (vport->attr.inner_rss_en) {
			support = mce_check_pattern_support(
				item, mce_fdir_ptype_tun_inner_sup,
				RTE_DIM(mce_fdir_ptype_tun_inner_sup));
		} else {
			support = mce_check_pattern_support(
				item, mce_fdir_ptype_support,
				RTE_DIM(mce_fdir_ptype_support));
		}
	}
	if (support == NULL)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "fdir pattern compose not support");
	if (item_compose & MCE_FLOW_ITEM_TUNNEL_MASK &&
	    !vport->attr.inner_rss_en)
		is_tunnel = 1;
	hi_bit = rte_fls_u64(item_compose & MCE_FLOW_ITEM_TUNNEL_MASK);
	if (hi_bit) {
		switch (hi_bit - 1) {
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			tun_type = MCE_RX_TUN_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			tun_type = MCE_RX_TUN_VXLAN;
			break;
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			tun_type = MCE_RX_TUN_GENEVE;
			break;
		case RTE_FLOW_ITEM_TYPE_GTPU:
			tun_type = MCE_RX_TUN_GTP_U;
			break;
		case RTE_FLOW_ITEM_TYPE_GTPC:
			tun_type = MCE_RX_TUN_GTP_C;
			break;
#endif
		default:
			tun_type = 0;
		}
	}
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		meta = &handle->meta_db[is_tunnel][meta_num];
		memset(meta, 0, sizeof(*meta));
		meta->type = MCE_META_TYPE_MAX;
		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = mce_parse_eth(item, meta, &inset, is_tunnel,
					    error);
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			ret = mce_parse_vlan(item, meta, &inset, is_tunnel,
					     error);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ret = mce_parse_ip4(item, meta, &inset, is_tunnel,
					    error);
			if (ret && inset & MCE_OPT_IPV4_FRAG)
				support = support + 1;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ret = mce_parse_ip6(item, meta, &inset, is_tunnel,
					    error);
			if (ret && inset & MCE_OPT_IPV6_FRAG)
				support = support + 1;
			is_ipv6 = true;
			break;
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT:
			ret = mce_parse_ip6_frag(item, meta, &inset, is_tunnel,
						 error);
			break;
#endif
		case RTE_FLOW_ITEM_TYPE_TCP:
			ret = mce_parse_tcp(item, meta, &inset, is_tunnel,
					    error);
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ret = mce_parse_udp(item, meta, &inset, is_tunnel,
					    error);
			break;
		case RTE_FLOW_ITEM_TYPE_SCTP:
			ret = mce_parse_sctp(item, meta, &inset, is_tunnel,
					     error);
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			ret = mce_parse_vxlan(item, meta, &inset, is_tunnel,
					      error);
			break;
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			ret = mce_parse_geneve(item, meta, &inset, is_tunnel,
					       error);
			break;
		case RTE_FLOW_ITEM_TYPE_GTP:
		case RTE_FLOW_ITEM_TYPE_GTPC:
			ret = mce_parse_gtpc(item, meta, &inset, is_tunnel,
					     error);
			break;
		case RTE_FLOW_ITEM_TYPE_GTPU:
			ret = mce_parse_gtpu(item, meta, &inset, is_tunnel,
					     error);
			break;
#endif
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			ret = mce_parse_nvgre(item, meta, &inset, is_tunnel,
					      error);
			break;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ITEM_TYPE_ESP:
			ret = mce_parse_esp(item, meta, &inset, is_tunnel,
					    error);
			break;
#endif
		default:
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  item,
						  "item type not support");
		}
		if (ret < 0)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"item options can't be parse");
		if (inset & MCE_OPT_OUT_IP_PORT && inset & MCE_OPT_IN_IP_PORT) {
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"for tunnel match not support both in and out"
				"both match");
		}
		if (inset & MCE_OPT_IN_IP_PORT && inset & MCE_TUNNEL_OPT) {
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"for tunnel match tunnel key just support with"
				"out pattern match");
		}
		if (inset & MCE_OPT_TCP_SYNC &&
		    ((inset & MCE_OPT_SRC_IP_PORT) ||
		     (inset & MCE_TUNNEL_OPT))) {
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"tcp sync only support dport dip match");
		}
		if (inset && (support->insets ^ (support->insets | inset))) {
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"this profile not support this pattern match");
		}
		meta_num += (ret > 0 ? 1 : 0);
		if (ret)
			field_bitmask_num +=
				mce_check_field_bitmask_valid(meta);
	}
	if (field_bitmask_num) {
		printf("prifile field bitmap en\n");
		printf("field_bitmask_num %d\n", field_bitmask_num);
		mask_info = rte_zmalloc(
			NULL, sizeof(struct mce_field_bitmask_info), 0);
		block_size = sizeof(struct mce_field_bitmask_block) *
			     field_bitmask_num;
		mask_info->field_bitmask = rte_zmalloc(NULL, block_size, 0);
		meta = &handle->meta_db[0][0];
		mce_fdir_field_mask_init(meta, meta_num, mask_info);
	}
	memset(&action_conf, 0, sizeof(action_conf));
	for (; act->type != RTE_FLOW_ACTION_TYPE_END; act++) {
		switch (act->type) {
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			memcpy(&action_conf.redir, act->conf,
			       sizeof(struct rte_flow_action_queue));
			if (action_conf.redir.index >=
			    vport->dev->data->nb_rx_queues)
				return rte_flow_error_set(
					error, ENOTSUP,
					RTE_FLOW_ERROR_TYPE_ACTION, act,
					"Fdir Flow Act queue is out of "
					"range");
			action_conf.rule_action = MCE_FILTER_PASS;
			action_conf.redirect_en = 1;
			act_q_cnt++;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
		case RTE_FLOW_ACTION_TYPE_PASSTHRU:
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			action_conf.redirect_en = 1;
			action_conf.rule_action = MCE_FILTER_DROP;
			act_q_cnt++;
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			memcpy(&action_conf.mark, act->conf,
			       sizeof(struct rte_flow_action_mark));
			action_conf.mark_en = 1;
			act_mark_cnt++;
			break;
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ACTION_TYPE_OF_POP_VLAN:
			action_conf.pop_vlan = 1;
#endif
			break;
		default:
			return rte_flow_error_set(
				error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
				"Fdir Flow Act type not supported");
		}
	}
	if (act_q_cnt >= 2)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
			"Flow Act type Queue 1 Rule Just Support One");
	if (act_mark_cnt >= 2)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
			"Flow Act type Mark 1 Rule Just Support One");
	if (meta_num == 0)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "Flow item is not support");
	/* if don't need upload the correct match info
	 * just upload the pattern is parse ready
	 */
	if (rule == NULL)
		goto end;
	tmp = rte_zmalloc(NULL, sizeof(struct mce_fdir_rule), 0);
	if (tmp == NULL)
		return -ENOMEM;
	tmp->engine_rule = support->meta_to_rule(handle, meta_num, mask_info,
						 &action_conf, inset, is_ipv6,
						 is_tunnel);
	if (tmp->engine_rule == NULL)
		return rte_flow_error_set(error, ENOMEM,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "fdir rule memory alloc failed");
	tmp->e_module = support->e_module;
	tmp->tun_type = tun_type;
	tmp->profile_id = support->hw_type;

	*rule = tmp;
end:
	memset(&handle->meta_db[is_tunnel][0], 0, sizeof(struct mce_lkup_meta) * meta_num);
	return 0;
}


/**
 * @brief Populate hardware action fields and prepare key for programming.
 *
 * Translates the parsed action configuration into the hardware `action`
 * word and sets the `hw_inset` keys/profile fields before key setup.
 *
 * @param filter Pointer to the filter whose hardware inset will be prepared.
 * @return 0 on success.
 */
static int mce_program_fdir_rule(struct mce_fdir_filter *filter)
{
	struct mce_flow_action *action = &filter->actions;
	uint16_t queue_id = 0;
	uint32_t act = 0;

	filter->hw_inset.profile_id = filter->profile_id;
	queue_id = action->redir.index;
	if (action->redirect_en) {
		if (action->rule_action) {
			act = MCE_RULE_ACTION_DROP | MCE_RULE_ACTION_Q_EN;
		} else {
			act = MCE_RULE_ACTION_Q_EN | MCE_RULE_ACTION_PASS;
			act |= queue_id << MCE_RULE_ACTION_Q_S;
		}
	}
	if (action->mark_en) {
		act |= MCE_RULE_ACTION_MARK_EN;
		act |= (action->mark.id) & (UINT16_MAX);
	}
	if (action->pop_vlan) {
		act |= MCE_RULE_ACTION_VLAN_EN;
		act |= MCE_POP_1VLAN << MCE_RULE_ACTION_POP_VLAN_S;
	}
	filter->hw_inset.profile_id = filter->profile_id;
	filter->hw_inset.action = act;
	mce_fdir_key_setup(filter);

	return 0;
}

/**
 * @brief Create and install a FDIR filter rule in hardware.
 *
 * Converts the parsed `flow->rule` into a hardware filter entry, assigns
 * a profile and installs the rule in the device. Returns an error if an
 * identical rule already exists.
 *
 * @param vport
 *   VPort owning the flow.
 * @param flow
 *   Flow containing the pre-parsed FDIR rule.
 * @param error
 *   Error reporting structure.
 * @return
 *   0 on success, negative errno on failure (e.g., EEXIST if rule exists,
 *   ENOTSUP if hardware resources insufficient).
 */
static int mce_fdir_flow_create(struct mce_vport *vport, struct rte_flow *flow,
				struct rte_flow_error *error)
{
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_fdir_rule *rule = (struct mce_fdir_rule *)flow->rule;
	struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_fdir_filter *filter = NULL;
	struct mce_fdir_filter *find = NULL;
	struct mce_fdir_handle *handle = NULL;
	struct mce_hw_profile *profile = NULL;
	uint64_t field_mask_options = 0;
	bool new_profile = false;
	int ret = 0;

	handle = (struct mce_fdir_handle *)flow_engine->handle;
	filter = (struct mce_fdir_filter *)rule->engine_rule;
	filter->lkup_pattern.formatted.tun_type = rule->tun_type;
	find = mce_fdir_entry_lookup(handle, filter);
	if (find)
		return rte_flow_error_set(error, EEXIST,
					  RTE_FLOW_ERROR_TYPE_ITEM, find,
					  "add fdir rule is exist");
	filter->hw_inset.keys.tun_type = rule->tun_type;
	filter->profile_id = rule->profile_id;
	if (handle->profiles[filter->profile_id] == NULL) {
		profile = mce_fdir_alloc_profile(handle, filter);
		if (profile == NULL)
			return rte_flow_error_set(error, -EINVAL,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  handle,
						  "fdir profile mask is null");
		handle->profiles[filter->profile_id] = profile;
		mce_fdir_profile_update(hw, profile, true);
		new_profile = true;
	} else {
		if (!mce_conflct_profile_check(handle, filter)) {
			if (filter->mask_info) {
				rte_free(filter->mask_info->field_bitmask);
				rte_free(filter->mask_info);
				rte_free(filter);
			}
			return rte_flow_error_set(
				error, -EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
				handle,
				"filter field_mask is conflict with old "
				"profile "
				"set");
		}
		profile = handle->profiles[filter->profile_id];
	}
	if (filter->mask_info) {
		if (profile->mask_info) {
			ret = mce_check_conflct_filed_bitmask(
				profile, filter->mask_info);
			if (ret) {
				rte_free(filter->mask_info->field_bitmask);
				rte_free(filter->mask_info);
				rte_free(filter);
				return rte_flow_error_set(
					error, -EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, handle,
					"fdir profile mask is inval");
			}
		} else {
			if (new_profile) {
				field_mask_options = mce_prof_bitmask_alloc(
					vport, handle, filter->mask_info);
				if (field_mask_options == 0) {
					mce_fdir_profile_update(
							hw, profile, false);
					handle->profiles[filter->profile_id] = NULL;
					rte_free(profile);
					rte_free(filter->mask_info
							 ->field_bitmask);
					rte_free(filter->mask_info);
					rte_free(filter);
					return rte_flow_error_set(
						error, -EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						handle,
						"fdir profile field mask "
						"resource "
						"is not enough");
				}
				mce_profile_field_bitmask_update(
					vport->hw, profile->profile_id,
					field_mask_options);
				profile->mask_info = filter->mask_info;
			} else {
				rte_free(filter->mask_info);
				rte_free(filter);

				return rte_flow_error_set(
					error, -EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, handle,
					"filter field_mask is conflict with"
					"old profile it is all mask");
			}
		}
	} else {
		if (profile->mask_info) {
			/* need to check bitmask rule is conflict with file_mask
			 * rule */
			rte_free(filter);
			return rte_flow_error_set(
				error, -EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
				handle,
				"profile field_bitmask is enable will conflict"
				" whit field mask so don't allow user set it");
		}
	}
	mce_program_fdir_rule(filter);
	filter->fdirhash = mce_inset_compute_hash(handle, &filter->hw_inset,
						  filter->profile_id,
						  vport->attr.vport_id,
						  MCE_ATR_BUCKET_HASH_KEY);
	filter->fdirhash &= MCE_HASH_VALID_BIT;
	if (handle->mode == MCE_FDIR_SIGN_M_MODE) {
		filter->signhash = mce_inset_compute_hash(
			handle, &filter->hw_inset, filter->profile_id,
			vport->attr.vport_id, MCE_ATR_SIGNATURE_HASH_KEY);
		filter->signhash &= MCE_SIGN_HASH_VALID_BIT;
	}
	ret = mce_fdir_insert_entry(handle, vport, filter);
	if (ret < 0)
		goto mat_res_out_range;
	mce_edit_hw_rule(handle, vport, filter);
	if (pf->fdir_flush_en) {
		mce_fdir_programming(&pf->commit);
		memset(&pf->commit.cmd_buf, 0, sizeof(pf->commit.cmd_buf));
		pf->commit.cmd_block = 0;
	}
	mce_fdir_insert_hash_map(handle, filter);
	profile->ref_cnt++;
	if (filter->mask_info)
		filter->mask_info->ref_cnt++;

	return 0;
mat_res_out_range:
	if (filter->mask_info) {
		rte_free(filter->mask_info->field_bitmask);
		rte_free(filter->mask_info);
		rte_free(filter);
	}
	if (new_profile) {
		mce_fdir_profile_update(hw, profile, false);
		handle->profiles[filter->profile_id] = NULL;
		rte_free(profile);
	}
	return rte_flow_error_set(error, -ret, RTE_FLOW_ERROR_TYPE_HANDLE,
				  handle, "hash_entry is out of range");
}

/**
 * @brief Query packet counters and hits for a FDIR flow.
 *
 * Retrieves accumulated statistics (packet count, byte count) for a
 * FDIR rule and optionally resets counters. Outputs results to a
 * `struct rte_flow_query_count` structure.
 *
 * @param vport
 *   VPort owning the flow.
 * @param flow
 *   Flow to query.
 * @param out
 *   Output buffer (expected: struct rte_flow_query_count *).
 * @param error
 *   Error reporting structure.
 * @return
 *   0 on success, negative errno on failure.
 */
static int mce_fdir_flow_delate(struct mce_vport *vport, struct rte_flow *flow,
				struct rte_flow_error *error)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_fdir_rule *rule = (struct mce_fdir_rule *)flow->rule;
	struct mce_fdir_handle *handle = NULL;
	struct mce_fdir_filter *filter = NULL;
	struct mce_fdir_filter *find = NULL;

	handle = (struct mce_fdir_handle *)flow_engine->handle;
	filter = (struct mce_fdir_filter *)rule->engine_rule;
	find = mce_fdir_entry_lookup(handle, filter);
	if (find == NULL)
		return rte_flow_error_set(error, ENOENT,
					  RTE_FLOW_ERROR_TYPE_ITEM, handle,
					  "fdir rule entry isn't exist");
	mce_fdir_remove_entry(handle, vport, filter);
	mce_clear_hw_rule(handle, vport, filter);
	mce_fdir_remove_hash_map(handle, filter);
	mce_fdir_remove_profile(hw, handle, filter);

	return 0;
}

/**
 * @brief Query counters and state for an FDIR rule.
 *
 * Reads hardware age/hit registers for the provided FDIR filter and fills
 * the supplied output structure (typically `struct rte_flow_query_count`).
 *
 * @param vport VPort owning the rule.
 * @param flow Flow handle referencing the rule to query.
 * @param out Output buffer for query results (engine-specific format).
 * @param error rte_flow_error for reporting failures.
 * @return 0 on success, negative errno on failure.
 */
static int mce_fdir_flow_query(struct mce_vport *vport, struct rte_flow *flow,
			       void *out, struct rte_flow_error *error)

{
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	struct rte_flow_query_count *flow_stats = out;
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_fdir_rule *rule = (struct mce_fdir_rule *)flow->rule;
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_fdir_handle *handle = NULL;
	struct mce_fdir_filter *filter = NULL;
	struct mce_fdir_filter *find = NULL;

	handle = (struct mce_fdir_handle *)flow_engine->handle;
	filter = (struct mce_fdir_filter *)rule->engine_rule;
	find = mce_fdir_entry_lookup(handle, filter);
	if (find == NULL)
		return rte_flow_error_set(error, ENOENT,
					  RTE_FLOW_ERROR_TYPE_ITEM, handle,
					  "fdir rule entry isn't exist");

	uint32_t age_state;
	uint32_t reg = 0;

	reg = MCE_E_REG_READ(hw, MCE_FDIR_RULE_AGE);
	reg &= ~GENMASK_U32(14, 0);
	if (flow_stats->reset)
		reg |= RTE_BIT32(15);
	else
		reg &= ~RTE_BIT32(15);
	reg |= filter->loc | MCE_FDIR_AGE_TM_READ;
	MCE_E_REG_WRITE(hw, MCE_FDIR_RULE_AGE, reg);

	reg = MCE_E_REG_READ(hw, MCE_FDIR_RULE_AGE);
	reg |= RTE_BIT32(14);
	MCE_E_REG_WRITE(hw, MCE_FDIR_RULE_AGE, reg);

	age_state = MCE_E_REG_READ(hw, MCE_FIDR_RULE_AGE_STATE);
	if (age_state)
		printf("hit 0x%.2x\n", age_state);
	flow_stats->hits_set = 1;
	flow_stats->hits = 1;
	flow_stats->bytes_set = 0;
	flow_stats->bytes = 0;
#else
	RTE_SET_USED(vport);
	RTE_SET_USED(flow);
	RTE_SET_USED(out);
	RTE_SET_USED(error);
#endif
	return 0;
}

#ifdef MCE_COMMIT_QUEUE
/**
 * @brief Reserve or lookup a memzone for FDIR commit packets.
 *
 * Ensures an IO-contiguous memzone exists and returns its descriptor.
 *
 * @param name Memzone name to reserve or lookup.
 * @param len Size of the memzone in bytes.
 * @param socket_id Socket ID for allocation.
 * @return Pointer to reserved memzone on success, NULL on failure.
 */
static const struct rte_memzone *
mce_memzone_reserve(const char *name, uint32_t len, int socket_id)
{
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(name);
	if (mz)
		return mz;

	return rte_memzone_reserve_aligned(name, len, socket_id,
					   RTE_MEMZONE_IOVA_CONTIG, 128);
}
#endif

/**
 * @brief Initialize the FDIR flow engine for a VPort.
 *
 * Allocates engine state (hash tables, maps), configures FDIR hardware
 * control registers and, when enabled, allocates commit buffers for
 * profile programming.
 *
 * @param vport VPort to initialize the engine for.
 * @param handle Out parameter receiving engine handle pointer.
 * @return 0 on success, negative errno on failure.
 */
static int mce_fdir_flow_engine_init(struct mce_vport *vport, void **handle)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	char fdir_hash_name[RTE_HASH_NAMESIZE];
	struct rte_hash_parameters fdir_hash_params = {
		.name = fdir_hash_name,
		.entries = 0,
		.key_len = sizeof(union mce_fdir_pattern),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	struct mce_fdir_handle *fdir_handle;
	uint32_t max_hash_entry = 0;
	uint32_t fd_entries = 0;
	uint32_t reg = 0;

	fdir_handle = rte_zmalloc(NULL, sizeof(struct mce_fdir_handle), 0);
	if (fdir_handle == NULL)
		return -ENOMEM;
	fdir_handle->hash_mode = MCE_MODE_HASH_EX_PORT;
	if (pf->fdir_mode == MCE_FDIR_SIGN_M_MODE || pf->fdir_mode == MCE_FDIR_MACVLAN_MODE) {
		fdir_handle->mode = MCE_FDIR_SIGN_M_MODE;
		fd_entries = 16 * 1024;
		max_hash_entry = fd_entries;
		fdir_handle->ipv4_max_hash_entry = fd_entries;
	} else {
		fdir_handle->mode = MCE_FDIR_EXACT_M_MODE;
		fd_entries = 8192;
		max_hash_entry = 8192 + 4096;
		fdir_handle->ipv4_max_hash_entry = 8192;
		fdir_handle->ipv6_max_hash_entry = 4096;
	}
	fdir_hash_params.entries = fd_entries;
	snprintf(fdir_hash_name, RTE_HASH_NAMESIZE, "fdir_%s",
		 vport->hw->device_name);
	fdir_handle->hash_handle = rte_hash_create(&fdir_hash_params);
	if (!fdir_handle->hash_handle) {
		PMD_INIT_LOG(ERR, "Failed to create fdir hash table!");
		return -EINVAL;
	}
	fdir_handle->hash_map = rte_zmalloc("mce",
		sizeof(struct mce_fdir_filter *) * fdir_hash_params.entries, 0);
	if (fdir_handle->hash_map == NULL) {
		PMD_INIT_LOG(ERR,
			     "Failed to allocate memory for fdir hash map!");
		rte_hash_free(fdir_handle->hash_handle);
		return -ENOMEM;
	}
	if (fdir_handle->mode == MCE_FDIR_EXACT_M_MODE) {
		/* setup ipv6 rule store db */
		fdir_hash_params.entries = 4096;
		snprintf(fdir_hash_name, RTE_HASH_NAMESIZE, "fdir_ex_%s",
			 vport->hw->device_name);
		fdir_handle->ex_hash_handle =
			rte_hash_create(&fdir_hash_params);
		if (!fdir_handle->ex_hash_handle) {
			PMD_INIT_LOG(ERR, "Failed to create fdir hash table!");
			return -EINVAL;
		}
		fdir_handle->ex_hash_map = rte_zmalloc(
			"mce",
			sizeof(struct mce_fdir_filter *) * MCE_MAX_FDIR_ENTRY,
			0);
		if (fdir_handle->ex_hash_map == NULL) {
			PMD_INIT_LOG(
				ERR,
				"Failed to allocate memory for fdir hash map!");
			rte_hash_free(fdir_handle->ex_hash_handle);
			return -ENOMEM;
		}
		TAILQ_INIT(&fdir_handle->hash_entry0_list);
		TAILQ_INIT(&fdir_handle->hash_entry1_list);
	} else {
		TAILQ_INIT(&fdir_handle->hash_entry0_list);
	}
	fdir_handle->fdir_entry_map = rte_zmalloc("mce_fdir_entry",
		sizeof(struct mce_fdir_hash_entry) * max_hash_entry, 0);
	if (pf->fdir_flush_en) {
		const struct rte_memzone *mz = NULL;
		char z_name[RTE_MEMZONE_NAMESIZE];
		uint64_t dma_addr = 0;

		mce_fdir_setup_txq(vport);
		mce_fdir_tx_queue_start(vport->dev);
#define MCE_FDIR_PKT_LEN 512

		/* reserve memory for the fdir profileming packet */
		snprintf(z_name, sizeof(z_name), "MCE_FDIR_%d",
			 vport->data->port_id);
		mz = mce_memzone_reserve(z_name, MCE_FDIR_PKT_LEN,
					 SOCKET_ID_ANY);
		if (!mz) {
			PMD_DRV_LOG(ERR, "Cannot init memzone for "
					 "flow director profile packet.");
			return -ENOMEM;
		}
		pf->commit.prg_pkt = mz->addr;
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#ifndef RTE_LIBRTE_XEN_DOM0
		dma_addr = (uint64_t)mz->phys_addr;
#else
		dma_addr = rte_mem_phy2mch((rz)->memseg_id, (mz)->phys_addr);
#endif
#else
		dma_addr = mz->iova;
#endif
		pf->commit.dma_addr = dma_addr;
		pf->commit.mz = mz;
#define MCE_FDIR_CMD_FIFO_C  _E_FDIR_F(0x0010)
#define MCE_FDIR_CMD_FIFO_EN RTE_BIT32(31)
		reg = MCE_E_REG_READ(hw, MCE_FDIR_CMD_FIFO_C);
		reg |= MCE_FDIR_CMD_FIFO_EN;
		MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_FIFO_C, reg);
		fdir_handle->fdir_flush_en = 1;
	}
	/* setup fdir hash input key */
	MCE_E_REG_WRITE(hw, MCE_FDIR_LK_KEY, MCE_ATR_BUCKET_HASH_KEY);
	MCE_E_REG_WRITE(hw, MCE_FDIR_SIGN_LK_KEY, MCE_ATR_SIGNATURE_HASH_KEY);
	/* fdir hash mode setup */
	reg = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
	if (fdir_handle->mode == MCE_FDIR_SIGN_M_MODE)
		reg |= MCE_FDIR_SIGN_M_EN;
	reg |= MCE_FDIR_TUN_TYPE_HASH_EN;
	reg |= MCE_FDIR_HASH_PORT;
	MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, reg);
	/* fdir profile mask setup */
	reg = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
	reg |= MCE_FDIR_PRF_MASK_EN;
	MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, reg);
	if (pf->fdir_mode == MCE_FDIR_MACVLAN_MODE) {
		/* MCE_FDIR_L2_M_MAC */
		reg = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
		reg |= MCE_FDIR_L2_M_MAC << MCE_FDIR_L2_M_S;
		MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, reg);
		printf("enable only mode\n");
	} else {
		/* MCE_FDIR_IP_DSCP_EN */
		reg = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
		reg |= MCE_FDIR_IP_DSCP_EN;
		MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, reg);
		/* MCE_FDIR_PAY_PROTO_EN */
		reg = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
		reg |= MCE_FDIR_PAY_PROTO_EN;
		MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, reg);
		/* enable esp spi match */
		reg = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
		reg |= MCE_FDIR_UDP_ESP_SPI_EN;
		MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, reg);
	}
	/* init hw age engine */
	MCE_E_REG_WRITE(hw, MCE_FDIR_RULE_AGE, MCE_FDIR_AGE_EN);
	rte_delay_ms(100);
#define MCE_AUTO_AGE_TM (10)
	reg = MCE_AUTO_AGE_TM << MCE_FDIR_AGE_TM_VAL_S | MCE_FDIR_AGE_AUTO_EN;
	MCE_E_REG_WRITE(hw, MCE_FDIR_RULE_AGE, reg);

	*handle = fdir_handle;

	return 0;
}

/**
 * @brief Uninitialize and free resources for the FDIR flow engine.
 *
 * Frees hash tables, maps and other engine-specific allocations.
 *
 * @param vport VPort associated with the engine (unused currently).
 * @param handle Engine handle previously returned by init.
 * @return 0 on success.
 */
static int mce_fdir_flow_engine_uinit(struct mce_vport *vport, void *handle)
{
	struct mce_fdir_handle *fdir_handle = handle;

	RTE_SET_USED(vport);
	rte_free(fdir_handle->fdir_entry_map);
	rte_free(fdir_handle->ex_hash_map);
	rte_free(fdir_handle->hash_map);

	rte_hash_free(fdir_handle->ex_hash_handle);
	rte_hash_free(fdir_handle->hash_handle);

	rte_free(fdir_handle);

	return 0;
}

struct mce_flow_engine_module mce_fdir_engine = {
	.parse = mce_fdir_flow_parse,
	.create = mce_fdir_flow_create,
	.destroy = mce_fdir_flow_delate,
	.query = mce_fdir_flow_query,
	.init = mce_fdir_flow_engine_init,
	.uinit = mce_fdir_flow_engine_uinit,
	.name = "mce_fdir_flow",
	.type = MCE_FLOW_FDIR,
};
