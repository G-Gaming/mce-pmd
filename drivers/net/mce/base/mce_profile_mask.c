#include <assert.h>
#include <strings.h>

#include "mce_eth_regs.h"
#include "mce_profile_mask.h"

#include "../mce_fdir_flow.h"
#include "../mce_pattern.h"
#include "../mce.h"

struct mce_profile_options_mask {
	u64 options;

	u32 field_mask;
};

#define MCE_FIELD_M_IP4_SIP   RTE_BIT32(0)
#define MCE_FIELD_M_IP4_DIP   RTE_BIT32(1)
#define MCE_FIELD_M_IP6_SIP   (RTE_BIT32(0) | RTE_BIT32(5))
#define MCE_FIELD_M_IP6_DIP   (RTE_BIT32(1) | RTE_BIT32(6))
#define MCE_FIELD_M_L4_PROTO  RTE_BIT32(2)
#define MCE_FIELD_M_L4_SPORT  RTE_BIT32(2)
#define MCE_FIELD_M_L4_DPORT  RTE_BIT32(3)
#define MCE_FIELD_M_TEID      RTE_BIT32(4)
#define MCE_FIELD_M_DSCP      RTE_BIT32(4)
#define MCE_FIELD_M_VNI	      RTE_BIT32(4)
#define MCE_FIELD_M_NVGRE_TNI RTE_BIT32(4)
#define MCE_FIELD_M_ESP_SPI   (RTE_BIT32(2) | RTE_BIT32(3))

#define MCE_FIELD_M_ETH_VLAN  RTE_BIT32(0)
#define MCE_FIELD_M_ETH_SMAC  (RTE_BIT32(1) | RTE_BIT32(2))
#define MCE_FIELD_M_ETH_DMAC  (RTE_BIT32(3) | RTE_BIT32(4))
#define MCE_FIELD_M_ETH_TYPE  RTE_BIT32(0)
static struct mce_profile_options_mask mce_dummy_todo[] = {
	{ 0, 0 },
};
static struct mce_profile_options_mask mce_ipv4_tcp_sync[] = {
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};
static struct mce_profile_options_mask mce_ipv4_tcp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_TCP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};
static struct mce_profile_options_mask mce_ipv4_udp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_UDP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_UDP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};
static struct mce_profile_options_mask mce_ipv4_sctp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_UDP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_UDP_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};
static struct mce_profile_options_mask mce_ipv4_esp[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_ESP_SPI, MCE_FIELD_M_ESP_SPI },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};
static struct mce_profile_options_mask mce_ipv4_pay[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_L4_PROTO, MCE_FIELD_M_L4_PROTO },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
};
static struct mce_profile_options_mask mce_ipv4_frag[] = {
	{ MCE_OPT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_IPV4_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_IPV4_FRAG, 0 },
};
static struct mce_profile_options_mask mce_ipv4_vxlan[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_VXLAN_VNI, MCE_FIELD_M_VNI },
};
static struct mce_profile_options_mask mce_ipv4_geneve[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GENEVE_VNI, MCE_FIELD_M_VNI },
};
static struct mce_profile_options_mask mce_ipv4_nvgre[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_NVGRE_TNI, MCE_FIELD_M_NVGRE_TNI },
};
static struct mce_profile_options_mask mce_ipv4_gtpu[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_U_TEID, MCE_FIELD_M_TEID },
};
static struct mce_profile_options_mask mce_ipv4_gtpc[] = {
	{ MCE_OPT_OUT_IPV4_SIP, MCE_FIELD_M_IP4_SIP },
	{ MCE_OPT_OUT_IPV4_DIP, MCE_FIELD_M_IP4_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_C_TEID, MCE_FIELD_M_TEID },
};
static struct mce_profile_options_mask mce_ipv6_tcp_sync[] = {
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};
static struct mce_profile_options_mask mce_ipv6_tcp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_TCP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_TCP_DPORT, MCE_FIELD_M_L4_DPORT },
};
static struct mce_profile_options_mask mce_ipv6_udp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_UDP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_UDP_DPORT, MCE_FIELD_M_L4_DPORT },
};
static struct mce_profile_options_mask mce_ipv6_sctp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_SCTP_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_SCTP_DPORT, MCE_FIELD_M_L4_DPORT },
};
static struct mce_profile_options_mask mce_ipv6_esp[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_ESP_SPI, MCE_FIELD_M_ESP_SPI },
};
static struct mce_profile_options_mask mce_ipv6_pay[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_L4_PROTO, MCE_FIELD_M_L4_PROTO },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
};
static struct mce_profile_options_mask mce_ipv6_frag[] = {
	{ MCE_OPT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_IPV6_DSCP, MCE_FIELD_M_DSCP },
	{ MCE_OPT_IPV6_FRAG, 0 },
};
static struct mce_profile_options_mask mce_ipv6_vxlan[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_VXLAN_VNI, MCE_FIELD_M_VNI },
};
static struct mce_profile_options_mask mce_ipv6_geneve[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GENEVE_VNI, MCE_FIELD_M_VNI },
};
static struct mce_profile_options_mask mce_ipv6_nvgre[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_NVGRE_TNI, MCE_FIELD_M_NVGRE_TNI },
};
static struct mce_profile_options_mask mce_ipv6_gtpu[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_U_TEID, MCE_FIELD_M_TEID },
};
static struct mce_profile_options_mask mce_ipv6_gtpc[] = {
	{ MCE_OPT_OUT_IPV6_SIP, MCE_FIELD_M_IP6_SIP },
	{ MCE_OPT_OUT_IPV6_DIP, MCE_FIELD_M_IP6_DIP },
	{ MCE_OPT_OUT_L4_SPORT, MCE_FIELD_M_L4_SPORT },
	{ MCE_OPT_OUT_L4_DPORT, MCE_FIELD_M_L4_DPORT },
	{ MCE_OPT_GTP_C_TEID, MCE_FIELD_M_TEID },
};
static struct mce_profile_options_mask mce_l2_eth[] = {
	{ MCE_OPT_VLAN_VID, MCE_FIELD_M_ETH_VLAN },
	{ MCE_OPT_SMAC, MCE_FIELD_M_ETH_SMAC },
	{ MCE_OPT_DMAC, MCE_FIELD_M_ETH_DMAC },
};
static struct mce_profile_options_mask mce_l2_ethtype[] = {
	{ MCE_OPT_ETHTYPE, MCE_FIELD_M_ETH_TYPE },
};
struct mce_profile_select_db {
	u64 profile_id;
	struct mce_profile_options_mask *options_list;
	u16 sup_options_num;
};
static struct mce_profile_select_db mce_profile_bitmask[] = {
	{ MCE_PTYPE_UNKNOW, mce_dummy_todo, 0 }, /* 0 */
	{ MCE_PTYPE_L2_ONLY, mce_l2_eth, 3 }, /* 1 */
	{ MCE_PTYPE_TUN_INNER_L2_ONLY, mce_l2_eth, 3 }, /* 2 */
	{ MCE_PTYPE_TUN_OUTER_L2_ONLY, mce_l2_eth, 3 }, /* 3 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_FRAG, mce_ipv4_frag, 4 }, /* 4 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_FRAG, mce_ipv6_frag, 4 }, /* 5 */
	{ MCE_PTYPE_L2_ETHTYPE, mce_l2_ethtype, 1 }, /* 6 */
	{ MCE_PTYPE_TUN_INNER_L2_ETHTYPE, mce_l2_ethtype, 1 }, /* 7 */
	{ MCE_PTYPE_IPV4_FRAG, mce_ipv4_frag, 4 }, /* 8*/
	{ MCE_PTYPE_IPV4_TCP_SYNC, mce_ipv4_tcp_sync, 2 }, /* 9 */
	{ MCE_PTYPE_IPV4_TCP, mce_ipv4_tcp, 4 }, /* 10 */
	{ MCE_PTYPE_IPV4_UDP, mce_ipv4_udp, 4 }, /* 11 */
	{ MCE_PTYPE_IPV4_SCTP, mce_ipv4_sctp, 4 }, /* 12 */
	{ MCE_PTYPE_IPV4_ESP, mce_ipv4_esp, 3 }, /* 13 */
	{ MCE_PTYPE_IPV4_PAY, mce_ipv4_pay, 4 }, /* 14 */
	{ 0, 0, 0 }, /* 15 */
	{ MCE_PTYPE_IPV6_FRAG, mce_ipv6_frag, 4 }, /* 16 */
	{ MCE_PTYPE_IPV6_TCP_SYNC, mce_ipv6_tcp_sync, 2 }, /* 17 */
	{ MCE_PTYPE_IPV6_TCP, mce_ipv6_tcp, 4 }, /* 18 */
	{ MCE_PTYPE_IPV6_UDP, mce_ipv6_udp, 4 }, /* 19 */
	{ MCE_PTYPE_IPV6_SCTP, mce_ipv6_sctp, 4 }, /* 20 */
	{ MCE_PTYPE_IPV6_ESP, mce_ipv6_esp, 3 }, /* 21 */
	{ MCE_PTYPE_IPV6_PAY, mce_ipv6_pay, 4 }, /* 22 */
	{ 0, 0, 0 }, /* 23 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_PAY, mce_ipv4_pay,
	  RTE_DIM(mce_ipv4_pay) }, /* 24 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_TCP, mce_ipv4_tcp, 4 }, /* 25 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_UDP, mce_ipv4_udp, 4 }, /* 26 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_SCTP, mce_ipv4_sctp, 4 }, /* 27 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_PAY, mce_ipv6_pay, 4 }, /* 28 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_TCP, mce_ipv6_tcp, 4 }, /* 29 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_UDP, mce_ipv6_udp, 4 }, /* 30 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_SCTP, mce_ipv6_sctp, 4 }, /* 31 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV4, mce_ipv4_gtpu, 5 }, /* 32 */
	{ MCE_PTYPE_GTP_U_IPV4, mce_ipv4_gtpu, 5 }, /* 33 */
	{ MCE_PTYPE_GTP_C_TEID_IPV4, mce_ipv4_gtpc, 5 }, /* 34 */
	{ MCE_PTYPE_GTP_C_IPV4, mce_ipv4_udp, 4 }, /* 35 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV6, mce_ipv6_gtpu, 5 }, /* 36 */
	{ MCE_PTYPE_GTP_U_IPV6, mce_ipv6_gtpu, 5 }, /* 37 */
	{ MCE_PTYPE_GTP_C_TEID_IPV6, mce_ipv6_gtpc, 5 }, /* 38 */
	{ MCE_PTYPE_GTP_C_IPV6, mce_ipv6_udp, 4 }, /* 39 */
	{ MCE_PTYPE_TUN_INNER_IPV4_FRAG, mce_ipv4_frag, 4 }, /* 40 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP_SYNC, mce_ipv4_tcp_sync, 2 }, /* 41 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP, mce_ipv4_tcp, 4 }, /* 42 */
	{ MCE_PTYPE_TUN_INNER_IPV4_UDP, mce_ipv4_udp, 4 }, /* 43 */
	{ MCE_PTYPE_TUN_INNER_IPV4_SCTP, mce_ipv4_sctp, 4 }, /* 44 */
	{ MCE_PTYPE_TUN_INNER_IPV4_ESP, mce_ipv4_esp, 3 }, /* 45 */
	{ MCE_PTYPE_TUN_INNER_IPV4_PAY, mce_ipv4_pay, 4 }, /* 46 */
	{ 0, 0, 0 }, /* 47 */
	{ MCE_PTYPE_TUN_INNER_IPV6_FRAG, mce_ipv6_frag, 4 }, /* 48 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP_SYNC, mce_ipv6_tcp_sync, 2 }, /* 49 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP, mce_ipv6_tcp, 4 }, /* 50 */
	{ MCE_PTYPE_TUN_INNER_IPV6_UDP, mce_ipv6_udp, 4 }, /* 51 */
	{ MCE_PTYPE_TUN_INNER_IPV6_SCTP, mce_ipv6_sctp, 4 }, /* 52 */
	{ MCE_PTYPE_TUN_INNER_IPV6_ESP, mce_ipv6_esp, 3 }, /* 53 */
	{ MCE_PTYPE_TUN_INNER_IPV6_PAY, mce_ipv6_pay, 4 }, /* 54 */
	{ 0, 0, 0 }, /* 55 */
	{ MCE_PTYPE_TUN_IPV4_VXLAN, mce_ipv4_vxlan, 5 }, /* 56 */
	{ MCE_PTYPE_TUN_IPV4_GENEVE, mce_ipv4_geneve, 5 }, /* 57 */
	{ MCE_PTYPE_TUN_IPV4_GRE, mce_ipv4_nvgre, 3 }, /* 58 */
	{ 0, 0, 0 }, /* 59 */
	{ MCE_PTYPE_TUN_IPV6_VXLAN, mce_ipv6_vxlan, 5 }, /* 60 */
	{ MCE_PTYPE_TUN_IPV6_GENEVE, mce_ipv6_geneve, 5 }, /* 61 */
	{ MCE_PTYPE_TUN_IPV6_GRE, mce_ipv6_nvgre, 3 }, /* 62 */
};

struct mce_profile_field_mask {
	u64 options;
	u16 bit_val;
};

struct mce_field_mask {
	u16 offset;
	u16 key_off;
	u8 mask_block[8];
	u16 mask_wide;
	u64 mask_options;
};

static const struct mce_field_mask mce_eth_mask[] = {
	{
		offsetof(struct mce_ether_meta, src_addr),
		4,
		"\xff\xff\xff\xff\xff\xff",
		6,
		MCE_OPT_SMAC,
	},
	{
		offsetof(struct mce_ether_meta, dst_addr),
		10,
		"\xff\xff\xff\xff\xff\xff",
		6,
		MCE_OPT_DMAC,
	},
	{
		offsetof(struct mce_ether_meta, ethtype_id),
		0,
		"\xff\xff",
		2,
		MCE_OPT_ETHTYPE,
	},
};

static const struct mce_field_mask mce_vlan_mask[] = {
	{
		offsetof(struct mce_vlan_meta, vlan_id),
		0,
		"\x0f\xff",
		2,
		MCE_OPT_VLAN_VID,
	},
};

static const struct mce_field_mask mce_ipv4_mask[] = {
	{ offsetof(struct mce_ipv4_meta, src_addr),
	  0,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_IPV4_SIP },
	{ offsetof(struct mce_ipv4_meta, dst_addr),
	  4,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_IPV4_DIP },
	{ offsetof(struct mce_ipv4_meta, protocol),
	  8,
	  { "\xff" },
	  1,
	  MCE_OPT_L4_PROTO },
	{
		offsetof(struct mce_ipv4_meta, dscp),
		12,
		{ "\xfc" },
		1,
		MCE_OPT_IPV4_DSCP,
	},
	{
		offsetof(struct mce_ipv4_meta, is_frag),
		0,
		{ "\x00" },
		1,
		MCE_OPT_IPV4_FRAG,
	},
};

static const struct mce_field_mask mce_tcp_mask[] = {
	{ offsetof(struct mce_tcp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_TCP_SPORT },
	{ offsetof(struct mce_tcp_meta, dst_port),
	  10,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_TCP_DPORT },
};

static const struct mce_field_mask mce_udp_mask[] = {
	{ offsetof(struct mce_udp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_UDP_SPORT },
	{ offsetof(struct mce_udp_meta, dst_port),
	  10,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_UDP_DPORT },
};

static const struct mce_field_mask mce_sctp_mask[] = {
	{ offsetof(struct mce_sctp_meta, src_port),
	  8,
	  { "\xff\xff" },
	  2,
	  MCE_OPT_SCTP_SPORT },
	{ offsetof(struct mce_sctp_meta, dst_port),
	  10,
	  { "\xff\xff\xff\xff" },
	  2,
	  MCE_OPT_SCTP_DPORT },
};

static const struct mce_field_mask mce_ipv6_mask[] = {
	{ offsetof(struct mce_ipv6_meta, src_addr),
	  0,
	  { "\xff\xff\xff\xff\xff\xff\xff\xff" },
	  16,
	  MCE_OPT_IPV6_SIP },
	{ offsetof(struct mce_ipv6_meta, dst_addr),
	  4,
	  { "\xff\xff\xff\xff\xff\xff\xff\xff" },
	  16,
	  MCE_OPT_IPV6_DIP },
	{ offsetof(struct mce_ipv6_meta, protocol),
	  8,
	  { "\xff" },
	  1,
	  MCE_OPT_L4_PROTO },
	{ offsetof(struct mce_ipv6_meta, dscp),
	  12,
	  { "\xfc" },
	  1,
	  MCE_OPT_IPV6_DSCP },
	{
		offsetof(struct mce_ipv6_meta, is_frag),
		0,
		{ "\x00" },
		1,
		MCE_OPT_IPV6_FRAG,
	},
};

static const struct mce_field_mask mce_esp_mask[] = {
	{ offsetof(struct mce_esp_meta, spi),
	  8,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_ESP_SPI },
};

static const struct mce_field_mask mce_vxlan_mask[] = {
	{ offsetof(struct mce_vxlan_meta, vni),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_VXLAN_VNI },
};

static const struct mce_field_mask mce_geneve_mask[] = {
	{ offsetof(struct mce_geneve_meta, vni),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_GENEVE_VNI },
};

static const struct mce_field_mask mce_nvgre_mask[] = {
	{ offsetof(struct mce_nvgre_meta, key),
	  12,
	  { "\xff\xff\xff\x00" },
	  4,
	  MCE_OPT_NVGRE_TNI },
};

static const struct mce_field_mask mce_gtp_mask[] = {
	{ offsetof(struct mce_gtp_meta, teid),
	  12,
	  { "\xff\xff\xff\xff" },
	  4,
	  MCE_OPT_GTP_U_TEID },
};

struct mce_field_mask_select_db {
	u16 type;
	const struct mce_field_mask *options_list;
	u16 sup_options_num;
};

static struct mce_field_mask_select_db mce_field_mask_db[] = {
	{ MCE_ETH_META, mce_eth_mask, RTE_DIM(mce_eth_mask) },
	{ MCE_VLAN_META, mce_vlan_mask, RTE_DIM(mce_vlan_mask) },
	{ MCE_IPV4_META, mce_ipv4_mask, RTE_DIM(mce_ipv4_mask) },
	{ MCE_IPV6_META, mce_ipv6_mask, RTE_DIM(mce_ipv6_mask) },
	{ 0, 0, 0 },
	{ MCE_UDP_META, mce_udp_mask, RTE_DIM(mce_udp_mask) },
	{ MCE_TCP_META, mce_tcp_mask, RTE_DIM(mce_tcp_mask) },
	{ MCE_SCTP_META, mce_sctp_mask, RTE_DIM(mce_sctp_mask) },
	{ MCE_ESP_META, mce_esp_mask, RTE_DIM(mce_esp_mask) },
	{ MCE_VXLAN_META, mce_vxlan_mask, RTE_DIM(mce_vxlan_mask) },
	{ MCE_GENEVE_META, mce_geneve_mask, RTE_DIM(mce_geneve_mask) },
	{ MCE_NVGRE_META, mce_nvgre_mask, RTE_DIM(mce_nvgre_mask) },
	{ MCE_GTPU_META, mce_gtp_mask, RTE_DIM(mce_gtp_mask) },
	{ MCE_GTPC_META, mce_gtp_mask, RTE_DIM(mce_gtp_mask) },
};

/**
 * @brief Validate that a lookup meta's field mask contains supported bits.
 *
 * Checks the provided lookup meta mask against known field masks and
 * returns 0 when the mask is empty or valid; otherwise returns a
 * non-zero value indicating how many non-matching mask blocks were found.
 *
 * @param meta Pointer to lookup meta to validate
 * @return 0 if valid/empty, non-zero if invalid bits found
 */
int mce_check_field_bitmask_valid(struct mce_lkup_meta *meta)
{
	union mce_flow_hdr *mask = &meta->mask;
	const struct mce_field_mask *field_opt;
	enum flow_meta_type type = meta->type;
	union mce_flow_hdr zero_mask = {};
	const char all_zero[256] = { 0 };
	int i = 0, j = 0;
	u8 *ptr = NULL;
	u16 block = 0;

	field_opt = mce_field_mask_db[type].options_list;
	if (!memcmp(&zero_mask, mask, sizeof(*mask)))
		return 0;
	ptr = (u8 *)mask;
	for (i = 0; i < mce_field_mask_db[type].sup_options_num;
	     i++, field_opt++) {
		if (!memcmp(all_zero, (ptr + field_opt->offset),
			    field_opt->mask_wide))
			continue;
		if (!memcmp((void const *)field_opt->mask_block,
			    (ptr + field_opt->offset), field_opt->mask_wide))
			continue;
		if (field_opt->mask_wide > 1) {
			u16 *fv = (u16 *)(((u8 *)mask) + field_opt->offset);
			for (j = 0; j < field_opt->mask_wide / 2; j++) {
				if (fv[j] != 0xffff)
					block++;
			}
		} else {
			if (!memcmp((u8 *)mask + field_opt->offset,
				    &field_opt->mask_block, 1))
				continue;
			block++;
		}
	}

	return block;
}

 /**
 * @brief Initialize field mask blocks for a set of lookup metas.
 *
 * Scans the provided metas and produces compact bitmask blocks describing
 * which key/offset/mask combinations must be programmed into hardware.
 * The results are written into the provided mask_info structure.
 *
 * @param meta Array of lookup metas
 * @param meta_num Number of metas in the array
 * @param mask_info Output structure to populate with bitmask blocks
 * @return Number of blocks populated
 */
int mce_fdir_field_mask_init(struct mce_lkup_meta *meta, u16 meta_num,
			     struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *block_mask = NULL;
	const struct mce_field_mask *field_opt;
	const char all_zero[256] = { 0 };
	union mce_flow_hdr *mask;
	int i = 0, j = 0, k = 0;
	u16 field_size = 0;
	u16 block = 0;
	u8 *ptr = NULL;
	u16 type = 0;
	/* ipv6-[3] ipv6[2] ipv6[1]--- ipv6-sip[0]	*/
	/*                        |< 96 >|  32		*/
	/* | 6 | 2 */
	/*                        | 128          |	*/
	/* 13 12 11 10 | 9 8 |765 432  | 1	0 |	*/
	block_mask = mask_info->field_bitmask;
	for (i = 0; i < meta_num; i++) {
		type = meta[i].type;
		mask = &meta[i].mask;
		ptr = (u8 *)mask;
		field_size = mce_field_mask_db[type].sup_options_num;
		field_size *= sizeof(struct mce_field_mask);
		field_opt = mce_field_mask_db[type].options_list;
		for (j = 0; j < mce_field_mask_db[type].sup_options_num;
		     j++, field_opt++) {
			if (!memcmp(all_zero, (ptr + field_opt->offset),
				    field_opt->mask_wide))
				continue;
			u16 *fv = (u16 *)(((u8 *)mask) + field_opt->offset);
			if (field_opt->mask_wide == 1) {
				if (fv[0] != 0xff) {
					block_mask->options =
						field_opt->mask_options;
					block_mask->key_off =
						field_opt->key_off + k * 2;
					block_mask->mask = fv[0];
					block_mask++;
					block++;
				}
			} else {
				for (k = 0; k < field_opt->mask_wide / 2; k++) {
					if (fv[k] != 0xffff) {
						printf("field_opt->mask_wide "
						       "%d fv 0x%.2x\n",
						       field_opt->mask_wide,
						       fv[k]);
						block_mask->options =
							field_opt->mask_options;
						block_mask->key_off =
							field_opt->key_off +
							k * 2;
						printf("base_key_off %d k %d\n",
						       block_mask->key_off, k);
						if (k > 1) {
							if (field_opt->mask_options ==
							    MCE_OPT_IPV6_SIP) {
								block_mask
									->key_off +=
									12;
							}
							if (field_opt->mask_options ==
							    MCE_OPT_IPV6_DIP)
								block_mask
									->key_off +=
									20;
						}
						printf("block_mask->key_off "
						       "0x%.2x\n",
						       block_mask->key_off);
						block_mask->mask = fv[k];
						block_mask++;
						block++;
					}
				}
			}
		}
	}
	mask_info->used_block = block;

	return block;
}

 /**
 * @brief Check for conflicts between an existing profile and new mask info.
 *
 * Ensures that the bitmask blocks in mask_info match those already stored
 * in the provided profile. Returns 0 when consistent, negative on conflict.
 *
 * @param profile Existing hardware profile
 * @param mask_info New mask info to compare
 * @return 0 if compatible, -EINVAL if a conflict exists
 */
int mce_check_conflct_filed_bitmask(struct mce_hw_profile *profile,
				    struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *src, *dst;
	bool new_mask = false;
	int i = 0;

	if (mask_info->used_block != profile->mask_info->used_block)
		return -EINVAL;
	for (i = 0; i < mask_info->used_block; i++) {
		dst = &profile->mask_info->field_bitmask[i];
		src = &mask_info->field_bitmask[i];
		if (src->key_off != dst->key_off || src->mask != dst->mask ||
		    src->options != dst->options) {
			new_mask = true;
		}
	}
	if (new_mask)
		return -EINVAL;

	return 0;
}

#define MCE_FIELD_VECTOR_MASK(n) _E_FDIR_F(0x02c0 + ((0x4 * (n))))
#define MCE_FIELD_VECTOR_MASK_S	 (16)
#define MCE_PROFILE_MASK_SEL(n)	 _E_FDIR_F(0x01c0 + ((0x4 * (n))))


/**
 * @brief Program a single field bitmask register for a hardware profile.
 *
 * Converts the compact block description into the HW register format and
 * writes the corresponding field vector mask register.
 *
 * @param hw Pointer to hardware context
 * @param options Field mask description to program
 * @param loc Hardware mask register index
 */
static void mce_field_bitmask_setup(struct mce_hw *hw,
				    struct mce_fdir_field_mask *options,
				    u16 loc)
{
	u32 ctrl = 0;

	if (options->mask == 0)
		options->mask = UINT16_MAX;
	ctrl |= (options->key_off / 2);
	ctrl |= ((~options->mask) << MCE_FIELD_VECTOR_MASK_S);

	MCE_E_REG_WRITE(hw, MCE_FIELD_VECTOR_MASK(loc), ctrl);
}

 /**
 * @brief Update the profile field mask selection register.
 *
 * Write the compiled bitmask options for the given profile into the
 * hardware profile select register.
 *
 * @param hw Pointer to hardware context
 * @param profile_id Profile identifier
 * @param options Bitmask options value to write
 */
void mce_profile_field_bitmask_update(struct mce_hw *hw, u16 profile_id,
				      u32 options)
{
	MCE_E_REG_WRITE(hw, MCE_PROFILE_MASK_SEL(profile_id), options);
}

 /**
 * @brief Allocate (or map) compact bitmask entries for a profile.
 *
 * Matches required bitmask blocks against the handle's pool, programming
 * new mask entries and returning a 32-bit options bitfield describing the
 * assigned mask indices.
 *
 * @param vport VPort context used for register programming
 * @param handle FDIR handle containing shared mask pool
 * @param mask_info Mask blocks to allocate
 * @return Options bitfield with bits set for allocated mask indices
 */
int mce_prof_bitmask_alloc(struct mce_vport *vport,
			   struct mce_fdir_handle *handle,
			   struct mce_field_bitmask_info *mask_info)
{
	struct mce_field_bitmask_block *block;
	u64 field_bitmask_opt = 0;
	int i = 0, j = 0;

	for (i = 0; i < mask_info->used_block; i++) {
		block = &mask_info->field_bitmask[i];
		for (j = 0; j < 32; j++) {
			if (handle->field_mask[j].used) {
				if (handle->field_mask[j].key_off ==
					    block->key_off &&
				    handle->field_mask[j].mask == block->mask) {
					field_bitmask_opt |= RTE_BIT32(j);
					handle->field_mask[j].ref_count++;
					break;
				}
			} else {
				handle->field_mask[j].key_off = block->key_off;
				handle->field_mask[j].mask = block->mask;
				handle->field_mask[j].used = 1;
				handle->field_mask[j].ref_count++;
				field_bitmask_opt |= RTE_BIT32(j);
				mce_field_bitmask_setup(
					vport->hw, &handle->field_mask[j], j);
				break;
			}
		}
	}

	return field_bitmask_opt;
}

 /**
 * @brief Check if an identical profile already exists or conflicts exist.
 *
 * If an existing profile is present with incompatible options this
 * function reports an error; otherwise it allows allocation.
 *
 * @param handle FDIR handle containing profile table
 * @param filter Incoming filter whose profile should be validated
 * @return 0 if ok, -EBUSY or other negative errno on conflict
 */
int mce_conflct_profile_check(struct mce_fdir_handle *handle,
			      struct mce_fdir_filter *filter)
{
	u64 profile_id = filter->profile_id;
	struct mce_hw_profile *profile = handle->profiles[profile_id];

	if (profile == NULL)
		return 0;
	if (profile->ref_cnt && profile->options == filter->options)
		return -EBUSY;
	if (profile->ref_cnt == 0) {
		free(profile);
		handle->profiles[profile_id] = NULL;
	}

	return 0;
}

 /**
 * @brief Allocate and initialize a hardware profile structure for a filter.
 *
 * Creates an `mce_hw_profile` and populates its field mask based on the
 * selected profile database and the filter's options. Returns NULL on
 * failure or if a conflicting profile exists.
 *
 * @param handle FDIR handle
 * @param filter Filter requesting a profile
 * @return Pointer to allocated `mce_hw_profile` or NULL
 */
struct mce_hw_profile *
mce_fdir_alloc_profile(struct mce_fdir_handle *handle,
		       struct mce_fdir_filter *filter)
{
	struct mce_profile_select_db *profile_db = NULL;
	struct mce_hw_profile *profile = NULL;
	u32 profile_id = filter->profile_id;
	int i, j, bit = -1, bit_num = 0;
	u64 options = filter->options;
	bool mask_match = false;

	if (mce_conflct_profile_check(handle, filter))
		return NULL;
	profile = rte_zmalloc("profile", sizeof(*profile), 0);
	if (profile == NULL)
		return NULL;
	profile->profile_id = profile_id;
	profile_db = &mce_profile_bitmask[profile_id];
	bit_num = __builtin_popcountl(options);
	for (i = 0; i < bit_num; i++) {
		bit = rte_ffs64(options) - 1;
		if (bit < 0)
			break;
		for (j = 0; j < profile_db->sup_options_num; j++) {
			if (RTE_BIT64(bit) ==
			    profile_db->options_list[j].options) {
				profile->fied_mask |=
					profile_db->options_list[j].field_mask;
				mask_match = true;
			}
		}
		options &= ~RTE_BIT64(bit);
	}
#define MCE_PROFILE_NO_OPT MCE_OPT_TCP_SYNC
	if (!mask_match && !(filter->options & MCE_PROFILE_NO_OPT)) {
		rte_free(profile);
		return NULL;
	}
	profile->options = filter->options;

	return profile;
}

/**
 * @brief Add or remove a profile's field-mask mapping in hardware.
 *
 * Updates the profile select registers with the profile's field mask or
 * clears them when removing the profile.
 *
 * @param hw Hardware context
 * @param profile Profile to program or remove
 * @param add True to program, false to remove
 * @return 0 on success
 */
int
mce_fdir_profile_update(struct mce_hw *hw, struct mce_hw_profile *profile,
			bool add)
{
	u64 addr_base;
	u32 cfg_shift;
	u32 reg;

	addr_base = MCE_PROFILE_FIELD_MASK_SELECT(profile->profile_id);
	cfg_shift = MCE_PROFILE_FIELD_LOC_SHIFT(profile->profile_id);

	if (add) {
		reg = MCE_E_REG_READ(hw, addr_base);
		reg &= ~(0XFF << cfg_shift);
		reg |= (profile->fied_mask << cfg_shift);
	} else {
		reg = MCE_E_REG_READ(hw, addr_base);
		reg &= ~(0XFF << cfg_shift);
	}
	MCE_E_REG_WRITE(hw, addr_base, reg);

	return 0;
}

 /**
 * @brief Release or decrement references for a profile associated with a filter.
 *
 * Decrements mask info and profile reference counters, clears hardware
 * registers as needed and frees profile memory when unused.
 *
 * @param hw Hardware context
 * @param handle FDIR handle
 * @param filter Filter whose profile should be removed
 * @return 0 on success
 */
int mce_fdir_remove_profile(struct mce_hw *hw, struct mce_fdir_handle *handle,
			    struct mce_fdir_filter *filter)
{
	struct mce_hw_profile *profile = NULL;
	u64 profile_id = filter->profile_id;

	profile = handle->profiles[profile_id];
	if (profile == NULL)
		assert(0);
	if (profile->mask_info) {
		profile->mask_info->ref_cnt--;
		if (profile->mask_info->ref_cnt == 0) {
			mce_profile_field_bitmask_update(hw, profile_id, 0);
			rte_free(profile->mask_info);
			profile->mask_info = NULL;
		}
	}
	profile->ref_cnt--;
	if (profile->ref_cnt == 0) {
		mce_fdir_profile_update(hw, profile, false);
		rte_free(profile);
		handle->profiles[profile_id] = NULL;
	}
	return 0;
}