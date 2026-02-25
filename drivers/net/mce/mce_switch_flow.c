#include <string.h>
#include <assert.h>

#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_tailq.h>
#include <rte_version.h>

#include "base/mce_eth_regs.h"
#include "base/mce_switch.h"

#include "mce_switch_flow.h"
#include "mce_pattern.h"
#include "mce_compat.h"
#include "mce_parse.h"
#include "mce_logs.h"
#include "mce_flow.h"
#include "mce.h"

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
enum rte_flow_item_type switch_cp_eth[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_sctp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_NVGRE,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_ipv4_gtpc[] = {
	RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP, RTE_FLOW_ITEM_TYPE_GTPC,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_sctp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	  RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4,  RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN, RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_nvgre[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_NVGRE,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_geneve[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_GENEVE,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_gtpu[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_GTPU,
	RTE_FLOW_ITEM_TYPE_END,
};

enum rte_flow_item_type switch_cp_eth_vlan_ipv4_gtpc[] = {
	RTE_FLOW_ITEM_TYPE_ETH,	 RTE_FLOW_ITEM_TYPE_VLAN,
	RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_GTPC,
	RTE_FLOW_ITEM_TYPE_END,
};

#define MCE_OPT_MACVLAN (MCE_OPT_DMAC | MCE_OPT_VLAN_VID | MCE_OPT_S_VPORT_ID)
#define MCE_OPT_ETH_IPV4 \
	(MCE_OPT_IPV4_SIP | MCE_OPT_IPV4_DIP | MCE_OPT_S_VPORT_ID)
#define MCE_SW_IPV4 \
	(MCE_OPT_ETH_IPV4 | MCE_OPT_SMAC | MCE_OPT_DMAC | MCE_OPT_S_VPORT_ID)
#define MCE_SW_OUT_IPV4                                               \
	(MCE_OPT_OUT_IPV4_SIP | MCE_OPT_OUT_IPV4_DIP | MCE_OPT_DMAC | \
	 MCE_OPT_S_VPORT_ID)
#define MCE_SW_IPV4_TCP		(MCE_SW_IPV4 | MCE_OPT_TCP_SPORT | MCE_OPT_TCP_DPORT)
#define MCE_SW_IPV4_UDP		(MCE_SW_IPV4 | MCE_OPT_UDP_SPORT | MCE_OPT_UDP_DPORT)
#define MCE_SW_IPV4_SCTP	(MCE_SW_IPV4 | MCE_OPT_SCTP_SPORT | MCE_OPT_SCTP_DPORT)
#define MCE_SW_ETH_IPV4		(MCE_SW_IPV4 | MCE_OPT_VLAN_VID)
#define MCE_SW_ETH_IPV4_TCP	(MCE_SW_IPV4_TCP | MCE_OPT_VLAN_VID)
#define MCE_SW_ETH_IPV4_UDP	(MCE_SW_IPV4_UDP | MCE_OPT_VLAN_VID)
#define MCE_SW_ETH_IPV4_SCTP	(MCE_SW_IPV4_SCTP | MCE_OPT_VLAN_VID)

#define MCE_SW_IPV4_VXLAN	(MCE_SW_OUT_IPV4 | MCE_OPT_VXLAN_VNI)
#define MCE_SW_IPV4_NVGRE	(MCE_SW_OUT_IPV4 | MCE_OPT_NVGRE_TNI)
#define MCE_SW_IPV4_GENEVE	(MCE_SW_OUT_IPV4 | MCE_OPT_VXLAN_VNI)
#define MCE_SW_IPV4_GTPU	(MCE_SW_OUT_IPV4 | MCE_OPT_GTP_U_TEID)
#define MCE_SW_IPV4_GTPC	(MCE_SW_OUT_IPV4 | MCE_OPT_GTP_C_TEID)

#define MCE_SW_VLAN_IPV4_VXLAN	(MCE_SW_IPV4_VXLAN | MCE_OPT_VLAN_VID)
#define MCE_SW_VLAN_IPV4_NVGRE	(MCE_SW_IPV4_NVGRE | MCE_OPT_VLAN_VID)
#define MCE_SW_VLAN_IPV4_GENEVE (MCE_SW_IPV4_GENEVE | MCE_OPT_VLAN_VID)
#define MCE_SW_VLAN_IPV4_GTPU	(MCE_SW_IPV4_GTPU | MCE_OPT_VLAN_VID)
#define MCE_SW_VLAN_IPV4_GTPC	(MCE_SW_IPV4_GTPC | MCE_OPT_VLAN_VID)

#define MCE_SW_ETH_NTUPLE                                                 \
	(MCE_OPT_DMAC | MCE_OPT_SMAC | MCE_OPT_IPV4_SIP |                 \
	 MCE_OPT_OUT_IPV4_SIP | MCE_OPT_IPV4_DIP | MCE_OPT_OUT_IPV4_DIP | \
	 MCE_OPT_TCP_SPORT | MCE_OPT_TCP_DPORT | MCE_OPT_UDP_SPORT |      \
	 MCE_OPT_UDP_DPORT | MCE_OPT_SCTP_SPORT | MCE_OPT_SCTP_DPORT)
static void *
mce_meta_to_switch_legend(void *h_ptr, uint16_t meta_num,
			  struct mce_field_bitmask_info *mask_info __rte_unused,
			  struct mce_flow_action *actions, uint64_t options,
			  bool is_ipv6 __rte_unused, bool is_tunnel)
{
	struct mce_switch_handle *handle = (struct mce_switch_handle *)h_ptr;
	struct mce_switch_filter *filter = NULL;
	struct mce_switch_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	int i = 0;

	filter = rte_zmalloc(NULL, sizeof(struct mce_switch_filter), 0);
	if (filter == NULL)
		return NULL;
	lkup_pattern = &filter->lkup_pattern;
	meta = &handle->meta_db[is_tunnel][0];

	if (meta->type != MCE_ETH_META || meta_num != 1)
		return NULL;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		switch (meta->type) {
		case MCE_ETH_META:
			memcpy(lkup_pattern->formatted.dst_mac,
			       meta->hdr.eth_meta.dst_addr, RTE_ETHER_ADDR_LEN);
			lkup_pattern->formatted.ether_type =
				meta->hdr.eth_meta.ethtype_id;
			break;
		case MCE_VLAN_META:
			lkup_pattern->formatted.vlan_id =
				meta->hdr.vlan_meta.vlan_id;
			break;
		default:
			break;
		}
	}
	filter->switch_key = MCE_SWITCH_RULE_VEB;
	switch (options) {
	case MCE_OPT_DMAC:
	case MCE_OPT_DMAC | MCE_OPT_SMAC:
	case MCE_OPT_DMAC | MCE_OPT_S_VPORT_ID:
		filter->rule_type = MCE_SW_OF_MAC;
		break;
	case MCE_OPT_DMAC | MCE_OPT_VLAN_VID:
		filter->rule_type = MCE_SW_OF_MACVLAN;
		filter->switch_key |= lkup_pattern->formatted.vlan_id;
		break;
	case MCE_OPT_VLAN_VID:
		filter->rule_type = MCE_SW_OF_VLAN;
		filter->switch_key |= lkup_pattern->formatted.vlan_id;
		break;
	}
	if (actions->rule_action == MCE_FILTER_DROP) {
		filter->drop_en = 1;
	} else {
		filter->redir_port = actions->redir_port;
		filter->vport_id = actions->redir_port;
	}
	filter->options = options;
	filter->meta_num = meta_num;

	return filter;
}

static void *mce_meta_to_switch_eswitch(
	void *h_ptr, uint16_t meta_num,
	struct mce_field_bitmask_info *mask_info __rte_unused,
	struct mce_flow_action *actions, uint64_t options,
	bool is_ipv6 __rte_unused, bool is_tunnel)
{
	struct mce_switch_handle *handle = (struct mce_switch_handle *)h_ptr;
	struct mce_switch_filter *filter = NULL;
	struct mce_switch_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	uint64_t vid = 0;
	int i = 0;

	filter = rte_zmalloc(NULL, sizeof(struct mce_switch_filter), 0);
	if (filter == NULL)
		return NULL;
	lkup_pattern = &filter->lkup_pattern;
	meta = &handle->meta_db[is_tunnel][0];
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		switch (meta->type) {
		case MCE_ETH_META:
			memcpy(lkup_pattern->formatted.dst_mac,
			       meta->hdr.eth_meta.dst_addr, RTE_ETHER_ADDR_LEN);
			break;
		case MCE_VLAN_META:
			lkup_pattern->formatted.vlan_id =
				meta->hdr.vlan_meta.vlan_id;
			break;
		case MCE_IPV4_META:
			lkup_pattern->formatted.src_addr =
				meta->hdr.ipv4_meta.src_addr;
			lkup_pattern->formatted.dst_addr =
				meta->hdr.ipv4_meta.dst_addr;
			lkup_pattern->formatted.protocol =
				meta->hdr.ipv4_meta.protocol;
			break;
		case MCE_UDP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.udp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.udp_meta.src_port;
			lkup_pattern->formatted.protocol = IPPROTO_UDP;
			break;
		case MCE_TCP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.tcp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.tcp_meta.src_port;
			lkup_pattern->formatted.protocol = IPPROTO_TCP;
			break;
		case MCE_SCTP_META:
			lkup_pattern->formatted.l4_dport =
				meta->hdr.sctp_meta.dst_port;
			lkup_pattern->formatted.l4_sport =
				meta->hdr.sctp_meta.src_port;
			lkup_pattern->formatted.protocol = IPPROTO_SCTP;
			break;
		case MCE_VXLAN_META:
			lkup_pattern->formatted.vni = meta->hdr.vxlan_meta.vni;
			break;
		case MCE_GENEVE_META:
			lkup_pattern->formatted.vni = meta->hdr.geneve_meta.vni;
			break;
		case MCE_NVGRE_META:
			lkup_pattern->formatted.tni = meta->hdr.nvgre_meta.key;
			break;
		case MCE_GTPU_META:
		case MCE_GTPC_META:
			lkup_pattern->formatted.teid = meta->hdr.gtp_meta.teid;
			break;
		case MCE_VPORT_ID:
			lkup_pattern->formatted.s_vport =
				meta->hdr.vport_meta.vport_id;
			break;
		default:
			PMD_DRV_LOG(ERR, "switch rule is not exist options");
			return NULL;
		}
	}
	if (options & MCE_SW_ETH_NTUPLE) {
		filter->rule_type = MCE_SW_OF_ESWITCH;
	} else {
		switch (options & MCE_TUNNEL_VLAN_OPT_MASK) {
		case MCE_OPT_VXLAN_VNI:
			filter->rule_type = MCE_SW_OF_VXLAN;
			break;
		case MCE_OPT_NVGRE_TNI:
			filter->rule_type = MCE_SW_OF_NVGRE;
			break;
		case MCE_OPT_GENEVE_VNI:
			filter->rule_type = MCE_SW_OF_GENEVE;
			break;
		case MCE_OPT_GTP_U_TEID:
			filter->rule_type = MCE_SW_OF_GTPU;
			break;
		case MCE_OPT_GTP_C_TEID:
			filter->rule_type = MCE_SW_OF_GTPC;
			break;
		case MCE_OPT_VLAN_VID | MCE_OPT_VXLAN_VNI:
			filter->rule_type = MCE_SW_OF_VXLAN_VLAN;
			break;
		case MCE_OPT_VLAN_VID | MCE_OPT_GENEVE_VNI:
			filter->rule_type = MCE_SW_OF_GENEVE_VLAN;
			break;
		case MCE_OPT_VLAN_VID | MCE_OPT_NVGRE_TNI:
			filter->rule_type = MCE_SW_OF_NVGRE_VLAN;
			break;
		case MCE_OPT_VLAN_VID | MCE_OPT_GTP_U_TEID:
			filter->rule_type = MCE_SW_OF_GTPU_VLAN;
			break;
		case MCE_OPT_VLAN_VID | MCE_OPT_GTP_C_TEID:
			filter->rule_type = MCE_SW_OF_GTPC_VLAN;
			break;
		}
	}
	printf("filter_type %d\n", filter->rule_type);
	if (filter->rule_type == 0) {
		printf("options 0x%.2lx\n", options);
		assert(0);
	}
	memcpy(&filter->switch_key, &lkup_pattern->formatted.dst_mac,
	       RTE_ETHER_ADDR_LEN);
	vid = lkup_pattern->formatted.vlan_id;
	filter->switch_key |= (vid << (RTE_ETHER_ADDR_LEN * 8));
	if (actions->rule_action == MCE_FILTER_DROP) {
		filter->drop_en = 1;
	} else {
		filter->redir_port = actions->redir_port;
		filter->vport_id = actions->redir_port;
		filter->lkup_pattern.vport_id = filter->vport_id;
	}
	filter->options = options;
	filter->meta_num = meta_num;

	return filter;
}

static struct mce_flow_ptype_match mce_switch_ptype_support[] = {
	{ switch_cp_eth, 0, MCE_OPT_DMAC | MCE_OPT_SMAC | MCE_OPT_S_VPORT_ID,
	  MCE_SWITCH_VPORT, mce_meta_to_switch_legend },
	{ switch_cp_eth_vlan, 0, MCE_OPT_MACVLAN, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_legend },

	{ switch_cp_eth_ipv4, 0, MCE_SW_IPV4, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_ipv4_tcp, 0, MCE_SW_IPV4_TCP, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_ipv4_udp, 0, MCE_SW_IPV4_UDP, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_ipv4_sctp, 0, MCE_SW_ETH_IPV4_UDP, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_vlan_ipv4_tcp, 0, MCE_SW_ETH_IPV4_UDP, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_vlan_ipv4_udp, 0, MCE_SW_ETH_IPV4_TCP, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_vlan_ipv4_sctp, 0, MCE_SW_ETH_IPV4_SCTP,
	  MCE_SWITCH_VPORT, mce_meta_to_switch_eswitch },

	{ switch_cp_eth_ipv4_vxlan, 0, MCE_SW_IPV4_VXLAN, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_ipv4_nvgre, 0, MCE_SW_IPV4_NVGRE, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_ipv4_geneve, 0, MCE_SW_IPV4_GENEVE, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_ipv4_gtpu, 0, MCE_SW_IPV4_GTPU, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },
	{ switch_cp_eth_ipv4_gtpc, 0, MCE_SW_IPV4_GTPC, MCE_SWITCH_VPORT,
	  mce_meta_to_switch_eswitch },

	{ switch_cp_eth_vlan_ipv4_vxlan, 0, MCE_SW_VLAN_IPV4_VXLAN,
	  MCE_SWITCH_VPORT, mce_meta_to_switch_eswitch },
	{ switch_cp_eth_vlan_ipv4_nvgre, 0, MCE_SW_VLAN_IPV4_NVGRE,
	  MCE_SWITCH_VPORT, mce_meta_to_switch_eswitch },
	{ switch_cp_eth_vlan_ipv4_geneve, 0, MCE_SW_VLAN_IPV4_GENEVE,
	  MCE_SWITCH_VPORT, mce_meta_to_switch_eswitch },
	{ switch_cp_eth_vlan_ipv4_gtpu, 0, MCE_SW_VLAN_IPV4_GTPU,
	  MCE_SWITCH_VPORT, mce_meta_to_switch_eswitch },
	{ switch_cp_eth_vlan_ipv4_gtpc, 0, MCE_SW_VLAN_IPV4_GTPC,
	  MCE_SWITCH_VPORT, mce_meta_to_switch_eswitch },
};

static int mce_switch_flow_parse(struct mce_vport *vport, void **o_parm,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_item pattern[],
				 const struct rte_flow_action actions[],
				 struct rte_flow_error *error)
{
	struct mce_switch_rule **rule = (struct mce_switch_rule **)o_parm;
	struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
	const struct rte_flow_action_ethdev *act_ethdev;
	struct mce_flow_ptype_match *support = NULL;
	const struct rte_flow_action *act = actions;
	const struct rte_flow_item *item = pattern;
	struct mce_switch_handle *handle = NULL;
	struct mce_flow_action action_conf;
	struct mce_lkup_meta *meta = NULL;
	const struct rte_eth_dev *repr;
	const struct rte_eth_dev *parent;
	const struct rte_eth_dev *left_port;
	struct mce_switch_rule *tmp;
	bool is_tunnel = false;
	uint16_t meta_num = 0;
	uint64_t inset = 0;
	bool is_ipv6 = false;
	int ret = 0;
	int i = 0;

	/* 1.define filter enging can support pattern compose */
	/* 2.check the pattern input options flow engine can deal */
	parent = pf->pf_vport->dev;
	if (pattern == NULL)
		return -EINVAL;
	/* Get the non-void item number of pattern */
	while (item->type == RTE_FLOW_ITEM_TYPE_VOID)
		item++;
	while (item->type == RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT ||
	       item->type == RTE_FLOW_ITEM_TYPE_PORT_REPRESENTOR)
		item++;
	support = mce_check_pattern_support(item, mce_switch_ptype_support,
					    RTE_DIM(mce_switch_ptype_support));
	if (support == NULL)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "switch pattern compose not support");
	handle = (struct mce_switch_handle *)mce_get_engine_handle(
		vport, MCE_FLOW_SWITCH);
	memset(&action_conf, 0, sizeof(action_conf));
	item = pattern;
	for (; act->type != RTE_FLOW_ACTION_TYPE_END; act++) {
		switch (act->type) {
		case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
			act_ethdev = act->conf;
			if (!rte_eth_dev_is_valid_port(act_ethdev->port_id))
				return rte_flow_error_set(
					error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
					item, "invalid act port-id");
			if (act_ethdev->port_id == vport->data->port_id) {
				action_conf.redir_port = 128;
			} else {
				repr = &rte_eth_devices[act_ethdev->port_id];
				if (!repr->data) {
					printf("repr port is null\n");
					return -EINVAL;
				}
				if (repr->data->backer_port_id !=
				    parent->data->port_id) {
					printf("repr port-id is invalid\n");
					return -EINVAL;
				}
				action_conf.redirect_en = 1;
				for (i = 0; i < pf->nr_repr_ports; i++) {
					if (pf->vf_reprs[i] == NULL)
						continue;
					if (pf->vf_reprs[i]->port_id ==
					    act_ethdev->port_id)
						break;
				}

				if (i == pf->nr_repr_ports) {
					printf("vf repr port-id is invalid\n");
					return -EINVAL;
				}
				struct mce_vf_representor *vf_repr =
					repr->data->dev_private;
				action_conf.redir_port = vf_repr->vf_id;
			}
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			action_conf.redirect_en = 1;
			action_conf.rule_action = MCE_FILTER_DROP;
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			break;
		default:
			return rte_flow_error_set(
				error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
				"Switch Flow Act type not supported");
		}
	}
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		meta = &handle->meta_db[0][meta_num];
		memset(meta, 0, sizeof(*meta));
		meta->type = MCE_META_TYPE_MAX;
		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = mce_parse_eth(item, meta, &inset, is_tunnel,
					    error);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ret = mce_parse_ip4(item, meta, &inset, is_tunnel,
					    error);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ret = mce_parse_ip6(item, meta, &inset, is_tunnel,
					    error);
			is_ipv6 = true;
			if (inset & (MCE_OPT_IPV6_SIP | MCE_OPT_IPV6_DIP))
				return rte_flow_error_set(
					error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"switch item type not support ipv6 "
					"options");
			break;
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
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			ret = mce_parse_nvgre(item, meta, &inset, is_tunnel,
					      error);
			break;
		case RTE_FLOW_ITEM_TYPE_GTPC:
			ret = mce_parse_gtpc(item, meta, &inset, is_tunnel,
					     error);
			break;
		case RTE_FLOW_ITEM_TYPE_GTPU:
			ret = mce_parse_gtpu(item, meta, &inset, is_tunnel,
					     error);
			break;
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			ret = mce_parse_geneve(item, meta, &inset, is_tunnel,
					       error);
			break;
		case RTE_FLOW_ITEM_TYPE_PORT_REPRESENTOR:
			/* real port not repr port */
			break;
		case RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT: {
			const struct rte_flow_item_ethdev *port_spec =
				item->spec;
			struct mce_vf_representor *vfr = NULL;

			/* rep port id used to replace sport */
			if (!rte_eth_dev_is_valid_port(port_spec->port_id))
				return rte_flow_error_set(
					error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
					item, "invalid act port-id");
			left_port = &rte_eth_devices[port_spec->port_id];
			if (!left_port->data) {
				printf("repr port is null\n");
				return -EINVAL;
			}
			if (!attr->transfer) {
				return rte_flow_error_set(
					error, EINVAL, RTE_FLOW_ERROR_TYPE_ATTR,
					attr,
					"RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT  "
					"not match with transfer");
			}
			vfr = left_port->data->dev_private;
			meta->type = MCE_VPORT_ID;
			meta->hdr.vport_meta.vport_id = vfr->vport_id;
			inset |= MCE_OPT_S_VPORT_ID;
		} break;
		default:
			return rte_flow_error_set(error, EINVAL,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  item,
						  "item type not support");
		}
		if (inset && (support->insets ^ (support->insets | inset))) {
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"switch this compose not support this pattern "
				"match");
		}
		if (ret < 0)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"item options can't be parse");
		meta_num += (ret > 0 ? 1 : 0);
	}
	if (mce_check_valid_inset(support, inset) < 0)
		return rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
			"switch item options compose not support");
	if (mce_check_action_valid(vport, &action_conf, error))
		return -EINVAL;
	/* if don't need upload the correct match info
	 * just upload the pattern is parse ready
	 */
	if (rule == NULL)
		goto end;
	tmp = rte_zmalloc(NULL, sizeof(struct mce_switch_rule), 0);
	if (tmp == NULL)
		return -ENOMEM;
	tmp->engine_rule = support->meta_to_rule(handle, meta_num, NULL,
						 &action_conf, inset, is_ipv6,
						 is_tunnel);
	if (tmp->engine_rule == NULL)
		return -EINVAL;
	memset(handle->meta_db[is_tunnel], 0,
	       sizeof(struct mce_lkup_meta) * meta_num);
	tmp->e_module = support->e_module;
	*rule = tmp;
end:
	return 0;
}

/**
 * @brief Create and install a switch filter rule in hardware.
 *
 * Converts the parsed `flow->rule` into a hardware filter entry and
 * installs the rule in the switch engine. Returns an error if an
 * identical rule already exists.
 *
 * @param vport
 *   VPort owning the flow.
 * @param flow
 *   Flow containing the pre-parsed switch rule.
 * @param error
 *   Error reporting structure.
 * @return
 *   0 on success, negative errno on failure (e.g., EEXIST if rule exists).
 */
static int mce_switch_flow_create(struct mce_vport *vport,
				  struct rte_flow *flow,
				  struct rte_flow_error *error)
{
	struct mce_switch_rule *rule = (struct mce_switch_rule *)flow->rule;
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_switch_filter *filter = NULL;
	struct mce_switch_filter *find = NULL;
	struct mce_switch_handle *handle = NULL;
	int ret = 0;

	handle = (struct mce_switch_handle *)flow_engine->handle;
	filter = (struct mce_switch_filter *)rule->engine_rule;
	find = mce_switch_entry_lookup(handle, &filter->lkup_pattern);
	if (find)
		return rte_flow_error_set(error, EEXIST,
					  RTE_FLOW_ERROR_TYPE_ITEM, find,
					  "add switch rule is exist");
	printf("filter->rule_type %d\n", filter->rule_type);
	if (filter->rule_type == 0)
		assert(0);
	switch (filter->rule_type) {
	case MCE_SW_OF_MAC:
	case MCE_SW_OF_VLAN:
	case MCE_SW_OF_MACVLAN:
		mce_switch_macvlan_program(handle, vport->hw, filter, 1);
		break;
	case MCE_SW_OF_VXLAN:
	case MCE_SW_OF_GENEVE:
	case MCE_SW_OF_GTPU:
	case MCE_SW_OF_NVGRE:
	case MCE_SW_OF_GENEVE_VLAN:
	case MCE_SW_OF_VXLAN_VLAN:
	case MCE_SW_OF_NVGRE_VLAN:
	case MCE_SW_OF_GTPU_VLAN:
	case MCE_SW_OF_GTPC_VLAN:
		mce_switch_tunvlan_program(handle, vport->hw, filter, 1);
		break;
	case MCE_SW_OF_ESWITCH:
		mce_switch_eswitch_program(handle, vport->hw, filter, 1);
		break;
	default:
		break;
	}
	ret = mce_switch_insert_hash_map(handle, filter);
	if (ret < 0) {
		return rte_flow_error_set(error, ENOMEM,
				RTE_FLOW_ERROR_TYPE_ITEM, find,
				"add switch hash map is outof range");
	}

	return 0;
}

static int mce_switch_flow_delate(struct mce_vport *vport,
				  struct rte_flow *flow __rte_unused,
				  struct rte_flow_error *error __rte_unused)
{
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_switch_rule *rule = (struct mce_switch_rule *)flow->rule;
	struct mce_switch_handle *handle = NULL;
	struct mce_switch_filter *filter = NULL;
	struct mce_switch_filter *find = NULL;
	int ret = 0;

	printf("delate switch rule\n");
	handle = (struct mce_switch_handle *)flow_engine->handle;
	filter = (struct mce_switch_filter *)rule->engine_rule;
	find = mce_switch_entry_lookup(handle, &filter->lkup_pattern);
	if (find == NULL)
		return rte_flow_error_set(error, ENOENT,
					  RTE_FLOW_ERROR_TYPE_ITEM, handle,
					  "switch rule entry isn't exist");
	switch (filter->rule_type) {
	case MCE_SW_OF_MAC:
	case MCE_SW_OF_VLAN:
	case MCE_SW_OF_MACVLAN:
		ret = mce_switch_macvlan_program(handle, vport->hw, filter, 0);
		break;
	case MCE_SW_OF_VXLAN:
	case MCE_SW_OF_GENEVE:
	case MCE_SW_OF_GTPU:
	case MCE_SW_OF_NVGRE:
	case MCE_SW_OF_GENEVE_VLAN:
	case MCE_SW_OF_VXLAN_VLAN:
	case MCE_SW_OF_NVGRE_VLAN:
	case MCE_SW_OF_GTPU_VLAN:
	case MCE_SW_OF_GTPC_VLAN:
		ret = mce_switch_tunvlan_program(handle, vport->hw, filter, 0);
		break;
	case MCE_SW_OF_ESWITCH:
		ret = mce_switch_eswitch_program(handle, vport->hw, filter, 0);
		break;
	default:
		break;
	}
	if (ret < 0)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, handle,
					  "switch rule destory failed");
	ret = mce_switch_remove_hash_map(handle, filter);
	if (ret < 0)
		return ret;

	return 0;
}
#else
static int mce_switch_flow_create(struct mce_vport *vport __rte_unused,
				  struct rte_flow *flow __rte_unused,
				  struct rte_flow_error *error __rte_unused)
{
	return -ENOTSUP;
}
static int mce_switch_flow_delate(struct mce_vport *vport __rte_unused,
				  struct rte_flow *flow __rte_unused,
				  struct rte_flow_error *error __rte_unused)
{
	return -ENOTSUP;
}
static int mce_switch_flow_parse(struct mce_vport *vport, void **o_parm,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_item pattern[],
				 const struct rte_flow_action actions[],
				 struct rte_flow_error *error)
{
	RTE_SET_USED(vport);
	RTE_SET_USED(o_parm);
	RTE_SET_USED(attr);
	RTE_SET_USED(pattern);
	RTE_SET_USED(actions);
	RTE_SET_USED(error);

	return -ENOTSUP;
}
#endif

static int mce_switch_flow_engine_init(struct mce_vport *vport, void **handle)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_switch_handle *switch_handle = NULL;
	char switch_hash_name[RTE_HASH_NAMESIZE];
	uint32_t reg = 0;
	int ret = 0;
	struct rte_hash_parameters switch_hash_params = {
		.name = switch_hash_name,
		.entries = 512,
		.key_len = sizeof(struct mce_switch_pattern),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};
	printf("switch_init \n");
	switch_handle = rte_zmalloc(NULL, sizeof(struct mce_switch_handle), 0);
	if (switch_handle == NULL)
		return -ENOMEM;
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
	snprintf(switch_hash_name, RTE_HASH_NAMESIZE, "switch_%s",
		 vport->dev->data->name);
#else
	snprintf(switch_hash_name, RTE_HASH_NAMESIZE, "switch_%s",
		 vport->dev->device->name);
#endif
	switch_handle->filter_hash_handle =
		rte_hash_create(&switch_hash_params);
	if (!switch_handle->filter_hash_handle) {
		PMD_INIT_LOG(ERR, "Failed to create fdir hash table!");
		return -EINVAL;
	}
	switch_handle->filter_hash_map = rte_zmalloc(
		"mce",
		sizeof(struct mce_switch_filter) * switch_hash_params.entries,
		0);
	if (switch_handle->filter_hash_map == NULL) {
		PMD_INIT_LOG(ERR,
			     "Failed to allocate memory for fdir hash map!");
		rte_hash_free(switch_handle->filter_hash_handle);
		return -ENOMEM;
	}
	reg |= MCE_SW_UP_TUPLE4_MASK_EN | MCE_SW_DN_TUPLE4_MASK_EN;
	reg |= MCE_SW_TUPLE10_EN | MCE_SW_TUPLE10_MASK_EN;
	/* enable 10 tuple filter */
	MCE_E_REG_WRITE(hw, MCE_SW_ENGINE_CTRL, reg);

	switch_handle->max_action_entry = 512;
	switch_handle->max_eswitch_rule = MCE_MAX_ESWITCH_RULE;
	switch_handle->max_legend_rule = MCE_MAX_LEGEND_RULE;
	/* setup bitmap table */
	ret = mce_switch_bitmap_init(switch_handle);
	if (ret)
		return ret;
	*handle = switch_handle;
	hw->switch_handle = switch_handle;
	TAILQ_INIT(&switch_handle->bc_domain_list);
	TAILQ_INIT(&switch_handle->sw_aggregate);

	printf("switch_pattern size %ld\n", sizeof(struct mce_switch_pattern));

	return 0;
}

static int mce_switch_flow_engine_uinit(struct mce_vport *vport __rte_unused,
					void *handle)
{
	struct mce_switch_handle *switch_handle = handle;
	struct mce_bitmap_entry *entry = NULL;
	uint32_t i = 0;

	if (switch_handle == NULL)
		return 0;
	if (switch_handle->filter_hash_handle) {
		if (rte_hash_count(switch_handle->filter_hash_handle)) {
			if (switch_handle->filter_hash_map == NULL)
				return -ENODEV;
			for (i = 0; i < 512; i++) {
				if (switch_handle->filter_hash_map[i] != NULL)
					rte_free(switch_handle
							 ->filter_hash_map[i]);
			}
		}
		rte_hash_free(switch_handle->filter_hash_handle);
	}
	if (switch_handle->filter_hash_map)
		rte_free(switch_handle->filter_hash_map);
	for (i = 0; i < 3; i++) {
		entry = &switch_handle->bitmap_entry[i];
		rte_free(entry->bitmap_mem);
	}
	rte_free(switch_handle);

	return 0;
}

static uint32_t mce_switch_query_rule(struct mce_hw *hw, uint32_t cmd)
{
	uint32_t ctrl = 0;

	ctrl = MCE_E_REG_READ(hw, 0x88038);
	ctrl &= ~GENMASK_U32(25, 16);
	ctrl |= cmd;
	MCE_E_REG_WRITE(hw, 0x88038, ctrl);

	return 0;
}

#if 0
static int
mce_debug_switch(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	int i = 0;

	mce_switch_debug_cmd(hw, 0 << 24);
	printf("switch eswitch[0] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));
	mce_switch_debug_cmd(hw, 1 << 24);
	printf("switch eswitch[1] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));
	mce_switch_debug_cmd(hw, 2 << 24);
	printf("switch eswitch[2] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));
	mce_switch_debug_cmd(hw, 3 << 24);
	printf("switch eswitch[2] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));

	for (i = 0; i < 16; i++) {
		mce_switch_debug_cmd(hw, i << 20);
		printf("switch legdy[%d] up match 0x%.2x\n", i,  MCE_E_REG_READ(hw, 0x93904));
	}
	for (i = 0; i < 16; i++) {
		mce_switch_debug_cmd(hw, i << 16);
		printf("switch legdy[%d] down match 0x%.2x\n", i, MCE_E_REG_READ(hw, 0x93908));
	}

	return 0;
}
#endif

/**
 * @brief Query packet counters for a switch flow.
 *
 * Retrieves the accumulated packet and byte counts for a switch rule
 * and optionally resets counters. Outputs results to a
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
static int mce_switch_flow_query(struct mce_vport *vport, struct rte_flow *flow,
				 void *out, struct rte_flow_error *error)

{
	struct rte_flow_query_count *flow_stats = out;
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_switch_rule *rule = flow->rule;
	struct mce_switch_handle *handle = NULL;
	struct mce_switch_filter *filter = NULL;
	struct mce_switch_filter *find = NULL;
	struct mce_hw *hw = vport->hw;

	handle = (struct mce_switch_handle *)flow_engine->handle;
	filter = (struct mce_switch_filter *)rule->engine_rule;
	find = mce_switch_entry_lookup(handle, &filter->lkup_pattern);
	if (find == NULL)
		return rte_flow_error_set(error, ENOENT,
					  RTE_FLOW_ERROR_TYPE_ITEM, handle,
					  "switch rule entry isn't exist");
	uint32_t blank = filter->rule_loc / 32;

	mce_switch_query_rule(hw, blank << 24);
	if (MCE_E_REG_READ(hw, 0x93900) & RTE_BIT32(filter->rule_loc)) {
		filter->in_packets++;
		printf("switch key %ld rule_loc %d, filter->in_packets %lu\n",
		       filter->switch_key, filter->rule_loc,
		       filter->in_packets);
		flow_stats->hits_set = 1;
		flow_stats->hits = 1;
		flow_stats->bytes_set = 0;
		flow_stats->bytes = 0;
	}

	return 0;
}

struct mce_flow_engine_module mce_switch_engine = {
	.parse = mce_switch_flow_parse,
	.create = mce_switch_flow_create,
	.destroy = mce_switch_flow_delate,
	.query = mce_switch_flow_query,
	.init = mce_switch_flow_engine_init,
	.uinit = mce_switch_flow_engine_uinit,
	.name = "mce_switch_flow",
	.type = MCE_FLOW_SWITCH,
};
