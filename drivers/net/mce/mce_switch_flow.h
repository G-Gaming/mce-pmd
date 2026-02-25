#ifndef _MCE_SWITCH_FLOW_H_
#define _MCE_SWITCH_FLOW_H_

#include "mce_flow.h"
#include "mce.h"

struct mce_bitmap_entry;
/* switch vport lkup pattern  */
struct mce_switch_pattern {
	struct {
		uint8_t dst_mac[RTE_ETHER_ADDR_LEN];
		uint16_t vlan_id;
		uint32_t tunnel_tag;

		uint16_t ether_type;
		uint32_t dst_addr;
		uint32_t src_addr;
		uint8_t protocol;
		uint16_t l4_sport;
		uint16_t l4_dport;
		uint32_t vni;
		uint32_t tni;
		uint32_t teid;

		bool is_ipv6;
		uint16_t s_vport;
	} formatted;

	uint16_t vport_id;
};

struct mce_switch_rule {
	enum mce_rule_engine_module e_module;
	void *engine_rule;
	uint16_t program_id;
};

enum mce_switch_of_type {
	MCE_SW_OF_MAC = 1,
	MCE_SW_OF_VLAN,
	MCE_SW_OF_MACVLAN,
	MCE_SW_OF_VXLAN,
	MCE_SW_OF_VXLAN_VLAN,
	MCE_SW_OF_NVGRE,
	MCE_SW_OF_NVGRE_VLAN,
	MCE_SW_OF_GENEVE,
	MCE_SW_OF_GENEVE_VLAN,
	MCE_SW_OF_GTPU,
	MCE_SW_OF_GTPU_VLAN,
	MCE_SW_OF_GTPC,
	MCE_SW_OF_GTPC_VLAN,
	MCE_SW_OF_ESWITCH,
};

enum mce_switch_action {
	MCE_SW_TO_VPORT,
	MCE_SW_TO_VPORTS,
};

struct mce_switch_filter {
	struct mce_switch_pattern lkup_pattern;
	uint64_t switch_key;
	enum mce_switch_of_type rule_type;
	enum mce_switch_action action;
	uint16_t redir_port;
	bool drop_en;
	uint16_t vport_id;
	struct mce_lkup_meta *meta;
	uint16_t meta_num;
	uint64_t options;

	uint16_t action_loc;
	uint16_t rule_loc;

	bool loc_user_def;
	uint16_t user_loc;

	uint64_t in_packets;
};

enum mce_group_type {
	MCE_LKUP_UNTAG,
	MCE_LKUP_VLAN_TAG,
	MCE_LKUP_TUNNEL_VXLAN,
	MCE_LKUP_TUNNEL_GRE,
	MCE_LKUP_TUNNEL_GENEVE,
	MCE_LKUP_TUNNEL_GTP_U,
	MCE_LKUP_TUNNEL_GTP_C,
	MCE_LKUP_ESWITCH,
};

enum mce_broadcast_pattern {
	MCE_LPBK_BC_MAC, /* untag broadcast packet */
	MCE_LPBK_BC_VLAN, /* vlan broadcast packet */
	MCE_LPBK_BC_MACVLAN, /* broadcast vlan domain */
	MCE_LPBK_BC_VXLAN, /* broadcast vxlan domain */
	MCE_LPBK_BC_GENEVE, /* broadcast geneve domain */
	MCE_LPBK_BC_GTP_U, /* broadcast gtp-u domain */
	MCE_LPBK_BC_GTP_C, /* broadcast gtp-c domain */
	MCE_LPBK_BC_ESWITCH, /* broadcast eswitch domain */
};
struct mce_switch_mirror_vport {
	struct mce_bitmap_entry
		vport_map; /* switch redirect/mirror member vport */
	uint16_t action_loc;
	uint16_t rule_loc;
	bool redir;
	uint16_t reference_count;
};

struct mce_switch_params {
	struct mce_switch_pattern lkup_pattern;
	uint16_t redir_port;
	bool drop_en;
	uint64_t options;
};
struct mce_broadcast_domain_node {
	TAILQ_ENTRY(mce_broadcast_domain_node) entry;
	/* union mce_switch_pattern lkup_pattern; */
	uint64_t switch_key; /* broadcast domain key */
	uint64_t options;
	enum mce_broadcast_pattern type;
	struct mce_bitmap_entry vport_map; /* domain member vport list */
	uint16_t member_cnt;
	uint16_t action_loc;
	uint16_t rule_loc;

	uint16_t reference_count;
};

struct mce_switch_node {
	TAILQ_ENTRY(mce_switch_node) entry;
	struct mce_switch_mirror_vport *vport_list;
	enum mce_switch_of_type rule_type;
	struct mce_switch_params params;
	enum mce_switch_action action;
	uint16_t reference_count;

	uint16_t rule_loc; /* rule match hardware resource loc of database */
	uint16_t action_loc; /* rule match action hardware resource loc */
	struct mce_broadcast_domain_node *domain;

	struct mce_switch_filter filter;
};

TAILQ_HEAD(mce_switch_node_list, mce_switch_node);

struct mce_sw_rule_aggregate {
	TAILQ_ENTRY(mce_sw_rule_aggregate) entry;
	enum mce_switch_of_type type;
	uint32_t pattern_cnt;
	uint64_t options;
	uint64_t key;
	uint16_t member_num;

	struct mce_broadcast_domain_node *domain_entry;
	struct mce_switch_node_list node_list;
};

struct mce_mirror_node {
	struct mce_switch_node_list node_list;
	uint16_t member_num;
};

TAILQ_HEAD(mce_broadcast_domain_list, mce_broadcast_domain_node);
TAILQ_HEAD(mce_sw_rule_aggregate_list, mce_sw_rule_aggregate);
TAILQ_HEAD(mce_mirror_node_list, mce_mirror_node);
enum mce_bitmap_entry_type {
	MCE_ACTION_LOC_BITMAP,
	MCE_LEGENCY_BITMAP,
	MCE_ESWITCH_BTMAP
};

struct mce_switch_handle {
	bool en_switchdev; /* eswitch mode enable */
	struct mce_switch_filter **filter_hash_map; /* switch match rule loc */
	struct rte_hash *filter_hash_handle; /* cuckoo hash handler */

	struct mce_broadcast_domain_list bc_domain_list; /* sync to hw list */
	struct mce_sw_rule_aggregate_list sw_aggregate;
	struct mce_mirror_node_list mirror_node;
	struct mce_lkup_meta meta_db[2][MCE_META_TYPE_MAX];
	uint16_t max_action_entry;
	uint16_t max_legend_rule;
	uint16_t max_eswitch_rule;

	struct mce_bitmap_entry bitmap_entry[3];
};

#endif /* _MCE_SWITCH_FLOW_H_ */
