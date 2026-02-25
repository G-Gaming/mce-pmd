#ifndef _MCE_FLOW_H_
#define _MCE_FLOW_H_

#include <rte_version.h>
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_flow.h>
#include <rte_flow_driver.h>
#endif /* RTE_VERSION >= 16.11 */
#include <stdbool.h>
#include "mce_compat.h"
struct mce_vport;
typedef int (*flow_engine_init_t)(struct mce_vport *port, void **handle);
typedef int (*flow_engine_uinit_t)(struct mce_vport *port, void *handle);
typedef int (*flow_engine_parse_t)(struct mce_vport *port, void **rule,
				   const struct rte_flow_attr *attr,
				   const struct rte_flow_item pattern[],
				   const struct rte_flow_action actions[],
				   struct rte_flow_error *error);
typedef int (*flow_engine_create_t)(struct mce_vport *port,
				    struct rte_flow *flow,
				    struct rte_flow_error *error);
typedef int (*flow_engine_destroy_t)(struct mce_vport *port,
				     struct rte_flow *flow,
				     struct rte_flow_error *error);
typedef int (*flow_engine_query_t)(struct mce_vport *port,
				   struct rte_flow *flow, void *out,
				   struct rte_flow_error *error);
struct mce_field_bitmask_info;
struct mce_flow_action;
typedef void *(*mce_meta_to_rule_t)(void *h_ptr, uint16_t meta_num,
				    struct mce_field_bitmask_info *mask_info,
				    struct mce_flow_action *act,
				    uint64_t options, bool is_ipv6,
				    bool is_tunnel);
enum mce_flow_engine_ops {
	MCE_FLOW_PARSE = 1,
	MCE_FLOW_CREATE,
	MCE_FLOW_DESTORY,
};

enum mce_rule_engine_module {
	MCE_GENERIC_ETYPE,
	MCE_GERERIC_NTUPLE,
	MCE_GENERIC_SYNC,
	MCE_RSS_FD,
	MCE_FDIR_PERFECT,
	MCE_FDIR_SIGNATURE,
	MCE_SWITCH_VPORT
};

struct mce_flow_ptype_match {
	enum rte_flow_item_type *pattern_list;
	const uint16_t hw_type;
	const uint64_t insets;
	const uint16_t e_module;
	mce_meta_to_rule_t meta_to_rule;
};

enum mce_filter_action {
	MCE_FILTER_PASS,
	MCE_FILTER_DROP,
};

struct mce_flow_action {
	uint8_t redirect_en;
	uint8_t mark_en;
	uint8_t pop_vlan;
	uint8_t rss_cfg;
	uint8_t priority;
	uint8_t redir_port;
	uint8_t mirror_port;
	enum mce_filter_action rule_action;
	struct rte_flow_action_queue redir;
	struct rte_flow_action_rss rss;
	struct rte_flow_action_mark mark;
};

struct mce_ether_meta {
	uint8_t dst_addr[RTE_ETHER_ADDR_LEN];
	uint8_t src_addr[RTE_ETHER_ADDR_LEN];

	uint16_t ethtype_id;
};

struct mce_vlan_meta {
	uint16_t vlan_id;
};

struct mce_ipv4_meta {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t protocol;
	uint8_t is_frag;
	uint8_t dscp;
};

struct mce_ipv6_meta {
	uint32_t src_addr[4];
	uint32_t dst_addr[4];
	uint8_t protocol;
	uint8_t dscp;
	uint8_t is_frag;
};

struct mce_ip_frag_meta {
	uint8_t is_frag;
};

struct mce_tcp_meta {
	uint16_t src_port;
	uint16_t dst_port;
};

struct mce_udp_meta {
	uint16_t src_port;
	uint16_t dst_port;
};

struct mce_sctp_meta {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t vtag;
};

struct mce_esp_meta {
	uint32_t spi;
};

struct mce_vxlan_meta {
	uint32_t vni;
};

struct mce_geneve_meta {
	uint32_t vni;
};

struct mce_nvgre_meta {
	uint32_t key;
};

struct mce_gtp_meta {
	uint32_t teid; /**< Tunnel endpoint identifier. */
};

struct mce_vport_meta {
	uint16_t vport_id;
};

enum flow_meta_type {
	MCE_ETH_META = 0,
	MCE_VLAN_META,
	MCE_IPV4_META,
	MCE_IPV6_META,
	MCE_IP_FRAG,
	MCE_UDP_META,
	MCE_TCP_META,
	MCE_SCTP_META,
	MCE_ESP_META,
	MCE_VXLAN_META,
	MCE_GENEVE_META,
	MCE_NVGRE_META,
	MCE_GTPU_META,
	MCE_GTPC_META,

	MCE_VPORT_ID,

	MCE_META_TYPE_MAX,
};

union mce_flow_hdr {
	struct mce_ether_meta eth_meta;
	struct mce_vlan_meta vlan_meta;
	struct mce_ipv4_meta ipv4_meta;
	struct mce_ipv6_meta ipv6_meta;
	struct mce_ip_frag_meta frag_meta;
	struct mce_tcp_meta tcp_meta;
	struct mce_udp_meta udp_meta;
	struct mce_sctp_meta sctp_meta;
	struct mce_esp_meta esp_meta;
	struct mce_vxlan_meta vxlan_meta;
	struct mce_geneve_meta geneve_meta;
	struct mce_nvgre_meta nvgre_meta;
	struct mce_gtp_meta gtp_meta;
	struct mce_vport_meta vport_meta;
};

struct mce_lkup_meta {
	enum flow_meta_type type;
	union mce_flow_hdr hdr;
	union mce_flow_hdr mask;
};

enum mce_flow_module {
	MCE_FLOW_FDIR = 1,
	MCE_FLOW_GENERIC,
	MCE_FLOW_SWITCH,
	MCE_FLOW_RSS,
};

struct mce_flow_engine_module {
	TAILQ_ENTRY(mce_flow_engine_module) node;
	flow_engine_init_t init; /* Init module manage resource info */
	flow_engine_uinit_t uinit; /* release all manage flow rule */
	flow_engine_parse_t parse; /* check pattern hw can support */
	flow_engine_create_t create; /* create redit flow action */
	flow_engine_destroy_t destroy; /* destroy the rule by add before */
	flow_engine_query_t query;
	const char *name;
	enum mce_flow_module type;
	void *handle;
};

struct rte_flow {
	TAILQ_ENTRY(rte_flow) node;
	struct mce_flow_engine_module *flow_engine;
	void *rule;
};

/**
 * @brief Retrieve the handle for a flow engine associated with a vport.
 *
 * @param vport Pointer to the vport.
 * @param type Type of flow engine requested.
 *
 * @return Engine-specific handle or NULL if not available.
 */
void *mce_get_engine_handle(struct mce_vport *vport, enum mce_flow_module type);

/**
 * @brief Check whether a flow pattern item is supported by a list of ptype matches.
 *
 * @param item Pointer to the flow item to check.
 * @param list Array of supported ptype matches.
 * @param list_num Number of entries in @p list.
 *
 * @return Pointer to the matching `mce_flow_ptype_match` on success, NULL if not supported.
 */
struct mce_flow_ptype_match *
mce_check_pattern_support(const struct rte_flow_item *item,
			  struct mce_flow_ptype_match *list, uint16_t list_num);

extern struct mce_flow_engine_module mce_generic_engine;
extern struct mce_flow_engine_module mce_rss_engine;
extern struct mce_flow_engine_module mce_fdir_engine;
extern struct mce_flow_engine_module mce_switch_engine;
extern struct rte_flow_ops mce_flow_ops;

/**
 * @brief Validate the supported inset bits for a given flow ptype support.
 *
 * @param support Pointer to the ptype support entry.
 * @param inset Insets bits to validate.
 *
 * @return 0 if valid, negative on invalid.
 */
int mce_check_valid_inset(struct mce_flow_ptype_match *support, uint64_t inset);

/**
 * @brief Validate a flow action configuration for a given vport.
 *
 * @param vport Pointer to the vport.
 * @param actconf Pointer to the action configuration to validate.
 * @param error Pointer to rte_flow_error to populate on error.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_check_action_valid(struct mce_vport *vport,
			   struct mce_flow_action *actconf,
			   struct rte_flow_error *error);
#endif /* _MCE_FLOW_H_ */
