#ifndef _MCE_PARSE_H_
#define _MCE_PARSE_H_
#include "mce_generic_flow.h"
int mce_parse_eth(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel,
		  struct rte_flow_error *error);
int mce_parse_vlan(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error);
int mce_parse_ip4(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel,
		  struct rte_flow_error *error);
int mce_parse_ip6(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel,
		  struct rte_flow_error *error);
int mce_parse_ip6_frag(const struct rte_flow_item *item,
		       struct mce_lkup_meta *meta, uint64_t *inset,
		       bool is_tunnel, struct rte_flow_error *error);
int mce_parse_tcp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel,
		  struct rte_flow_error *error);
int mce_parse_udp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel,
		  struct rte_flow_error *error);
int mce_parse_sctp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error);
int mce_parse_vxlan(const struct rte_flow_item *item,
		    struct mce_lkup_meta *meta, uint64_t *inset, bool is_tunnel,
		    struct rte_flow_error *error);
int mce_parse_geneve(const struct rte_flow_item *item,
		     struct mce_lkup_meta *meta, uint64_t *inset,
		     bool is_tunnel, struct rte_flow_error *error);
int mce_parse_nvgre(const struct rte_flow_item *item,
		    struct mce_lkup_meta *meta, uint64_t *inset, bool is_tunnel,
		    struct rte_flow_error *error);
int mce_parse_esp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel,
		  struct rte_flow_error *error);
int mce_parse_gtpc(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error);
int mce_parse_gtpu(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error);
#endif
