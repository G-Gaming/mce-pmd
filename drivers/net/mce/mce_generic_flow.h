#ifndef _MCE_GENERIC_FLOW_H_
#define _MCE_GENERIC_FLOW_H_

#include "base/mce_osdep.h"
#include "base/mce_pfvf.h"
#include "mce_flow.h"
#include "mce.h"

struct mce_generic_rule {
	enum mce_rule_engine_module e_module;
	void *engine_rule;
};

struct mce_generic_ntuple_pattern {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t protocol;
	uint16_t l4_dport;
	uint16_t l4_sport;

	uint8_t vport_id;
	bool is_tunnel;
	bool is_ipv6;
};

struct mce_generic_ntuple_filter {
	struct mce_generic_ntuple_pattern lkup_pattern;
	struct mce_flow_action actions;

	uint64_t options;
	uint16_t loc;
};

struct mce_generic_etype_pattern {
	uint16_t ethtype_id;

	bool is_tunnel;
};

struct mce_generic_etype_filter {
	struct mce_generic_etype_pattern lkup_pattern;
	struct mce_flow_action actions;
	uint64_t options;
	uint16_t loc;
};

struct mce_generic_sync_filter {
	struct mce_flow_action actions;

	bool hi_priori;
	uint64_t options;
	uint16_t loc;
};

struct mce_generic_handle {
	struct mce_generic_ntuple_filter **ntuple_hash_map;
	struct rte_hash *ntuple_hash_table;
	uint16_t max_ntuple_rule;

	struct mce_generic_etype_filter **etype_hash_map;
	struct rte_hash *etype_hash_table;
	uint16_t max_etype_rule;

	struct mce_bitmap_entry ntuple_map;

	struct mce_lkup_meta meta_db[2][MCE_META_TYPE_MAX];
};
struct mce_vf_ntuple_rule;
int mce_vf_del_ntuple(struct mce_pf *pf, int vfid, struct mce_vf_ntuple_rule *rule);
int mce_vf_add_ntuple(struct mce_pf *pf, int vfid, struct mce_vf_ntuple_rule *rule);

#endif /* _MCE_GENERIC_FLOW_H_ */
