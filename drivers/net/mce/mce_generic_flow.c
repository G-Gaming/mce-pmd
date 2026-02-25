#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_string_fns.h>

#include "./base/mce_common.h"
#include "./base/mce_eth_regs.h"
#include "./base/mce_bitops.h"
#include "mce_flow.h"
#include "mce_generic_flow.h"
#include "mce_logs.h"
#include "mce_parse.h"
#include "mce_pattern.h"
#include "mce_compat.h"
#include "mce_pf.h"
#include "mce_vf.h"
#include "mce.h"

#define MCE_OPT_IPV4	  (MCE_OPT_IPV4_DIP | MCE_OPT_IPV4_SIP | MCE_OPT_L4_PROTO)
#define MCE_OPT_L4_TCP	  (MCE_OPT_TCP_SPORT | MCE_OPT_TCP_DPORT)
#define MCE_OPT_L4_UDP	  (MCE_OPT_UDP_SPORT | MCE_OPT_UDP_DPORT)
#define MCE_OPT_L4_SCTP	  (MCE_OPT_SCTP_SPORT | MCE_OPT_SCTP_SPORT)

#define MCE_OPT_IPV4_TCP  (MCE_OPT_IPV4 | MCE_OPT_L4_TCP)
#define MCE_OPT_IPV4_UDP  (MCE_OPT_IPV4 | MCE_OPT_L4_UDP)
#define MCE_OPT_IPV4_SCTP (MCE_OPT_IPV4 | MCE_OPT_L4_SCTP)
/* L2 */
enum rte_flow_item_type compose_eth[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4 */
enum rte_flow_item_type compose_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-TCP */
enum rte_flow_item_type compose_ipv4_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-UDP */
enum rte_flow_item_type compose_ipv4_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV4-SCTP */
enum rte_flow_item_type compose_ipv4_sctp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-TCP */
enum rte_flow_item_type compose_ipv6_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-UDP */
enum rte_flow_item_type compose_ipv6_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};
/* IPV6-SCTP */
enum rte_flow_item_type compose_ipv6_sctp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_SCTP,
	RTE_FLOW_ITEM_TYPE_END,
};

/* TCP-SYNC */
enum rte_flow_item_type compose_tcp_sync[] = {
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

/**
 * @brief Convert lookup metadata into an ETYPE filter object.
 *
 * Allocates and fills a `mce_generic_etype_filter` from parsed metadata
 * for an Ethertype based match.
 *
 * @param h_ptr Engine handle (cast to `struct mce_generic_handle *`).
 * @param meta_num Number of metadata entries provided.
 * @param mask_info Unused bitmask information (reserved).
 * @param actions Pointer to actions to attach to the filter.
 * @param options Option bitmask describing which fields are enabled.
 * @param is_ipv6 Unused indicator for IPv6 (reserved).
 * @param is_tunnel Unused indicator for tunnel context (reserved).
 * @return Pointer to allocated filter on success, NULL on allocation/error.
 */
static void *mce_generic_meta_to_etype_rule(
	void *h_ptr, uint16_t meta_num,
	struct mce_field_bitmask_info *mask_info __rte_unused,
	struct mce_flow_action *actions, uint64_t options,
	bool is_ipv6 __rte_unused, bool is_tunnel __rte_unused)
{
	struct mce_generic_handle *handle = (struct mce_generic_handle *)h_ptr;
	struct mce_generic_etype_filter *filter = NULL;
	struct mce_generic_etype_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;

	filter = rte_zmalloc(NULL, sizeof(struct mce_generic_ntuple_filter), 0);
	if (filter == NULL)
		return NULL;
	lkup_pattern = &filter->lkup_pattern;
	meta = &handle->meta_db[is_tunnel][0];

	if (meta->type != MCE_ETH_META || meta_num != 1)
		return NULL;
	lkup_pattern->ethtype_id = meta->hdr.eth_meta.ethtype_id;
	lkup_pattern->is_tunnel = is_tunnel;
	filter->options = options;
	filter->actions = *actions;

	return filter;
}

/**
 * @brief Convert lookup metadata into an ntuple (L3/L4) filter object.
 *
 * Builds a `mce_generic_ntuple_filter` from parsed metadata entries
 * combining IP and L4 fields as required.
 *
 * @param h_ptr Engine handle (cast to `struct mce_generic_handle *`).
 * @param meta_num Number of metadata entries provided.
 * @param mask_info Unused bitmask information (reserved).
 * @param actions Pointer to actions to attach to the filter.
 * @param options Option bitmask describing which fields are enabled.
 * @param is_ipv6 True when parsing IPv6 metadata.
 * @param is_tunnel True when parsing tunnel-encapsulated metadata.
 * @return Pointer to allocated filter on success, NULL on allocation/error.
 */
static void *mce_generic_meta_to_ntuple_rule(
	void *h_ptr, uint16_t meta_num,
	struct mce_field_bitmask_info *mask_info __rte_unused,
	struct mce_flow_action *actions, uint64_t options, bool is_ipv6,
	bool is_tunnel)
{
	struct mce_generic_handle *handle = (struct mce_generic_handle *)h_ptr;
	struct mce_generic_ntuple_filter *filter = NULL;
	struct mce_generic_ntuple_pattern *lkup_pattern;
	struct mce_lkup_meta *meta;
	uint8_t proto = 0;
	bool l4_en = false;
	int i = 0;

	filter = rte_zmalloc(NULL, sizeof(struct mce_generic_ntuple_filter), 0);
	if (filter == NULL)
		return NULL;
	lkup_pattern = &filter->lkup_pattern;
	for (i = 0; i < meta_num; i++) {
		meta = &handle->meta_db[is_tunnel][i];
		switch (meta->type) {
		case MCE_IPV4_META:
			lkup_pattern->src_addr = meta->hdr.ipv4_meta.src_addr;
			lkup_pattern->dst_addr = meta->hdr.ipv4_meta.dst_addr;
			lkup_pattern->protocol = meta->hdr.ipv4_meta.protocol;
			break;
		case MCE_UDP_META:
			lkup_pattern->l4_dport = meta->hdr.udp_meta.dst_port;
			lkup_pattern->l4_sport = meta->hdr.udp_meta.src_port;
			l4_en = true;
			proto = IPPROTO_UDP;
			break;
		case MCE_TCP_META:
			lkup_pattern->l4_dport = meta->hdr.tcp_meta.dst_port;
			lkup_pattern->l4_sport = meta->hdr.tcp_meta.src_port;
			l4_en = true;
			proto = IPPROTO_TCP;
			break;
		case MCE_SCTP_META:
			lkup_pattern->l4_dport = meta->hdr.sctp_meta.dst_port;
			lkup_pattern->l4_sport = meta->hdr.sctp_meta.src_port;
			l4_en = true;
			proto = IPPROTO_SCTP;
			break;
		default:
			PMD_DRV_LOG(ERR, "the rule isn't support this options");
		}
	}
	if (!lkup_pattern->protocol && l4_en) {
		lkup_pattern->protocol = proto;
		options |= MCE_OPT_L4_PROTO;
	}
	lkup_pattern->is_tunnel = is_tunnel;
	lkup_pattern->is_ipv6 = is_ipv6;

	filter->options = options;
	filter->actions = *actions;

	return filter;
}

/**
 * @brief Convert lookup metadata into a sync filter object.
 *
 * Creates a `mce_generic_sync_filter` used for TCP-SYN style matching
 * and sets priority flags when requested.
 *
 * @param h_ptr Unused engine handle.
 * @param meta_num Unused metadata count.
 * @param mask_info Unused bitmask information.
 * @param actions Pointer to actions to attach to the filter.
 * @param options Option bitmask describing which fields are enabled.
 * @param is_ipv6 Unused indicator for IPv6.
 * @param is_tunnel Unused indicator for tunnel context.
 * @return Pointer to allocated filter on success, NULL on allocation/error.
 */
static void *mce_generic_meta_to_sync_rule(
	void *h_ptr __rte_unused, uint16_t meta_num __rte_unused,
	struct mce_field_bitmask_info *mask_info __rte_unused,
	struct mce_flow_action *actions, uint64_t options,
	bool is_ipv6 __rte_unused, bool is_tunnel __rte_unused)
{
	struct mce_generic_sync_filter *filter = NULL;

	filter = rte_zmalloc(NULL, sizeof(struct mce_generic_sync_filter), 0);
	if (filter == NULL)
		return NULL;

	filter->options = options;
	filter->actions = *actions;
	if (actions->priority)
		filter->hi_priori = 1;

	return filter;
}

static struct mce_flow_ptype_match mce_ptype_generic_support[] = {
	{ compose_eth, 0, MCE_OPT_ETHTYPE, MCE_GENERIC_ETYPE,
	  mce_generic_meta_to_etype_rule },
	{ compose_ipv4, 0, MCE_OPT_IPV4, MCE_GERERIC_NTUPLE,
	  mce_generic_meta_to_ntuple_rule },
	{ compose_ipv4_tcp, 0, MCE_OPT_IPV4_TCP, MCE_GERERIC_NTUPLE,
	  mce_generic_meta_to_ntuple_rule },
	{ compose_ipv4_udp, 0, MCE_OPT_IPV4_UDP, MCE_GERERIC_NTUPLE,
	  mce_generic_meta_to_ntuple_rule },
	{ compose_ipv4_sctp, 0, MCE_OPT_IPV4_SCTP, MCE_GERERIC_NTUPLE,
	  mce_generic_meta_to_ntuple_rule },
	{ compose_ipv6_tcp, 0, MCE_OPT_L4_TCP, MCE_GERERIC_NTUPLE,
	  mce_generic_meta_to_ntuple_rule },
	{ compose_ipv6_udp, 0, MCE_OPT_L4_UDP, MCE_GERERIC_NTUPLE,
	  mce_generic_meta_to_ntuple_rule },
	{ compose_ipv6_sctp, 0, MCE_OPT_L4_SCTP, MCE_GERERIC_NTUPLE,
	  mce_generic_meta_to_ntuple_rule },
	{ compose_tcp_sync, 0, MCE_OPT_TCP_SYNC, MCE_GENERIC_SYNC,
	  mce_generic_meta_to_sync_rule },
};

/**
 * @brief Check whether a flow item pattern matches an item type array.
 *
 * Compares an expected item type sequence against a parsed flow item
 * pattern to determine compatibility.
 *
 * @param item_array Null-terminated array of expected `rte_flow_item_type`.
 * @param pattern Parsed flow item sequence to validate.
 * @return true if the pattern exactly matches the expected array, false otherwise.
 */
static bool mce_match_pattern(enum rte_flow_item_type *item_array,
			      const struct rte_flow_item *pattern)
{
	const struct rte_flow_item *item = pattern;
	while ((*item_array == item->type) &&
	       (*item_array != RTE_FLOW_ITEM_TYPE_END)) {
		item_array++;
		item++;
	}

	return (*item_array == RTE_FLOW_ITEM_TYPE_END &&
		item->type == RTE_FLOW_ITEM_TYPE_END);
}

/**
 * @brief Find a matching pattern support entry for a parsed flow item.
 *
 * @param item Pointer to the first non-void `rte_flow_item` in a pattern.
 * @param list Array of supported pattern match descriptors.
 * @param list_num Number of entries in `list`.
 * @return Pointer to matching `mce_flow_ptype_match` on success, NULL if none match.
 */
struct mce_flow_ptype_match *
mce_check_pattern_support(const struct rte_flow_item *item,
			  struct mce_flow_ptype_match *list, uint16_t list_num)
{
	int i = 0;

	for (i = 0; i < list_num; i++) {
		if (mce_match_pattern(list[i].pattern_list, item))
			return &list[i];
	}

	return NULL;
}

/**
 * @brief Validate that inset options are non-zero and within supported range.
 *
 * @param support Pointer to the supported pattern descriptor.
 * @param inset Bitmask of enabled options parsed from the flow items.
 * @return 0 on valid, -EINVAL on invalid inset.
 */
int mce_check_valid_inset(struct mce_flow_ptype_match *support, uint64_t inset)
{
	if (!inset)
		return -EINVAL;
	if (inset > support->insets)
		return -EINVAL;
	return 0;
}

/**
 * @brief Validate flow action configuration for a vport.
 *
 * Checks redirect queue index and mark value ranges and reports errors
 * through `rte_flow_error` when validation fails.
 *
 * @param vport VPort owning the flow.
 * @param actconf Action configuration to validate.
 * @param error rte_flow_error for detailed error reporting.
 * @return 0 on success, negative error code and sets `error` on failure.
 */
int mce_check_action_valid(struct mce_vport *vport,
			   struct mce_flow_action *actconf,
			   struct rte_flow_error *error)
{
	if (actconf->redirect_en) {
		if (actconf->redir.index >= vport->dev->data->nb_rx_queues)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL,
				"Queue Index Is Outof Range Of Rx Queues");
	}
	if (actconf->mark.id > UINT16_MAX)
		return rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF, NULL,
			"ntuple action Mark Range from 0 to 65535");

	return 0;
}

/**
 * @brief Parse generic flow items into an engine-specific rule.
 *
 * Translates `pattern` and `actions` into a `mce_generic_rule` and
 * allocates engine-specific filter objects via the engine handle.
 *
 * @param vport VPort owning the flow.
 * @param o_parm Out parameter receiving pointer to allocated rule.
 * @param attr Flow attributes (unused).
 * @param pattern Array of flow items describing the match.
 * @param actions Array of flow actions describing the behavior.
 * @param error rte_flow_error for reporting parse/validation failures.
 * @return 0 on success, negative errno on failure and sets `error` as appropriate.
 */
static int mce_generic_flow_parse(struct mce_vport *vport, void **o_parm,
				  const struct rte_flow_attr *attr __rte_unused,
				  const struct rte_flow_item pattern[],
				  const struct rte_flow_action actions[],
				  struct rte_flow_error *error)
{
	struct mce_generic_rule **rule = (struct mce_generic_rule **)o_parm;
	struct mce_flow_ptype_match *support = NULL;
	const struct rte_flow_action *act = actions;
	const struct rte_flow_item *item = pattern;
	struct mce_generic_handle *handle = NULL;
	struct mce_flow_action action_conf;
	struct mce_lkup_meta *meta = NULL;
	struct mce_generic_rule *tmp;
	uint8_t act_mark_cnt = 0;
	bool is_tunnel = false;
	uint16_t meta_num = 0;
	uint8_t act_q_cnt = 0;
	uint64_t inset = 0;
	bool is_ipv6 = false;
	int ret = 0;

	/* 1.define filter enging can support pattern compose */
	/* 2.check the pattern input options flow engine can deal */
	if (pattern == NULL)
		return -EINVAL;
	/* Get the non-void item number of pattern */
	while (item->type == RTE_FLOW_ITEM_TYPE_VOID)
		item++;
	support = mce_check_pattern_support(item, mce_ptype_generic_support,
					    RTE_DIM(mce_ptype_generic_support));
	if (support == NULL)
		return rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
			"generic pattern compose not support");

	handle = (struct mce_generic_handle *)mce_get_engine_handle(
		vport, MCE_FLOW_GENERIC);
	memset(&action_conf, 0, sizeof(action_conf));
	item = pattern;
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		meta = &handle->meta_db[is_tunnel][meta_num];
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
					"generate item type not "
					"support "
					"ipv6 options");
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
		case RTE_FLOW_ITEM_TYPE_NVGRE:
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ITEM_TYPE_GRE:
#endif /* RTE_VERSION >= 17.05 */
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ITEM_TYPE_GTP:
		case RTE_FLOW_ITEM_TYPE_GTPC:
		case RTE_FLOW_ITEM_TYPE_GTPU:
#endif /* RTE_VERSION >= 17.11 */
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ITEM_TYPE_GENEVE:
		case RTE_FLOW_ITEM_TYPE_ESP:
			is_tunnel = true;
			break;
#endif /* RTE_VERSION >= 18.02*/
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
		meta_num += (ret > 0 ? 1 : 0);
	}
	if (mce_check_valid_inset(support, inset) < 0)
		return rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
			"generic item options compose not support");
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
			break;
#endif
		default:
			return rte_flow_error_set(
				error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
				"Generic Flow Act type not supported");
		}
	}
	if (act_q_cnt == 0)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
			"Flow Act action need drop or redir queue");
	if (act_q_cnt >= 2)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
			"Flow Act type Queue 1 Rule Just Support One");
	if (act_mark_cnt >= 2)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
			"Flow Act type Mark 1 Rule Just Support One");
	if (mce_check_action_valid(vport, &action_conf, error))
		return -EINVAL;
	/* if don't need upload the correct match info
	 * just upload the pattern is parse ready
	 */
	if (rule == NULL)
		goto end;
	tmp = rte_zmalloc(NULL, sizeof(struct mce_generic_rule), 0);
	if (tmp == NULL)
		return -ENOMEM;
	tmp->engine_rule = support->meta_to_rule(handle, meta_num, NULL,
						 &action_conf, inset, is_ipv6,
						 is_tunnel);
	memset(handle->meta_db[is_tunnel], 0,
	       sizeof(struct mce_lkup_meta) * meta_num);
	tmp->e_module = support->e_module;
	*rule = tmp;
end:
	return 0;
}

/**
 * @brief Lookup an etype filter by its pattern key in the handle's hash table.
 *
 * @param handle Engine handle owning the etype hash table.
 * @param key Pointer to the etype pattern key to lookup.
 * @return Pointer to the matching filter or NULL if not found.
 */
static struct mce_generic_etype_filter *
mce_etype_entry_lookup(struct mce_generic_handle *handle,
		       const struct mce_generic_etype_pattern *key)
{
	int ret;

	ret = rte_hash_lookup(handle->etype_hash_table, key);
	if (ret < 0)
		return NULL;

	return handle->etype_hash_map[ret];
}


/**
 * @brief Insert an etype filter into the engine's hash table and map.
 *
 * @param handle Engine handle owning the etype structures.
 * @param entry Pointer to filter to insert (ownership remains with caller).
 * @param key Pointer to key used for hash insertion.
 * @return 0 on success, negative errno on failure.
 */
static int mce_etype_entry_insert(struct mce_generic_handle *handle,
				  struct mce_generic_etype_filter *entry,
				  const struct mce_generic_etype_pattern *key)
{
	int ret;

	ret = rte_hash_add_key(handle->etype_hash_table, key);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to insert etype entry to hash table %d!",
			    ret);
		return ret;
	}
	entry->loc = ret;
	handle->etype_hash_map[ret] = entry;

	return 0;
}

/**
 * @brief Delete an etype filter identified by `key` from the engine.
 *
 * @param handle Engine handle owning the etype structures.
 * @param key Pointer to key used to delete the entry.
 * @return 0 on success, negative errno on failure.
 */
static int mce_etype_entry_del(struct mce_generic_handle *handle,
			       const struct mce_generic_etype_pattern *key)
{
	int ret;

	ret = rte_hash_del_key(handle->etype_hash_table, key);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to delete etype filter to hash table %d!",
			    ret);
		return ret;
	}
	handle->etype_hash_map[ret] = NULL;

	return 0;
}

/**
 * @brief Program or remove an Ethertype hardware rule for a vport.
 *
 * When `add` is true the function allocates a hardware location, programs
 * action/control registers and inserts the entry into the hash map. When
 * `add` is false it removes the entry and clears hardware registers.
 *
 * @param vport VPort owning the rule.
 * @param handle Engine handle for the vport.
 * @param filter Pointer to etype filter to add or remove.
 * @param add True to add/program the rule, false to remove it.
 * @return 0 on success, negative errno on failure.
 */
static int mce_generic_etype_setup(struct mce_vport *vport,
				   struct mce_generic_handle *handle,
				   struct mce_generic_etype_filter *filter,
				   bool add)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_generic_etype_filter *tmp;
	struct mce_flow_action *action;
	uint32_t etqf = 0, etqs = 0;
	uint16_t queue_id = 0;
	uint16_t vport_id = 0;
	uint16_t loc = 0;
	int i = 0;

	vport_id = vport->attr.vport_id;
	if (!(handle->max_etype_rule -
	      rte_hash_count(handle->etype_hash_table)))
		return -ENOMEM;
	tmp = mce_etype_entry_lookup(handle, &filter->lkup_pattern);
	if (add == MCE_FLOW_ADD && tmp)
		return -EEXIST;
	if (add == MCE_FLOW_DEL && tmp == NULL)
		return -EIDRM;
	if (add) {
		mce_etype_entry_insert(handle, filter, &filter->lkup_pattern);
		loc = filter->loc;
		action = &filter->actions;
		queue_id = action->redir.index;
		etqf = MCE_ETQF_EN | filter->lkup_pattern.ethtype_id;
		if (action->rule_action == MCE_FILTER_DROP) {
			etqs = MCE_RULE_ACTION_DROP;
		} else {
			etqs = MCE_RULE_ACTION_PASS;
			if (action->redirect_en) {
				etqs |= queue_id << MCE_RULE_ACTION_Q_S;
				etqs |= MCE_RULE_ACTION_Q_EN;
			}
		}
		if (action->mark_en) {
			etqs |= MCE_RULE_ACTION_MARK_EN;
			etqs |= (action->mark.id) & (UINT16_MAX);
		}
		if (action->pop_vlan) {
			etqs |= MCE_RULE_ACTION_VLAN_EN;
			etqs |= MCE_POP_1VLAN << MCE_RULE_ACTION_POP_VLAN_S;
		}
		MCE_E_REG_WRITE(hw, MCE_ETH_ETQF(vport_id, loc), etqf);
		MCE_E_REG_WRITE(hw, MCE_ETH_ETQS(vport_id, loc), etqs);
	} else {
		loc = filter->loc;
		mce_etype_entry_del(handle, &filter->lkup_pattern);
		rte_free(filter);
		MCE_E_REG_WRITE(hw, MCE_ETH_ETQF(vport_id, loc), 0);
		MCE_E_REG_WRITE(hw, MCE_ETH_ETQS(vport_id, loc), 0);
	}
	for (i = 0; i < 16; i++) {
		etqf = MCE_E_REG_READ(hw, MCE_ETH_ETQF(vport_id, i));
		etqs = MCE_E_REG_READ(hw, MCE_ETH_ETQS(vport_id, i));

		printf("conf[%d] etqf 0x%.2x\n", i, etqf);
		printf("conf[%d] etqs 0x%.2x\n", i, etqs);
	}

	return 0;
}
/**
 * @brief Lookup an ntuple filter by key in the engine's ntuple hash table.
 *
 * @param handle Engine handle owning the ntuple hash table.
 * @param key Pointer to the ntuple pattern key to lookup.
 * @return Pointer to the matching filter or NULL if not found.
 */
static struct mce_generic_ntuple_filter *
mce_ntuple_entry_lookup(struct mce_generic_handle *handle,
			const struct mce_generic_ntuple_pattern *key)
{
	int ret;

	ret = rte_hash_lookup(handle->ntuple_hash_table, key);
	if (ret < 0)
		return NULL;

	return handle->ntuple_hash_map[ret];
}

/**
 * @brief Insert an ntuple filter into the engine's ntuple structures.
 *
 * @param handle Engine handle.
 * @param entry Pointer to filter to insert.
 * @param key Pointer to key used for hash insertion.
 * @return 0 on success, negative errno on failure.
 */
static int mce_ntuple_entry_insert(struct mce_generic_handle *handle,
				   struct mce_generic_ntuple_filter *entry,
				   const struct mce_generic_ntuple_pattern *key)
{
	int ret;

	ret = rte_hash_add_key(handle->ntuple_hash_table, key);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to insert ntuple entry to hash table %d!",
			    ret);
		return ret;
	}
	handle->ntuple_hash_map[ret] = entry;
	mce_set_used_location(&handle->ntuple_map, entry->loc);

	return 0;
}

/**
 * @brief Delete an ntuple filter identified by `key` and free resources.
 *
 * @param handle Engine handle.
 * @param key Pattern key used to remove the entry.
 * @return 0 on success, negative errno on failure.
 */
static int mce_ntuple_entry_del(struct mce_generic_handle *handle,
				const struct mce_generic_ntuple_pattern *key)
{
	struct mce_generic_ntuple_filter *filter = NULL;
	int ret;

	ret = rte_hash_del_key(handle->ntuple_hash_table, key);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to delete fdir filter to hash table %d!",
			    ret);
		return ret;
	}
	filter = handle->ntuple_hash_map[ret];
	handle->ntuple_hash_map[ret] = NULL;
	mce_free_used_location(&handle->ntuple_map, filter->loc);

	return 0;
}

static int
mcevf_set_vf_ntuple(struct mce_vport *vport,
		    struct mce_generic_ntuple_filter *filter, bool add)
{
	uint32_t msgbuf[15] = { 0 };
	struct mce_vf_ntuple_rule *rule = (void *)msgbuf;

	rule->add = add;
	rule->pattern.sip = filter->lkup_pattern.src_addr;
	rule->pattern.dip = filter->lkup_pattern.dst_addr;
	rule->pattern.l4_type = filter->lkup_pattern.protocol;
	rule->pattern.is_ipv6 = filter->lkup_pattern.is_ipv6;
	rule->act.is_drop  = filter->actions.rule_action == MCE_FILTER_DROP ? 1 : 0;
	rule->act.redir_queue = filter->actions.redir.index;
	rule->act.mark_id = filter->actions.mark.id;

	return mce_request_set_vf_ntuple(vport, rule);;
}

static int
mcevf_generic_ntuple_setup(struct mce_vport *vport,
			   struct mce_generic_handle *handle,
			   struct mce_generic_ntuple_filter *filter,
			   bool add)
{

	struct mce_generic_ntuple_filter *tmp;
	int ret = 0;

	if (!(handle->max_ntuple_rule -
	      rte_hash_count(handle->ntuple_hash_table)))
		return -ENOMEM;
	tmp = mce_ntuple_entry_lookup(handle, &filter->lkup_pattern);
	if (add == MCE_FLOW_ADD && tmp)
		return -EEXIST;
	if (add == MCE_FLOW_DEL && tmp == NULL)
		return -EIDRM;
	ret = mcevf_set_vf_ntuple(vport, filter, add);
	if (ret < 0)
		return ret;
	if (add) {
		mce_ntuple_entry_insert(handle, filter, &filter->lkup_pattern);
	} else {
		mce_ntuple_entry_del(handle, &filter->lkup_pattern);
		rte_free(filter);
	}
	return 0;
}
/**
 * @brief Program or remove an ntuple (L3/L4) hardware rule.
 *
 * Programs SIP/DIP/L4 ports and control flags into hardware when `add` is
 * true or clears registers when removing. Also manages the engine's
 * allocation bitmap and hash map entries.
 *
 * @param port VPort owning the rule.
 * @param handle Engine handle for the port.
 * @param filter Pointer to ntuple filter to add/remove.
 * @param add True to add/program the rule, false to remove it.
 * @return 0 on success, negative errno on failure.
 */
static int mce_generic_ntuple_setup(struct mce_vport *vport,
				    struct mce_generic_handle *handle,
				    struct mce_generic_ntuple_filter *filter,
				    bool add)
{
	struct mce_flow_action *action = &filter->actions;
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_generic_ntuple_filter *tmp;
	uint32_t sip = 0, dip = 0;
	uint16_t queue_id = 0;
	uint8_t l4_proto = 0;
	uint32_t l4_port = 0;
	uint32_t ctrl = 0;
	uint32_t act = 0;
	uint16_t loc = 0;
	int ret = 0;

	if (!(handle->max_ntuple_rule -
	      rte_hash_count(handle->ntuple_hash_table)))
		return -ENOMEM;
	tmp = mce_ntuple_entry_lookup(handle, &filter->lkup_pattern);
	if (add == MCE_FLOW_ADD && tmp)
		return -EEXIST;
	if (add == MCE_FLOW_DEL && tmp == NULL)
		return -EIDRM;
	queue_id = action->redir.index;
	if (add) {
		ret = mce_get_valid_location(&handle->ntuple_map, &filter->loc);
		if (ret < 0)
			return ret;
		printf("ntuple add loc %d\n", filter->loc);
		loc = filter->loc;
		sip = (filter->lkup_pattern.src_addr);
		dip = (filter->lkup_pattern.dst_addr);
		l4_proto = filter->lkup_pattern.protocol;
		l4_port = filter->lkup_pattern.l4_dport << 16 |
			filter->lkup_pattern.l4_sport;
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_SIP(loc), sip);
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_DIP(loc), dip);
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_L4PORT(loc), l4_port);
		ctrl = MCE_NTUPLE_F_EN;
		if (!(filter->options &
					(MCE_OPT_OUT_L4_SPORT | MCE_OPT_L4_SPORT)))
			ctrl |= MCE_NTUPLE_F_L4SP_MASK;
		if (!(filter->options &
					(MCE_OPT_OUT_L4_DPORT | MCE_OPT_L4_DPORT)))
			ctrl |= MCE_NTUPLE_F_L4DP_MASK;
		if (!(filter->options &
					(MCE_OPT_OUT_IPV4_SIP | MCE_OPT_IPV4_SIP)))
			ctrl |= MCE_NTUPLE_F_SIP_MASK;
		if (!(filter->options &
					(MCE_OPT_OUT_IPV4_DIP | MCE_OPT_IPV4_DIP)))
			ctrl |= MCE_NTUPLE_F_DIP_MASK;
		if (!(filter->options & MCE_OPT_L4_PROTO))
			ctrl |= MCE_NTUPLE_F_L3TYPE_MASK;
		if (dip == 0 && sip == 0 && filter->lkup_pattern.is_ipv6)
			ctrl |= MCE_NTUPLE_F_IPV6;
		ctrl |= l4_proto;
		if (hw->max_vfs) {
			ctrl |= MCE_NTUPLE_F_P_EN;
			ctrl |= filter->lkup_pattern.vport_id << MCE_NTUPLE_F_P_S;
		}
		/* need to get if rule is a ipv6 l4 match */
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_F_CTRL(loc), ctrl);
		if (action->rule_action == MCE_FILTER_DROP) {
			act = MCE_RULE_ACTION_DROP;
		} else {
			act = MCE_RULE_ACTION_PASS;
			if (action->redirect_en) {
				act |= queue_id << MCE_RULE_ACTION_Q_S;
				act |= MCE_RULE_ACTION_Q_EN;
			}
		}
		if (action->mark_en) {
			act |= MCE_RULE_ACTION_MARK_EN;
			act |= action->mark.id;
		}
		if (action->pop_vlan) {
			act |= MCE_RULE_ACTION_VLAN_EN;
			act |= MCE_POP_1VLAN << MCE_RULE_ACTION_POP_VLAN_S;
		}
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_F_ACT(loc), act);
	} else {
		loc = filter->loc;
		sip = (filter->lkup_pattern.src_addr);
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_SIP(loc), 0);
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_DIP(loc), 0);
		MCE_E_REG_WRITE(hw, MCE_NTUPLE_L4PORT(loc), 0);

		MCE_E_REG_WRITE(hw, MCE_NTUPLE_F_CTRL(loc), 0);

		MCE_E_REG_WRITE(hw, MCE_NTUPLE_F_ACT(loc), 0);
	}
	if (add) {
		mce_ntuple_entry_insert(handle, filter, &filter->lkup_pattern);
	} else {
		mce_ntuple_entry_del(handle, &filter->lkup_pattern);
		rte_free(filter);
	}

	return 0;
}

/**
 * @brief Program or remove a sync (TCP-SYN) hardware rule.
 *
 * Configures sync priority and action registers for the specified vport.
 *
 * @param vport VPort owning the rule.
 * @param handle Unused engine handle.
 * @param filter Sync filter containing actions and priority flag.
 * @param add True to add/program the rule, false to remove it.
 * @return 0 on success, negative errno on failure.
 */
static int
mce_generic_sync_setup(struct mce_vport *vport,
		       struct mce_generic_handle *handle __rte_unused,
		       struct mce_generic_sync_filter *filter, bool add)
{
	struct mce_flow_action *action = &filter->actions;
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	uint16_t vport_id = vport->attr.vport_id;
	uint16_t queue_id = 0;
	uint32_t reg = 0;
	uint32_t act = 0;

	queue_id = action->redir.index;
	if (add) {
		reg = MCE_SYNC_RULE_EN;
		/* flow match first match all other flow */
		if (filter->hi_priori)
			reg |= MCE_SYNC_HI_PRIV_EN;
		MCE_E_REG_WRITE(hw, MCE_SYNC_PRIORITY(vport_id), reg);
		if (action->rule_action == MCE_FILTER_DROP) {
			act = MCE_RULE_ACTION_DROP;
		} else {
			act = MCE_RULE_ACTION_PASS;
			if (action->redirect_en) {
				act |= queue_id << MCE_RULE_ACTION_Q_S;
				act |= MCE_RULE_ACTION_Q_EN;
			}
		}
		if (action->mark_en) {
			act |= MCE_RULE_ACTION_MARK_EN;
			act |= action->mark.id;
		}
		if (action->pop_vlan) {
			act |= MCE_RULE_ACTION_VLAN_EN;
			act |= MCE_POP_1VLAN << MCE_RULE_ACTION_POP_VLAN_S;
		}
		MCE_E_REG_WRITE(hw, MCE_SYNC_QF(vport_id), act);
	} else {
		MCE_E_REG_WRITE(hw, MCE_SYNC_QF(vport_id), 0);
		MCE_E_REG_WRITE(hw, MCE_SYNC_PRIORITY(vport_id), 0);
	}

	return 0;
}

/**
 * @brief Create and install a generic filter rule in hardware.
 *
 * Applies the parsed `flow->rule` by calling appropriate hardware setup
 * functions based on the filter module type (ntuple, etype, etc.).
 *
 * @param vport
 *   VPort owning the flow.
 * @param flow
 *   Flow containing the pre-parsed generic rule.
 * @param error
 *   Error reporting structure.
 * @return
 *   0 on success, negative errno on failure.
 */
static int mce_generic_flow_create(struct mce_vport *vport,
				   struct rte_flow *flow,
				   struct rte_flow_error *error)
{
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_generic_rule *rule = flow->rule;
	struct mce_generic_handle *handle = NULL;
	int ret = 0;
	/* according the flow to setup the rule engine sub rule */
	if (rule == NULL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_HANDLE, flow,
					  "parse rule is null");
	handle = (struct mce_generic_handle *)flow_engine->handle;
	switch (rule->e_module) {
	case MCE_GENERIC_ETYPE:
		ret = mce_generic_etype_setup(
			vport, handle,
			(struct mce_generic_etype_filter *)rule->engine_rule,
			MCE_FLOW_ADD);
		if (ret < 0)
			return rte_flow_error_set(error, -ret,
						  RTE_FLOW_ERROR_TYPE_HANDLE,
						  rule,
						  "etype rule add failed");
		break;
	case MCE_GERERIC_NTUPLE:
		if (vport->is_vf) {
			ret = mcevf_generic_ntuple_setup(
					vport, handle,
					(struct mce_generic_ntuple_filter *)rule->engine_rule,
					MCE_FLOW_ADD);

		} else {
			ret = mce_generic_ntuple_setup(
					vport, handle,
					(struct mce_generic_ntuple_filter *)rule->engine_rule,
					MCE_FLOW_ADD);

		}
		if (ret < 0)
			return rte_flow_error_set(error, -ret,
						  RTE_FLOW_ERROR_TYPE_HANDLE,
						  rule,
						  "ntuple rule add failed");
		break;
	case MCE_GENERIC_SYNC:
		ret = mce_generic_sync_setup(
			vport, handle,
			(struct mce_generic_sync_filter *)rule->engine_rule,
			MCE_FLOW_ADD);
		if (ret < 0)
			return rte_flow_error_set(error, -ret,
						  RTE_FLOW_ERROR_TYPE_HANDLE,
						  rule,
						  "sync filter add failed");
		break;
	default:
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_HANDLE, rule,
					  "rule is not support to setup");
		break;
	}

	return 0;
}



static int mce_generic_flow_delate(struct mce_vport *vport,
				   struct rte_flow *flow,
				   struct rte_flow_error *error)
{
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_generic_rule *rule = flow->rule;
	struct mce_generic_handle *handle = NULL;
	int ret = 0;
	/* according the flow to setup the rule engine sub rule */
	if (rule == NULL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, flow,
					  "parse rule is null");
	handle = (struct mce_generic_handle *)flow_engine->handle;
	switch (rule->e_module) {
	case MCE_GENERIC_ETYPE:
		ret = mce_generic_etype_setup(
			vport, handle,
			(struct mce_generic_etype_filter *)rule->engine_rule,
			MCE_FLOW_DEL);
		if (ret < 0)
			return rte_flow_error_set(error, -ret,
						  RTE_FLOW_ERROR_TYPE_HANDLE,
						  rule,
						  "etype rule delata failed");
		break;
	case MCE_GERERIC_NTUPLE:
		if (vport->is_vf) {
			ret = mcevf_generic_ntuple_setup(
					vport, handle,
					(struct mce_generic_ntuple_filter *)rule->engine_rule,
					MCE_FLOW_DEL);

		} else {
			ret = mce_generic_ntuple_setup(
					vport, handle,
					(struct mce_generic_ntuple_filter *)rule->engine_rule,
					MCE_FLOW_DEL);

		}
		if (ret < 0)
			return rte_flow_error_set(error, -ret,
						  RTE_FLOW_ERROR_TYPE_HANDLE,
						  rule,
						  "ntuple rule delete failed");
		break;
	case MCE_GENERIC_SYNC:
		ret = mce_generic_sync_setup(
			vport, handle,
			(struct mce_generic_sync_filter *)rule->engine_rule,
			MCE_FLOW_DEL);
		if (ret < 0)
			return rte_flow_error_set(error, -ret,
						  RTE_FLOW_ERROR_TYPE_HANDLE,
						  rule,
						  "sync filter deleta failed");
		break;
	default:
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_HANDLE, rule,
					  "rule is not support to setup");
		break;
	}
	rte_free(rule);
	flow->rule = NULL;

	return 0;
}

static int mce_generic_flow_engine_init(struct mce_vport *vport __rte_unused,
					void **handle)
{
	char ntuple_hash_name[RTE_HASH_NAMESIZE];
	char etype_hash_name[RTE_HASH_NAMESIZE];
	struct mce_generic_handle *tmp = 0;
	struct rte_hash_parameters ntuple_hash_params = {
		.name = ntuple_hash_name,
		.entries = vport->attr.max_ntuple_num <= 4 ? 8 : vport->attr.max_ntuple_num,
		.key_len = sizeof(struct mce_generic_ntuple_pattern),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
	};
	struct rte_hash_parameters etype_hash_params = {
		.name = etype_hash_name,
		.entries = MCE_MAX_ETYPE_NUM,
		.key_len = sizeof(struct mce_generic_ntuple_pattern),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
	};
	int ret = 0;

	tmp = rte_zmalloc(NULL, sizeof(struct mce_generic_handle), 0);
	if (tmp == NULL)
		return -ENOMEM;
	snprintf(ntuple_hash_name, RTE_HASH_NAMESIZE, "ntuple_%s",
		 vport->hw->device_name);
	snprintf(etype_hash_name, RTE_HASH_NAMESIZE, "etype_%s",
		 vport->hw->device_name);
	tmp->ntuple_hash_table = rte_hash_create(&ntuple_hash_params);
	if (!tmp->ntuple_hash_table) {
		PMD_INIT_LOG(ERR, "Failed to create ntuple hash table!");
		ret = -EINVAL;
		goto hash_create_failed;
	}
	tmp->etype_hash_table = rte_hash_create(&etype_hash_params);
	if (!tmp->etype_hash_table) {
		PMD_INIT_LOG(ERR, "Failed to create etype hash table!");
		ret = -EINVAL;
		goto hash_create_failed;
	}
	tmp->ntuple_hash_map = rte_zmalloc(
		"mce_ntuple_hash_map",
		sizeof(*tmp->ntuple_hash_map) * vport->attr.max_ntuple_num, 0);
	if (tmp->ntuple_hash_map == NULL) {
		PMD_INIT_LOG(ERR,
			     "Failed to allocate memory for ntuple hash map!");
		ret = -ENOMEM;
		goto hash_create_failed;
	}
	tmp->etype_hash_map = rte_zmalloc(
		"mce_etype_hash_map",
		sizeof(*tmp->etype_hash_map) * MCE_MAX_ETYPE_NUM, 0);
	if (!tmp->etype_hash_map) {
		PMD_INIT_LOG(ERR,
			     "Failed to allocate memory for etype hash map!");
		ret = -ENOMEM;
		goto hash_create_failed;
	}
	tmp->max_ntuple_rule = vport->attr.max_ntuple_num;
	tmp->max_etype_rule = MCE_MAX_ETYPE_NUM;
	ret = mce_bitmap_entry_alloc(&tmp->ntuple_map, "tuple_filter",
				     tmp->max_ntuple_rule);
	if (ret < 0)
		goto hash_create_failed;
	mce_entry_bitmap_init_range(&tmp->ntuple_map, 0, tmp->max_ntuple_rule);
	*handle = tmp;

	return 0;
hash_create_failed:
	/* this have sw bug */
	if (tmp->ntuple_hash_map) {
		rte_hash_free(tmp->ntuple_hash_table);
		rte_free(tmp->ntuple_hash_map);
	}
	if (tmp->etype_hash_map) {
		rte_hash_free(tmp->etype_hash_table);
		rte_free(tmp->etype_hash_map);
	}
	rte_free(tmp);
	return ret;
}

static int mce_generic_flow_engine_uinit(struct mce_vport *vport __rte_unused,
					 void *h)
{
	struct mce_generic_handle *handle = h;

	if (handle == NULL)
		return 0;
	if (handle->ntuple_hash_table)
		rte_hash_free(handle->ntuple_hash_table);
	if (handle->ntuple_hash_map)
		rte_free(handle->ntuple_hash_map);
	if (handle->etype_hash_table)
		rte_hash_free(handle->etype_hash_table);
	if (handle->etype_hash_map)
		rte_free(handle->etype_hash_map);
	rte_free(handle);

	return 0;
}

static void print_pattern(const struct mce_vf_ntuple_pattern *pattern) {
	printf("Pattern:\n");
	printf("  sip: 0x%08x (%u)\n", pattern->sip, pattern->sip);
	printf("  dip: 0x%08x (%u)\n", pattern->dip, pattern->dip);
	printf("  sport: %u\n", pattern->sport);
	printf("  dport: %u\n", pattern->dport);
	printf("  l4_type: %u\n", pattern->l4_type);
	printf("  is_ipv6: %s\n", pattern->is_ipv6 ? "true" : "false");
}

static void print_act(const struct mce_vf_ntuple_act *act) {
	printf("Action:\n");
	printf("  is_drop: %s\n", act->is_drop ? "true" : "false");
	printf("  redir_queue: %u\n", act->redir_queue);
	printf("  mark_id: %u\n", act->mark_id);
}

static void print_rule(const struct mce_vf_ntuple_rule *rule) {
	if (rule == NULL) {
		printf("Error: rule is NULL\n");
		return;
	}
	printf("=== mce_vf_ntuple_rule ===\n");
	print_pattern(&rule->pattern);
	print_act(&rule->act);
	printf("add: %s\n", rule->add ? "true" : "false");
	printf("===========================\n");
}

int mce_vf_add_ntuple(struct mce_pf *pf, int vfid, struct mce_vf_ntuple_rule *rule)
{
	print_rule(rule);
	struct mce_generic_handle *ntuple_handle = NULL;
	struct mce_generic_ntuple_filter *filter = NULL;
	struct mce_vf_info *vfinfo = &pf->vfinfos[vfid];
	struct mce_generic_ntuple_pattern lkup_pattern;
	struct mce_generic_ntuple_filter *tmp;
	int ret = 0;

	ntuple_handle = mce_get_engine_handle(pf->pf_vport, MCE_FLOW_GENERIC);
	if (ntuple_handle == NULL)
		return -ENODEV;
	memset(&lkup_pattern, 0, sizeof(lkup_pattern));
	lkup_pattern.src_addr = rule->pattern.sip;
	lkup_pattern.dst_addr = rule->pattern.dip;
	lkup_pattern.protocol = rule->pattern.l4_type;
	lkup_pattern.l4_sport = rule->pattern.sport;
	lkup_pattern.l4_dport = rule->pattern.dport;
	lkup_pattern.is_ipv6 = rule->pattern.is_ipv6;
	lkup_pattern.vport_id = vfid;
	tmp = mce_ntuple_entry_lookup(ntuple_handle, &lkup_pattern);
	if (tmp != NULL)
		return -EEXIST;
	if (vfinfo->cur_ntuple_cnt + 1 > vfinfo->max_ntuple)
		return -ENOMEM;
	filter = rte_zmalloc(NULL, sizeof(*filter), 0);
	if (filter == NULL)
		return -ENOMEM;
	filter->lkup_pattern = lkup_pattern;
	if (rule->act.is_drop) {
		filter->actions.rule_action = MCE_FILTER_DROP;
	} else {
		filter->actions.redirect_en = 1;
		filter->actions.redir.index = rule->act.redir_queue;
		if (rule->act.mark_id) {
			filter->actions.mark_en = 1;
			filter->actions.mark.id= rule->act.mark_id;
		}
	}
	filter->options |= (filter->lkup_pattern.src_addr ? MCE_OPT_OUT_IPV4_SIP : 0);
	filter->options |= (filter->lkup_pattern.dst_addr ? MCE_OPT_OUT_IPV4_DIP : 0);
	filter->options |= (filter->lkup_pattern.protocol ? MCE_OPT_L4_PROTO : 0);
	filter->options |= (filter->lkup_pattern.l4_sport ? MCE_OPT_L4_SPORT : 0);
	filter->options |= (filter->lkup_pattern.l4_dport ? MCE_OPT_L4_DPORT : 0);
	ret = mce_generic_ntuple_setup(pf->pf_vport, ntuple_handle, filter, 1);
	if (ret < 0)
		rte_free(filter);
	vfinfo->cur_ntuple_cnt++;

	return ret;
}

int mce_vf_del_ntuple(struct mce_pf *pf, int vfid, struct mce_vf_ntuple_rule *rule)
{
	struct mce_generic_handle *ntuple_handle = NULL;
	struct mce_vf_info *vfinfo = &pf->vfinfos[vfid];
	struct mce_generic_ntuple_filter *filter = NULL;
	struct mce_generic_ntuple_pattern lkup_pattern;
	int err = 0;

	memset(&lkup_pattern, 0, sizeof(lkup_pattern));
	lkup_pattern.src_addr = rule->pattern.sip;
        lkup_pattern.dst_addr = rule->pattern.dip;
        lkup_pattern.protocol = rule->pattern.l4_type;
        lkup_pattern.l4_sport = rule->pattern.sport;
        lkup_pattern.l4_dport = rule->pattern.dport;
        lkup_pattern.is_ipv6 = rule->pattern.is_ipv6;
	lkup_pattern.vport_id = vfid;

	ntuple_handle = mce_get_engine_handle(pf->pf_vport, MCE_FLOW_GENERIC);
	if (ntuple_handle == NULL)
		return -ENODEV;
	filter = mce_ntuple_entry_lookup(ntuple_handle, &lkup_pattern);
	if (filter == NULL)
		return -EIDRM;
	err = mce_generic_ntuple_setup(pf->pf_vport, ntuple_handle, filter, 0);
	if (err < 0)
		return err;
	vfinfo->cur_ntuple_cnt--;

	return 0;
}

struct mce_flow_engine_module mce_generic_engine = {
	.parse = mce_generic_flow_parse,
	.create = mce_generic_flow_create,
	.destroy = mce_generic_flow_delate,
	.init = mce_generic_flow_engine_init,
	.uinit = mce_generic_flow_engine_uinit,
	.name = "mce_generic_flow",
	.type = MCE_FLOW_GENERIC,
};
