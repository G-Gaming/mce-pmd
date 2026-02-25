/**
 * @file mce_switch.c
 * @brief Hardware switch and Virtual Ethernet Bridge (VEB) implementation
 *
 * Implements hardware switch management and VEB (Virtual Ethernet Bridge)
 * operations for port and VF isolation and bridging:
 * - VEB mode configuration (switching between ports and VFs)
 * - MAC/VLAN based switching decisions
 * - Port mirroring and replication
 * - Switch table management
 * - MAC learning and aging
 * - Broadcast/multicast replication policies
 *
 * VEB Modes:
 * - Switching: Packets switched between ports based on MAC lookup
 * - Bridging: Ports connected as virtual bridge members
 * - Filtering: MAC/VLAN filtering per port/VF
 *
 * @see mce_switch.h for public API
 * @see mce_l2_filter.c for MAC/VLAN filtering
 */

#include <stdio.h>
#include <assert.h>

#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_tailq.h>

#include "mce_osdep.h"
#include "mce_bitops.h"
#include "mce_switch.h"
#include "mce_eth_regs.h"

#include "../mce.h"
#include "../mce_logs.h"
#include "../mce_pattern.h"

/**
 * @brief Initialize switch bitmap resources.
 *
 * Allocate and initialize internal bitmaps used to track action,
 * legend and eswitch table entries for the switch handle.
 *
 * @param handle Pointer to the switch handle to initialize
 * @return 0 on success, negative errno on failure
 */
int mce_switch_bitmap_init(struct mce_switch_handle *handle)
{
	u16 max_bit = 0;
	int ret = 0;

	max_bit = handle->max_action_entry;
	ret = mce_bitmap_entry_alloc(&handle->bitmap_entry[MCE_ACTION_LOC_BITMAP],
		"mce_action_entry", max_bit);
	if (ret)
		return ret;
	max_bit = handle->max_legend_rule + handle->max_eswitch_rule;
	ret = mce_bitmap_entry_alloc(&handle->bitmap_entry[MCE_LEGENCY_BITMAP],
				     "mce_legend_rule", max_bit);
	if (ret)
		return ret;
	max_bit = handle->max_eswitch_rule;
	ret = mce_bitmap_entry_alloc(&handle->bitmap_entry[MCE_ESWITCH_BTMAP],
				     "mce_ewsitch_rule", max_bit);

	/* init bitmap entry */
	mce_entry_bitmap_init_range(
		&handle->bitmap_entry[MCE_ACTION_LOC_BITMAP], 128,
		handle->max_action_entry);

	mce_entry_bitmap_init_range(&handle->bitmap_entry[MCE_ESWITCH_BTMAP], 0,
				    handle->max_eswitch_rule);
	mce_entry_bitmap_init_range(
		&handle->bitmap_entry[MCE_LEGENCY_BITMAP], 128,
		handle->max_legend_rule + handle->max_eswitch_rule);

	return ret;
}

/**
 * @brief Insert a filter into the switch hash-map.
 *
 * Adds the provided filter to the handle's hash table and stores a
 * reference in the hash_map array for quick retrieval.
 *
 * @param handle Pointer to the switch handle
 * @param filter Filter to insert
 * @return 0 on success, negative errno on failure
 */
int mce_switch_insert_hash_map(struct mce_switch_handle *handle,
			   struct mce_switch_filter *filter)
{
	struct mce_switch_filter **hash_map = NULL;
	struct rte_hash *hash_handle = NULL;
	int ret;

	hash_handle = handle->filter_hash_handle;
	hash_map = handle->filter_hash_map;
	ret = rte_hash_add_key(hash_handle, &filter->lkup_pattern);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to insert switch entry to hash table %d!",
			    ret);
		return ret;
	}
	hash_map[ret] = filter;

	return 0;
}

/**
 * @brief Remove a filter from the switch hash-map.
 *
 * Deletes the key from the hash table and clears the corresponding
 * slot in the hash_map array.
 *
 * @param handle Pointer to the switch handle
 * @param filter Filter to remove
 * @return 0 on success, negative errno on failure
 */
int mce_switch_remove_hash_map(struct mce_switch_handle *handle,
			   struct mce_switch_filter *filter)
{
	struct mce_switch_filter **hash_map = NULL;
	struct rte_hash *hash_handle = NULL;
	int ret;

	hash_handle = handle->filter_hash_handle;
	hash_map = handle->filter_hash_map;
	ret = rte_hash_del_key(hash_handle, &filter->lkup_pattern);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to delete fdir filter to hash table %d!",
			    ret);
		return ret;
	}
	hash_map[ret] = NULL;

	return 0;
}

/**
 * @brief Lookup a switch filter entry by pattern.
 *
 * Perform a hash table lookup for the provided pattern and return
 * the corresponding filter entry if present.
 *
 * @param handle Pointer to the switch handle
 * @param lkup_pattern Pattern to lookup
 * @return Pointer to matching filter or NULL if not found
 */
struct mce_switch_filter *
mce_switch_entry_lookup(struct mce_switch_handle *handle,
		   struct mce_switch_pattern *lkup_pattern)
{
	struct mce_switch_filter **hash_map = NULL;
	struct rte_hash *hash_handle = NULL;
	int ret;

	hash_handle = handle->filter_hash_handle;
	hash_map = handle->filter_hash_map;

	ret = rte_hash_lookup(hash_handle, lkup_pattern);
	if (ret < 0)
		return NULL;
	return hash_map[ret];
}

/**
 * @brief Flush (program or clear) an eswitch filter entry to HW.
 *
 * Program or remove a VM/eswitch NTUPLE rule according to the node
 * parameters.
 *
 * @param hw Pointer to MCE hardware context
 * @param node Switch node describing the rule and action
 * @param add True to program the rule, false to clear it
 * @return 0 on success, negative errno on failure
 */
static int mce_flush_eswitch_filter(struct mce_hw *hw,
				   struct mce_switch_node *node, bool add)
{
	struct mce_switch_params *params = &node->params;
	struct mce_switch_pattern *lkup_pattern = &params->lkup_pattern;
	u8 *mac = (u8 *)&lkup_pattern->formatted.dst_mac;
	u64 options = node->filter.options;
	u16 action_loc = node->action_loc;
	u16 rule_loc = node->rule_loc;
	u32 sip = 0, dip = 0;
	u32 act_ctrl = 0;
	u32 tun_key = 0;
	u32 mac_lo = 0;
	u32 mac_hi = 0;
	u16 l4_proto;
	u16 rank = 0;
	u32 ctrl = 0;
	u32 l4_port;
	u32 vid = 0;

	if (add) {
		sip = lkup_pattern->formatted.src_addr;
		dip = lkup_pattern->formatted.dst_addr;
		l4_proto = lkup_pattern->formatted.protocol;
		l4_port = lkup_pattern->formatted.l4_sport << 16;
		l4_port |= lkup_pattern->formatted.l4_dport;
		MCE_E_REG_WRITE(hw, MCE_SW_VM_SIP(rule_loc), sip);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DIP(rule_loc), dip);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_L4PORT(rule_loc), l4_port);
		if (options & MCE_OPT_L4_SPORT)
			ctrl |= MCE_VM_L4SP_VALID;
		if (options & MCE_OPT_L4_DPORT)
			ctrl |= MCE_VM_L4DP_VALID;
		if ((options & (MCE_OPT_OUT_IPV4_SIP | MCE_OPT_IPV4_SIP)))
			ctrl |= MCE_VM_SIP_VALID;
		if ((options & (MCE_OPT_OUT_IPV4_DIP | MCE_OPT_IPV4_DIP)))
			ctrl |= MCE_VM_DIP_VALID;
		if (options & MCE_OPT_L4_PROTO) {
			ctrl |= MCE_VM_L3TYPE_VALID;
			ctrl |= l4_proto & MCE_VM_L3TYPE_MASK;
		}
		if (dip == 0 && sip == 0 && lkup_pattern->formatted.is_ipv6) {
			ctrl |= MCE_VM_L2TYPE_VALID;
			ctrl |= RTE_ETHER_TYPE_IPV6 << MCE_VM_L2TYPE_SHIFT;
		} else if (options & MCE_OPT_ETHTYPE) {
			ctrl |= MCE_VM_L2TYPE_VALID;
			ctrl |= lkup_pattern->formatted.ether_type
				<< MCE_VM_L2TYPE_SHIFT;
		}
		printf("rule_loc %d\n", rule_loc);
		/* setup switch ntuple rule ctrl */
		MCE_E_REG_WRITE(hw, MCE_SW_VM_NTUPLE_CTRL(rule_loc), ctrl);
		ctrl = 0;
		if (options & MCE_OPT_DMAC) {
			mac_lo = (mac[2] << 24) | (mac[3] << 16) |
				 (mac[4] << 8) | mac[5];
			mac_hi = (mac[0] << 8) | mac[1];
			MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAH(rule_loc),
					mac_hi);
			MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAL(rule_loc),
					mac_lo);
			ctrl |= MCE_SW_VM_MAC_EN;
		}
		if (options & MCE_OPT_S_VPORT_ID) {
			ctrl |= MCE_SW_VM_S_VPID_EN;
			ctrl |= lkup_pattern->formatted.s_vport;
			printf("transfor port %d\n",
			       lkup_pattern->formatted.s_vport);
			printf("ctrl 0x%.2x\n", ctrl);
		}
		if (options & MCE_TUNNEL_OPT) {
			switch (options & MCE_TUNNEL_OPT) {
			case MCE_OPT_VXLAN_VNI:
				ctrl |= MCE_SW_VM_TUN_VXLAN
					<< MCE_SW_VM_TUN_TYPE_S;
				tun_key = lkup_pattern->formatted.vni;
				break;
			case MCE_OPT_GENEVE_VNI:
				ctrl |= MCE_SW_VM_TUN_GENEVE
					<< MCE_SW_VM_TUN_TYPE_S;
				tun_key = lkup_pattern->formatted.vni;
				break;
			case MCE_OPT_NVGRE_TNI:
				ctrl |= MCE_SW_VM_TUN_GRE
					<< MCE_SW_VM_TUN_TYPE_S;
				tun_key = lkup_pattern->formatted.tni >> 8;
				break;
			case MCE_OPT_GTP_U_TEID:
				ctrl |= MCE_SW_VM_TUN_GTP_U
					<< MCE_SW_VM_TUN_TYPE_S;
				tun_key = lkup_pattern->formatted.teid;
				break;
			case MCE_OPT_GTP_C_TEID:
				ctrl |= MCE_SW_VM_TUN_GTP_C
					<< MCE_SW_VM_TUN_TYPE_S;
				tun_key = lkup_pattern->formatted.teid;
				break;
			}
			MCE_E_REG_WRITE(hw, MCE_SW_VM_TUN_KEY(rule_loc),
					tun_key);
			ctrl |= MCE_SW_VM_TUN_EN;
		}
		if (options & MCE_OPT_VLAN_VID) {
			vid = lkup_pattern->formatted.vlan_id;
			MCE_E_REG_WRITE(hw, MCE_SW_VM_VLAN(rule_loc), vid);
			ctrl |= MCE_SW_VM_VID_EN;
		}
		printf("rule_loc %d action_loc %d\n", rule_loc, action_loc);
		printf("node->filter.vport_id %d\n", node->filter.vport_id);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_CTRL(rule_loc), ctrl);
		if (params->drop_en) {
			act_ctrl = MCE_SW_VM_ACT_DROP_DB << MCE_SW_VM_ACT_DB_S;
			MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc),
					act_ctrl);
		} else {
			if (node->filter.vport_id == 128) {
				/* down to uplink port to mac */
				MCE_E_REG_WRITE(
					hw, MCE_SW_VM_ACT_CTRL(rule_loc), 0x20);
				printf("uplink port set rule 0ffset 0x%.2x\n",
				       MCE_SW_VM_ACT_CTRL(rule_loc));
			} else {
				act_ctrl = action_loc << MCE_SW_VM_ACT_DB_S;
				MCE_E_REG_WRITE(hw,
						MCE_SW_VM_ACT_CTRL(rule_loc),
						act_ctrl);
				printf("setup MCE_SW_VM_ACT_CTRL offset "
				       "0x%.2x\n",
				       MCE_SW_VM_ACT_CTRL(rule_loc));
				if (node->domain == NULL) {
					rank = node->filter.vport_id / 32;
					ctrl = MCE_E_REG_READ(
						hw, MCE_SW_VM_ACT_DB_BTMAP(
							    rank, action_loc));
					ctrl |= RTE_BIT32(
						node->filter.vport_id % 32);
					printf("MCE_SW_VM_ACT_DB_BTMAP "
					       "offset 0x%.2x\n",
					       MCE_SW_VM_ACT_DB_BTMAP(
						       rank, action_loc));
					MCE_E_REG_WRITE(hw,
							MCE_SW_VM_ACT_DB_BTMAP(
								rank,
								action_loc),
							ctrl);
				}
			}
		}
	} else {
		MCE_E_REG_WRITE(hw, MCE_SW_VM_NTUPLE_CTRL(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_L4PORT(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_SIP(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DIP(rule_loc), 0);

		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAH(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAL(rule_loc), 0);

		MCE_E_REG_WRITE(hw, MCE_SW_VM_CTRL(rule_loc), 0);
		if (node->domain == NULL) {
			rank = node->filter.vport_id / 32;
			ctrl = MCE_E_REG_READ(
				hw, MCE_SW_VM_ACT_DB_BTMAP(rank, action_loc));
			ctrl &= ~RTE_BIT32(node->filter.vport_id % 32);
			MCE_E_REG_WRITE(
				hw, MCE_SW_VM_ACT_DB_BTMAP(rank, action_loc),
				ctrl);
		}
	}

	return 0;
}

/**
 * @brief Flush MAC+VLAN switch action into hardware registers.
 *
 * Program or clear the hardware MAC/VLAN action entries for the
 * provided switch node.
 *
 * @param hw Pointer to MCE hardware context
 * @param node Switch node describing MAC/VLAN action
 * @param add True to program, false to clear
 */
static void mce_sw_flush_hw_macvlan(struct mce_hw *hw,
				   struct mce_switch_node *node, bool add)
{
	struct mce_switch_params *params = &node->params;
	u8 *mac = params->lkup_pattern.formatted.dst_mac;
	u16 action_loc = node->action_loc;
	u16 rule_loc = node->rule_loc;
	u32 act_ctrl = 0;
	u32 vp_bit = 0;
	u16 rank = 0;
	u32 ctrl = 0;
	u32 act = 0;
	u32 mac_hi;
	u16 vid = 0;
	u32 mac_lo;

	if (add) {
		if (params->options & MCE_OPT_DMAC) {
			ctrl |= MCE_SW_VM_MAC_EN;
			mac_lo = (mac[2] << 24) | (mac[3] << 16) |
				 (mac[4] << 8) | mac[5];
			mac_hi = (mac[0] << 8) | mac[1];
			MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAH(rule_loc),
					mac_hi);
			MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAL(rule_loc),
					mac_lo);
		}
		if (params->options & MCE_OPT_VLAN_VID) {
			vid = params->lkup_pattern.formatted.vlan_id;
			ctrl |= MCE_SW_VM_VID_EN;
			MCE_E_REG_WRITE(hw, MCE_SW_VM_VLAN(rule_loc), vid);
		}
		if (params->options & MCE_OPT_S_VPORT_ID) {
			ctrl |= MCE_SW_VM_S_VPID_EN;
			ctrl |= params->lkup_pattern.formatted.s_vport;
			printf("transfor port %d\n",
			       params->lkup_pattern.formatted.s_vport);
		}
		MCE_E_REG_WRITE(hw, MCE_SW_VM_CTRL(rule_loc), ctrl);
		if (params->drop_en) {
			MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc),
					MCE_SW_VM_ACT_DROP_DB
						<< MCE_SW_VM_ACT_DB_S);
			printf("flush hw macvlan rule[%d] to register to drop",
			       rule_loc);

			return;
		}
		if (node->filter.vport_id == 128) {
			/* down to uplink port to mac */
			MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc), 0x20);
		} else {
			act_ctrl = action_loc << MCE_SW_VM_ACT_DB_S;
			MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc),
					act_ctrl);
			/* update vport bitmap */
			rank = node->filter.vport_id / 32;

			act = MCE_E_REG_READ(
				hw, MCE_SW_VM_ACT_DB_BTMAP(rank, action_loc));
			vp_bit = node->filter.vport_id % 32;
			act |= RTE_BIT32(vp_bit);
			MCE_E_REG_WRITE(
				hw, MCE_SW_VM_ACT_DB_BTMAP(rank, action_loc),
				act);
		}
	} else {
		MCE_E_REG_WRITE(hw, MCE_SW_VM_CTRL(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAH(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAL(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_VLAN(rule_loc), 0);

		MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc), 0);

		/* update vport bitmap */
		rank = node->filter.vport_id / 32;
		act = MCE_E_REG_READ(hw,
				     MCE_SW_VM_ACT_DB_BTMAP(rank, action_loc));
		vp_bit = node->filter.vport_id % 32;
		act &= ~RTE_BIT32(vp_bit);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_DB_BTMAP(rank, action_loc),
				act);
	}

	printf("flush hw macvlan rule[%d] to register op %d action_loc %d\n",
	       rule_loc, add, action_loc);
}

/**
 * @brief Add a MAC+VLAN filter by programming hardware entries.
 *
 * Wrapper that flushes the MAC/VLAN configuration into hardware.
 *
 * @param hw Pointer to MCE hardware context
 * @param node Switch node representing the filter
 * @return 0 on success, negative errno on failure
 */
static int mce_sw_add_macvlan_filter(struct mce_hw *hw,
					struct mce_switch_node *node)
{
	mce_sw_flush_hw_macvlan(hw, node, 1);

	return 0;
}

static int mce_sw_remove_macvlan_filter(struct mce_hw *hw,
					struct mce_switch_node *node)
{
	mce_sw_flush_hw_macvlan(hw, node, 0);

	return 0;
}

static struct mce_switch_node *
mce_find_switch_node(struct mce_switch_handle *handle,
		     struct mce_switch_filter *filter)
{
	struct mce_sw_rule_aggregate *list = NULL;
	struct mce_switch_node *node = NULL;
	void *temp_list = NULL;
	void *temp_node = NULL;
	if (filter == NULL || handle == NULL)
		return NULL;
	RTE_TAILQ_FOREACH_SAFE(list, &handle->sw_aggregate, entry, temp_list) {
		if (list->type != filter->rule_type)
			continue;
		RTE_TAILQ_FOREACH_SAFE(node, &list->node_list, entry, temp_node) {
			if (!memcmp(&node->params.lkup_pattern.formatted,
				    &filter->lkup_pattern.formatted,
				    sizeof(filter->lkup_pattern.formatted)))
				return node;
		}
	}

	return node;
}

static struct mce_broadcast_domain_node *
mce_sw_get_untag_domain(struct mce_switch_handle *handle)
{
	struct mce_broadcast_domain_node *domain = NULL;
	void *temp = NULL;

	RTE_TAILQ_FOREACH_SAFE(domain, &handle->bc_domain_list, entry, temp) {
		if (domain->type == MCE_LPBK_BC_MAC)
			return domain;
	}

	return NULL;
}

static struct mce_broadcast_domain_node *
mce_sw_get_vlan_domain(struct mce_switch_handle *handle,
		       struct mce_switch_filter *filter)
{
	struct mce_broadcast_domain_node *domain = NULL;
	uint64_t switch_key = 0;
	void *temp = NULL;

	switch_key = filter->lkup_pattern.formatted.vlan_id;
	RTE_TAILQ_FOREACH_SAFE(domain, &handle->bc_domain_list, entry, temp) {
		if (domain->type == MCE_LPBK_BC_VLAN &&
		    domain->switch_key == switch_key)
			return domain;
	}

	return NULL;
}

static struct mce_broadcast_domain_node *
mce_sw_get_macvlan_domain(struct mce_switch_handle *handle,
			  struct mce_switch_filter *filter)
{
	struct mce_broadcast_domain_node *domain = NULL;
	void *temp = NULL;

	RTE_TAILQ_FOREACH_SAFE(domain, &handle->bc_domain_list, entry, temp) {
		if (domain->type == MCE_LPBK_BC_MACVLAN &&
		    domain->switch_key == filter->switch_key)
			return domain;
	}

	return NULL;
}

static struct mce_switch_node *
mce_alloc_switch_node(struct mce_switch_handle *handle,
		      struct mce_switch_filter *filter)
{
	struct mce_bitmap_entry *act_entry = NULL;
	struct mce_bitmap_entry *entry = NULL;
	struct mce_switch_node *node = NULL;

	int ret = 0;

	node = rte_zmalloc(NULL, sizeof(*node), 0);
	if (node == NULL)
		return NULL;
	if (filter->rule_type == MCE_SW_OF_ESWITCH)
		entry = &handle->bitmap_entry[MCE_ESWITCH_BTMAP];
	else
		entry = &handle->bitmap_entry[MCE_LEGENCY_BITMAP];
	act_entry = &handle->bitmap_entry[MCE_ACTION_LOC_BITMAP];

	node->params.lkup_pattern = filter->lkup_pattern;
	node->params.redir_port = filter->redir_port;
	node->params.drop_en = filter->drop_en;
	node->params.options = filter->options;
	node->rule_type = filter->rule_type;
	node->action = filter->action;
	node->reference_count = 1;
	node->filter = *filter;

	ret = mce_get_valid_location(entry, &node->rule_loc);
	if (ret)
		goto rule_loc_failed;
	if (filter->loc_user_def == 0) {
		ret = mce_get_valid_location(act_entry, &node->action_loc);
		if (ret < 0)
			return NULL;
		mce_set_used_location(act_entry, node->action_loc);
	} else {
		node->action_loc = filter->user_loc;
	}
	filter->rule_loc = node->rule_loc;
	mce_set_used_location(entry, node->rule_loc);
	mce_set_used_location(act_entry, node->action_loc);

	return node;

rule_loc_failed:
	rte_free(node);
	return NULL;
}

static int mce_destory_switch_node(struct mce_switch_handle *handle,
				   struct mce_switch_node *node)
{
	struct mce_bitmap_entry *action_entry =
		&handle->bitmap_entry[MCE_ACTION_LOC_BITMAP];

	if (node->filter.loc_user_def == 0) {
		printf("node->action_loc free 0x%.2x\n", node->action_loc);
		mce_free_used_location(action_entry, node->action_loc);
	}
	if (node->rule_type == MCE_SW_OF_ESWITCH)
		mce_free_used_location(&handle->bitmap_entry[2],
				       node->rule_loc);
	else
		mce_free_used_location(&handle->bitmap_entry[1],
				       node->rule_loc);
	rte_free(node);

	return 0;
}

static struct mce_sw_rule_aggregate *
mce_sw_rule_aggregate_alloc(struct mce_switch_handle *handle,
			    struct mce_switch_filter *filter)
{
	struct mce_sw_rule_aggregate *new = NULL;

	new = rte_zmalloc(NULL, sizeof(*new), 0);
	if (new == NULL)
		return NULL;
	new->type = filter->rule_type;
	new->pattern_cnt = rte_popcount64(filter->options);
	new->options = filter->options;
	new->member_num = 0;
	switch (new->type) {
	case MCE_SW_OF_MAC:
	case MCE_SW_OF_VLAN:
	case MCE_SW_OF_MACVLAN:
	case MCE_SW_OF_ESWITCH:
		new->key = filter->switch_key;
		break;
	default:
		new->pattern_cnt = 0;
		new->key = 0;
		break;
	}
	TAILQ_INIT(&new->node_list);
	TAILQ_INSERT_TAIL(&handle->sw_aggregate, new, entry);

	return new;
}

static int
mce_sw_rule_aggregate_destory(struct mce_switch_handle *handle,
			      struct mce_sw_rule_aggregate *rule_list)
{
	TAILQ_REMOVE(&handle->sw_aggregate, rule_list, entry);
	memset(rule_list, 0, sizeof(*rule_list));
	rte_free(rule_list);
	rule_list = NULL;

	return 0;
}

static struct mce_broadcast_domain_node *
mce_alloc_domain_entry(struct mce_hw *hw, struct mce_switch_handle *handle,
		       struct mce_switch_filter *filter)
{
	struct mce_broadcast_domain_node *domain = NULL;
	struct mce_bitmap_entry *rule_entry = NULL;
	struct mce_bitmap_entry *act_entry = NULL;
	uint64_t switch_key = 0;
	uint16_t action_loc = 0;
	uint16_t rule_loc = 0;
	char name[128] = "";
	int ret = 0;

	if (filter->rule_type == MCE_SW_OF_ESWITCH)
		rule_entry = &handle->bitmap_entry[MCE_ESWITCH_BTMAP];
	else
		rule_entry = &handle->bitmap_entry[MCE_LEGENCY_BITMAP];
	act_entry = &handle->bitmap_entry[MCE_ACTION_LOC_BITMAP];
	ret = mce_get_valid_location(act_entry, &action_loc);
	if (ret < 0)
		return NULL;
	ret = mce_get_valid_location(rule_entry, &rule_loc);
	if (ret < 0)
		return NULL;
	domain = rte_zmalloc(NULL, sizeof(*domain), 0);
	if (domain == NULL)
		return NULL;
	snprintf(name, 128, "vport_map_loc_%d", action_loc);
	ret = mce_bitmap_entry_alloc(&domain->vport_map, name, 128);
	if (ret < 0)
		return NULL;
	domain->switch_key = switch_key;
	switch (filter->rule_type) {
	case MCE_SW_OF_MAC:
		domain->type = MCE_LPBK_BC_MAC;
		break;
	case MCE_SW_OF_VLAN:
		domain->type = MCE_LPBK_BC_VLAN;
		break;
	case MCE_SW_OF_MACVLAN:
		domain->type = MCE_LPBK_BC_MACVLAN;
		break;
	case MCE_SW_OF_VXLAN:
		domain->type = MCE_LPBK_BC_VXLAN;
		break;
	default:
		break;
	}
	/* todo add a function */
	u8 mac_addr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	u8 *mac = mac_addr;
	u32 mac_lo, mac_hi;
	u32 filter_ctrl = 0;
	u32 act_ctrl = 0;
	u32 ctrl = 0;
	u32 vid = 0;

	if (filter->options & MCE_OPT_DMAC) {
		ctrl |= MCE_SW_VM_MAC_EN;
		mac_lo = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) |
			 mac[5];
		mac_hi = (mac[0] << 8) | mac[1];
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAH(rule_loc), mac_hi);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAL(rule_loc), mac_lo);

		filter_ctrl = MCE_E_REG_READ(hw, MCE_ETH_GLOBAL_L2_EX_F_CTRL);
		filter_ctrl |= MCE_G_MCAST_CVERT_TO_BCAST;
		MCE_E_REG_WRITE(hw, MCE_ETH_GLOBAL_L2_EX_F_CTRL, filter_ctrl);

		filter_ctrl = MCE_E_REG_READ(hw, MCE_ETH_RQA_CTRL);
		filter_ctrl |= MCE_RQA_MULTICAST_F_EN;
		MCE_E_REG_WRITE(hw, MCE_ETH_RQA_CTRL, filter_ctrl);
	}
	if (filter->options & MCE_OPT_VLAN_VID) {
		vid = filter->lkup_pattern.formatted.vlan_id;
		ctrl |= MCE_SW_VM_VID_EN;
		MCE_E_REG_WRITE(hw, MCE_SW_VM_VLAN(rule_loc), vid);
	}
	MCE_E_REG_WRITE(hw, MCE_SW_VM_CTRL(rule_loc), ctrl);
	act_ctrl = action_loc << MCE_SW_VM_ACT_DB_S;
	MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc), act_ctrl);

	domain->options = filter->options;
	domain->rule_loc = rule_loc;
	domain->action_loc = action_loc;
	TAILQ_INSERT_TAIL(&handle->bc_domain_list, domain, entry);

	mce_set_used_location(rule_entry, rule_loc);
	mce_set_used_location(act_entry, action_loc);

	return domain;
}

static void
mce_sw_destory_domain_entry(struct mce_switch_handle *handle, struct mce_hw *hw,
			    struct mce_broadcast_domain_node *domain)
{
	uint16_t action_loc = domain->rule_loc;
	uint16_t rule_loc = domain->action_loc;

	if (domain->options & MCE_OPT_DMAC) {
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAH(rule_loc), 0);
		MCE_E_REG_WRITE(hw, MCE_SW_VM_DMAC_RAL(rule_loc), 0);
	}
	if (domain->options & MCE_OPT_VLAN_VID)
		MCE_E_REG_WRITE(hw, MCE_SW_VM_VLAN(rule_loc), 0);
	MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc), 0);
	MCE_E_REG_WRITE(hw, MCE_SW_VM_CTRL(rule_loc), 0);

	rte_bitmap_set(handle->bitmap_entry[0].bitmap, action_loc);
	rte_bitmap_set(handle->bitmap_entry[1].bitmap, rule_loc);
	TAILQ_REMOVE(&handle->bc_domain_list, domain, entry);

	rte_free(domain->vport_map.bitmap_mem);
	rte_free(domain);
}

static int mce_sw_add_domain_entry(struct mce_broadcast_domain_node *domain,
				   struct mce_switch_filter *filter)
{
	rte_bitmap_set(domain->vport_map.bitmap, filter->vport_id);
	domain->reference_count++;

	return 0;
}

static int mce_sw_del_domain_entry(struct mce_broadcast_domain_node *domain,
				   struct mce_switch_filter *filter)
{
	rte_bitmap_clear(domain->vport_map.bitmap, filter->vport_id);
	domain->reference_count--;

	return 0;
}

static void mce_sw_update_domain_entry(struct mce_hw *hw,
				       struct mce_broadcast_domain_node *domain)
{
	u32 *bitmem = NULL;
	u32 loc = 0;
	u16 i = 0;

	loc = domain->action_loc;
	bitmem = domain->vport_map.mem_store;
	printf("broadcast domain_entry type %d update bitmap\n", domain->type);
	for (i = 0; i < 4; i++) {
		printf("bitmap[%d] loc %d => 0x%.2x\n", i, loc, bitmem[i]);
		MCE_E_REG_WRITE(hw, MCE_BITMAP_DB(i, loc), bitmem[i]);
	}
}

static struct mce_sw_rule_aggregate *
mce_sw_get_aggregate(struct mce_switch_handle *handle,
		     struct mce_switch_filter *filter)
{
	struct mce_sw_rule_aggregate *it = NULL;
	void *temp = NULL;

	RTE_TAILQ_FOREACH_SAFE(it, &handle->sw_aggregate, entry, temp) {
		if (it->type == filter->rule_type &&
		    it->key == filter->switch_key &&
		    it->pattern_cnt == rte_popcount64(filter->options))
			return it;
	}

	return NULL;
}

static struct mce_switch_mirror_vport *
mce_alloc_mirror_entry(struct mce_switch_node *node,
		       struct mce_switch_filter *new)
{
	struct mce_switch_mirror_vport *list = NULL;
	struct mce_switch_filter *old = &node->filter;
	char name[128] = "";
	int ret = 0;

	if (new->vport_id == old->vport_id)
		return NULL;
	list = rte_zmalloc(NULL, sizeof(*list), 0);
	if (list == NULL)
		return NULL;
	list->action_loc = node->action_loc;
	list->rule_loc = node->rule_loc;

	snprintf(name, 128, "vport_map_loc_%d", list->action_loc);
	ret = mce_bitmap_entry_alloc(&list->vport_map, name, 128);
	if (ret < 0)
		return NULL;
	rte_bitmap_set(list->vport_map.bitmap, new->vport_id);
	rte_bitmap_set(list->vport_map.bitmap, old->vport_id);
	list->reference_count = 2;
	node->action = MCE_SW_TO_VPORTS;

	return list;
}

static int mce_add_mirror_list_entry(struct mce_switch_mirror_vport *list,
				     struct mce_switch_filter *filter)
{
	if (rte_bitmap_get(list->vport_map.bitmap, filter->vport_id))
		return -EINVAL;
	rte_bitmap_set(list->vport_map.bitmap, filter->vport_id);
	list->reference_count++;

	return 0;
}

static int mce_del_mirror_list_entry(struct mce_switch_mirror_vport *list,
				     struct mce_switch_filter *filter)
{
	if (rte_bitmap_get(list->vport_map.bitmap, filter->vport_id) == 0)
		return -EINVAL;
	rte_bitmap_clear(list->vport_map.bitmap, filter->vport_id);
	list->reference_count--;

	return 0;
}

static void
mce_sw_update_mirror_entry(struct mce_hw *hw,
			   struct mce_switch_mirror_vport *vport_list)
{
	u32 *bitmem = NULL;
	u32 loc = 0;
	u16 i = 0;

	loc = vport_list->action_loc;
	bitmem = vport_list->vport_map.mem_store;
	for (i = 0; i < 4; i++) {
		printf("bitmap[%d] loc %d => 0x%.2x\n", i, loc, bitmem[i]);
		MCE_E_REG_WRITE(hw, MCE_BITMAP_DB(i, loc), bitmem[i]);
	}
}

static void mce_sw_destory_mirror_list(struct mce_switch_mirror_vport *list)
{
	rte_free(list->vport_map.bitmap_mem);
	rte_free(list);
}

static bool mce_sw_support_tun_brocast(struct mce_switch_filter *filter)
{
	switch (filter->rule_type) {
	case MCE_SW_OF_MAC:
	case MCE_SW_OF_VLAN:
	case MCE_SW_OF_MACVLAN:
	case MCE_SW_OF_VXLAN:
	case MCE_SW_OF_VXLAN_VLAN:
	case MCE_SW_OF_NVGRE:
	case MCE_SW_OF_NVGRE_VLAN:
	case MCE_SW_OF_GENEVE:
	case MCE_SW_OF_GENEVE_VLAN:
	case MCE_SW_OF_GTPU:
	case MCE_SW_OF_GTPU_VLAN:
	case MCE_SW_OF_GTPC:
	case MCE_SW_OF_GTPC_VLAN:
		return true;
	default:
		return false;
	}
}

static int mce_sw_add_mirror_list(struct mce_hw *hw,
				  struct mce_switch_node *node,
				  struct mce_switch_filter *filter)
{
	int ret = 0;

	filter->action = MCE_SW_TO_VPORTS;
	if (node->reference_count == 1 && node->vport_list == NULL) {
		node->vport_list = mce_alloc_mirror_entry(node, filter);
	} else {
		ret = mce_add_mirror_list_entry(node->vport_list, filter);
		if (ret < 0) {
			printf("mirror add rule is vport_is is invaled");
			return -EINVAL;
		}
	}
	if (node->vport_list == NULL) {
		printf("mirror add rule port is same with last rule or mem "
		       "alloc failed");
		return -EEXIST;
	}

	filter->rule_loc = node->rule_loc;
#if 0
	tun_bc_sup = mce_sw_support_tun_brocast(filter);
	if (tun_bc_sup && node->domain == NULL) {
		/* for mirror vport brocast/mucast is also mirror to */
		switch (filter->rule_type) {
		case MCE_SW_OF_MAC:
			domain = mce_sw_get_untag_domain(handle);
			break;
		case MCE_SW_OF_VLAN:
			domain = mce_sw_get_vlan_domain(handle, filter);
			break;
		case MCE_SW_OF_MACVLAN:
			domain = mce_sw_get_macvlan_domain(handle, filter);
			break;
		default:
			assert(0);
		}
		if (domain == NULL) {
			if (node->vport_list->ref_cnt >= 2) {
				domain = mce_alloc_domain_entry(hw, handle, filter);
				mce_sw_add_domain_entry(domain, &node->filter);
				node->domain = domain;
			}
		}
	}
	if (domain) {
		mce_sw_add_domain_entry(domain, filter);
		mce_sw_update_domain_entry(hw, node->domain);
	}
#endif
	mce_sw_update_mirror_entry(hw, node->vport_list);
	node->reference_count++;

	return 0;
}

static int mce_sw_del_mirror_list(struct mce_hw *hw,
				  struct mce_switch_node *node,
				  struct mce_switch_filter *filter)
{
	int ret = 0;

	if (node->vport_list == NULL)
		return -EINVAL;
	ret = mce_del_mirror_list_entry(node->vport_list, filter);
	if (ret < 0) {
		printf("mirror del rule vport is invalid\n");
		return ret;
	}
	if (node->vport_list)
		mce_sw_update_mirror_entry(hw, node->vport_list);
	node->reference_count--;
	if (node->reference_count == 1) {
		mce_sw_destory_mirror_list(node->vport_list);
		node->vport_list = NULL;
	}

	return 0;
}

int mce_switch_macvlan_program(struct mce_switch_handle *handle,
			       struct mce_hw *hw,
			       struct mce_switch_filter *filter, bool add)
{
	struct mce_broadcast_domain_node *domain = NULL;
	struct mce_sw_rule_aggregate *rule_list;
	struct mce_switch_node *node = NULL;
	bool tun_bc_sup = false;
	int ret = 0;

	/* todo support modify
	 * user first set mac and then set portvlan
	 * we need update rule from mac to macvlan
	 */
	node = mce_find_switch_node(handle, filter);
	if (add) {
		if (node)
			return mce_sw_add_mirror_list(hw, node, filter);
		node = mce_alloc_switch_node(handle, filter);
		if (node == NULL)
			return -ENOMEM;
		/* TODO just mac/vlan, macvlan,
		 * vxlan/vxlan-vlan geneve/geneve-vlan gre/gre-vlan
		 * gtp-u/gtp-u-vlan can support add brocast/mucast communicate
		 * rule
		 */
		tun_bc_sup = mce_sw_support_tun_brocast(filter);
		rule_list = mce_sw_get_aggregate(handle, filter);
		if (rule_list == NULL)
			rule_list = mce_sw_rule_aggregate_alloc(handle, filter);
		if (tun_bc_sup && node->domain == NULL) {
			switch (filter->rule_type) {
			case MCE_SW_OF_MAC:
				domain = mce_sw_get_untag_domain(handle);
				break;
			case MCE_SW_OF_VLAN:
				domain = mce_sw_get_vlan_domain(handle, filter);
				break;
			case MCE_SW_OF_MACVLAN:
				domain = mce_sw_get_macvlan_domain(handle,
								   filter);
				break;
			case MCE_SW_OF_VXLAN:
			case MCE_SW_OF_NVGRE:
			case MCE_SW_OF_GENEVE:
			case MCE_SW_OF_GTPU:
			case MCE_SW_OF_GTPC:
				break;
			case MCE_SW_OF_VXLAN_VLAN:
			case MCE_SW_OF_NVGRE_VLAN:
			case MCE_SW_OF_GENEVE_VLAN:
			case MCE_SW_OF_GTPU_VLAN:
			case MCE_SW_OF_GTPC_VLAN:
				break;
			default:
				assert(0);
			}
			if (domain == NULL) {
				if (rule_list->member_num + 1 >= 2) {
					domain = mce_alloc_domain_entry(
						hw, handle, filter);
					/* TODO check domain null don't support
					 * borcast/mucast communicate
					 */
					struct mce_switch_node *first_node =
						TAILQ_FIRST(
							&rule_list->node_list);
					/* add old rule a domain */
					mce_sw_add_domain_entry(
						domain, &first_node->filter);
					node->domain = domain;
					rule_list->domain_entry = domain;
				}
			}
		}
		ret = mce_sw_add_macvlan_filter(hw, node);
		if (ret < 0)
			return ret;
		if (domain) {
			/* add cur new rule a domain */
			mce_sw_add_domain_entry(domain, filter);
			mce_sw_update_domain_entry(hw, domain);
		}
		TAILQ_INSERT_TAIL(&rule_list->node_list, node, entry);
		rule_list->member_num++;
	} else {

		if (node == NULL) {
			assert(0);
			return -EINVAL;
		}
		/* delete mirror rule list */
		if (node->vport_list && node->reference_count > 1)
			return mce_sw_del_mirror_list(hw, node, filter);
		rule_list = mce_sw_get_aggregate(handle, filter);
		if (rule_list) {
			mce_sw_remove_macvlan_filter(hw, node);
			TAILQ_REMOVE(&rule_list->node_list, node, entry);
			rule_list->member_num--;
			if (rule_list->member_num == 0)
				mce_sw_rule_aggregate_destory(handle,
							      rule_list);
			if (node->domain) {
				mce_sw_del_domain_entry(node->domain,
							&node->filter);
				mce_sw_update_domain_entry(hw, node->domain);
				if (node->domain->reference_count == 0)
					mce_sw_destory_domain_entry(
						handle, hw, node->domain);
			}
			mce_destory_switch_node(handle, node);
		}
	}


	return 0;
}

int mce_switch_tunvlan_program(struct mce_switch_handle *handle,
			       struct mce_hw *hw,
			       struct mce_switch_filter *filter, bool add)
{
	RTE_SET_USED(handle);
	RTE_SET_USED(hw);
	RTE_SET_USED(filter);
	RTE_SET_USED(add);

	return 0;
}

int mce_switch_eswitch_program(struct mce_switch_handle *handle,
			       struct mce_hw *hw,
			       struct mce_switch_filter *filter, bool add)
{
	struct mce_sw_rule_aggregate *rule_list;
	struct mce_switch_node *node = NULL;
	int ret = 0;

	node = mce_find_switch_node(handle, filter);
	if (add) {
		if (node)
			return mce_sw_add_mirror_list(hw, node, filter);
		node = mce_alloc_switch_node(handle, filter);
		if (node == NULL)
			return -ENOMEM;
		rule_list = mce_sw_get_aggregate(handle, filter);
		if (rule_list == NULL)
			rule_list = mce_sw_rule_aggregate_alloc(handle, filter);
		ret = mce_flush_eswitch_filter(hw, node, 1);
		if (ret) {
			mce_destory_switch_node(handle, node);
			return ret;
		}
		rule_list->member_num++;
		TAILQ_INSERT_TAIL(&rule_list->node_list, node, entry);
	} else {
		if (node == NULL)
			return -EINVAL;
		/* delete mirror rule list */
		if (node->vport_list && node->reference_count > 1)
			return mce_sw_del_mirror_list(hw, node, filter);
		rule_list = mce_sw_get_aggregate(handle, filter);
		if (rule_list) {
			mce_flush_eswitch_filter(hw, node, 0);
			mce_destory_switch_node(handle, node);
			rule_list->member_num--;
			if (rule_list->member_num == 0)
				mce_sw_rule_aggregate_destory(handle,
							      rule_list);
		}
	}

	return 0;
}

int mce_sw_remove_vf_macaddr(struct mce_hw *hw, struct mce_mac_filter *mac_f,
			     uint16_t vf_num)
{
	struct mce_switch_pattern lkup_pattern;
	struct mce_switch_filter *filter;
	int ret = 0;

	memset(&lkup_pattern, 0, sizeof(lkup_pattern));
	memcpy(&lkup_pattern.formatted.dst_mac, &mac_f->mac.mac_addr,
	       RTE_ETHER_ADDR_LEN);
	lkup_pattern.vport_id = vf_num;
	filter = mce_switch_entry_lookup(hw->switch_handle, &lkup_pattern);
	if (filter == NULL)
		return -EINVAL;
	ret = mce_switch_macvlan_program(hw->switch_handle, hw, filter, 0);
	if (ret < 0)
		return ret;
	ret = mce_switch_remove_hash_map(hw->switch_handle, filter);
	if (ret < 0)
		return ret;
	rte_free(filter);

	return 0;
}

int mce_sw_set_vf_macaddr(struct mce_hw *hw, struct mce_mac_filter *mac_f,
			  uint16_t vf_num)
{
	struct mce_switch_filter *filter = NULL;
	int ret = 0;

	filter = rte_zmalloc(NULL, sizeof(struct mce_switch_filter), 0);
	memcpy(&filter->lkup_pattern.formatted.dst_mac, &mac_f->mac.mac_addr,
	       RTE_ETHER_ADDR_LEN);
	filter->lkup_pattern.vport_id = vf_num;
	filter->rule_type = MCE_SW_OF_MAC;
	filter->action = MCE_SW_TO_VPORT;
	filter->options = MCE_OPT_DMAC;

	filter->redir_port = vf_num;
	filter->vport_id = vf_num;
	filter->loc_user_def = 1;
	filter->user_loc = vf_num;
	filter->switch_key = MCE_SWITCH_PFVF_VEB;
	mce_switch_macvlan_program(hw->switch_handle, hw, filter, 1);
	mac_f->mac.loc = filter->rule_loc;
	ret = mce_switch_insert_hash_map(hw->switch_handle, filter);
	if (ret < 0)
		goto sw_failed;
	return 0;
sw_failed:
	/* TODO */
	return ret;
}

int mce_sw_remove_pf_macaddr(struct mce_vport *vport,
			     struct mce_mac_filter *mac_filter)
{
	struct mce_switch_pattern lkup_pattern;
	struct mce_switch_filter *filter;
	struct mce_hw *hw = vport->hw;
	int ret = 0;

	memset(&lkup_pattern, 0, sizeof(lkup_pattern));
	memcpy(&lkup_pattern.formatted.dst_mac, &mac_filter->mac.mac_addr,
	       RTE_ETHER_ADDR_LEN);
	lkup_pattern.vport_id = vport->attr.vport_id;
	filter = mce_switch_entry_lookup(hw->switch_handle, &lkup_pattern);
	if (filter == NULL)
		return -EINVAL;
	ret = mce_switch_macvlan_program(hw->switch_handle, hw, filter, 0);
	if (ret < 0)
		return ret;
	mce_switch_remove_hash_map(hw->switch_handle, filter);
	memset(filter, 0, sizeof(*filter));
	rte_free(filter);

	return 0;
}

int mce_sw_set_pf_macaddr(struct mce_vport *vport,
			  struct mce_mac_filter *mac_filter)
{
	struct mce_switch_filter *filter = NULL;
	struct mce_hw *hw = vport->hw;
	int ret = -1;

	filter = rte_zmalloc(NULL, sizeof(struct mce_switch_filter), 0);
	memcpy(&filter->lkup_pattern.formatted.dst_mac,
	       &mac_filter->mac.mac_addr, RTE_ETHER_ADDR_LEN);
	filter->lkup_pattern.vport_id = vport->attr.vport_id;
	filter->rule_type = MCE_SW_OF_MAC;
	filter->action = MCE_SW_TO_VPORT;
	filter->options = MCE_OPT_DMAC;
	filter->redir_port = 0;
	filter->vport_id = vport->attr.vport_id;
	filter->switch_key = MCE_SWITCH_PFVF_VEB;
	filter->loc_user_def = 1;
	filter->user_loc = vport->attr.vport_id;
	ret = mce_switch_macvlan_program(hw->switch_handle, hw, filter, 1);
	if (ret < 0)
		goto fail;
	mce_switch_insert_hash_map(hw->switch_handle, filter);

	return 0;
fail:
	rte_free(filter);

	return ret;
}

int mce_sw_set_pf_uplink(struct mce_pf *pf)
{
	uint32_t uplink_port = pf->pf_vport->attr.vport_id;
	struct mce_hw *hw = pf->pf_vport->hw;
	uint32_t rule_loc = 511;
	uint32_t ctrl = 0;

	/* set uplink port can send any pkt to phytical pot */
	ctrl |= MCE_SW_VM_S_VPID_EN;
	ctrl |= uplink_port;
	MCE_E_REG_WRITE(hw, MCE_SW_VM_CTRL(rule_loc), ctrl);
	MCE_E_REG_WRITE(hw, MCE_SW_VM_ACT_CTRL(rule_loc), MCE_SW_ACT_TO_SWITCH);
	MCE_E_REG_SET_BITS(pf->pf_vport->hw, 0x8047c, 0x3, 0x2);

	return 0;
}
