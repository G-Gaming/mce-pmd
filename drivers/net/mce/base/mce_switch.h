/**
 * @file mce_switch.h
 * @brief MCE Hardware Switch and Filtering
 *
 * Provides hardware switch control structures and filtering capabilities
 * for MAC VLAN filtering, multi-cast, and broadcast packet control.
 *
 * @details
 * Supports:
 * - Layer 2 MAC and VLAN filtering
 * - MAC-VLAN combination filtering
 * - Virtual Ethernet Bridge (VEB) switching
 * - Filter state management (add/remove)
 * - Switch action parameters
 * @see mce_switch.c for implementation
 */

#ifndef _MCE_SWITCH_H_
#define _MCE_SWITCH_H_

#include "../mce_switch_flow.h"

/** @def MCE_VF_L2_MAC_FILTER VF Layer 2 MAC filtering flag */
#define MCE_VF_L2_MAC_FILTER	 RTE_BIT32(0)

/** @def MCE_VF_L2_VLAN_FILTER VF Layer 2 VLAN filtering flag */
#define MCE_VF_L2_VLAN_FILTER	 RTE_BIT32(1)

/** @def MCE_VF_L2_MACVLAN_FILTER VF MAC+VLAN filtering flags combined */
#define MCE_VF_L2_MACVLAN_FILTER (MCE_VF_L2_MAC_FILTER | MCE_VF_L2_VLAN_FILTER)

/** @def MCE_SWITCH_PFVF_VEB PF/VF VEB flag in configuration */
#define MCE_SWITCH_PFVF_VEB	RTE_BIT64(63)

/** @def MCE_SWITCH_RULE_VEB Switch rule VEB flag */
#define MCE_SWITCH_RULE_VEB	RTE_BIT64(62)

/** @def MCE_SWITCH_KRY_VAL_MASK Switch key value mask */
#define MCE_SWITCH_KRY_VAL_MASK GENMASK_U32(31, 0)

/**
 * @enum mce_filter_state
 * @brief Filter operation state
 */
enum mce_filter_state {
	MCE_FILTER_ADD,    /**< Add filter rule */
	MCE_FILTER_REMOVE, /**< Remove filter rule */
};

/**
 * @struct mce_sw_macvlan_filter
 * @brief MAC-VLAN filter entry
 *
 * Represents a single MAC-VLAN filtering rule with state management.
 */
struct mce_sw_macvlan_filter {
	TAILQ_ENTRY(mce_mac_vlan_filter) entry;
	u8 macaddr[ETH_ALEN];                      /**< MAC address */
	u16 vlan;                                  /**< VLAN ID */
	u16 loc;                                   /**< Location/index */
	u8 type;                                   /**< Filter type */
	enum mce_filter_state state;               /**< Filter state */
	struct mce_switch_action_params *action_node; /**< Associated action */
};

struct mce_hw;
/**
 * @brief Initialize switch bitmap structures.
 *
 * Allocate and initialize internal bitmaps used for managing
 * switch filter entries.
 *
 * @param handle Pointer to switch handle
 * @return 0 on success, negative errno on failure
 */
int mce_switch_bitmap_init(struct mce_switch_handle *handle);

/**
 * @brief Program VF MAC address into hardware.
 *
 * Add or update a VF's MAC address entry in hardware tables.
 *
 * @param hw Pointer to MCE hardware context
 * @param mac_f Pointer to MAC filter structure
 * @param vf_num VF identifier
 * @return 0 on success, negative errno on failure
 */
int mce_sw_set_vf_macaddr(struct mce_hw *hw, struct mce_mac_filter *mac_f,
			  uint16_t vf_num);

/**
 * @brief Remove VF MAC address from hardware.
 *
 * Remove a previously programmed MAC entry for a VF.
 *
 * @param hw Pointer to MCE hardware context
 * @param mac_f Pointer to MAC filter structure
 * @param vf_num VF identifier
 * @return 0 on success, negative errno on failure
 */
int mce_sw_remove_vf_macaddr(struct mce_hw *hw, struct mce_mac_filter *mac_f,
			 uint16_t vf_num);

/**
 * @brief Lookup a switch entry by pattern.
 *
 * Search the switch handle's data structures for a matching filter
 * entry corresponding to the provided pattern.
 *
 * @param handle Pointer to switch handle
 * @param lkup_pattern Pattern to locate
 * @return Pointer to matching filter or NULL if not found
 */
struct mce_switch_filter *
mce_switch_entry_lookup(struct mce_switch_handle *handle,
			struct mce_switch_pattern *lkup_pattern);

/**
 * @brief Insert filter into switch hash-map.
 *
 * Adds the provided filter structure into the switch's lookup
 * hash-map for fast matching.
 *
 * @param handle Pointer to switch handle
 * @param filter Filter to insert
 * @return 0 on success, negative errno on failure
 */
int mce_switch_insert_hash_map(struct mce_switch_handle *handle,
			   struct mce_switch_filter *filter);

/**
 * @brief Remove filter from switch hash-map.
 *
 * Removes the provided filter from the switch's lookup structures.
 *
 * @param handle Pointer to switch handle
 * @param filter Filter to remove
 * @return 0 on success, negative errno on failure
 */
int mce_switch_remove_hash_map(struct mce_switch_handle *handle,
			   struct mce_switch_filter *filter);

/**
 * @brief Set PF MAC address for vport.
 *
 * Program the physical function's MAC address for the given vport.
 *
 * @param vport Pointer to virtual port
 * @param mac_filter MAC filter structure
 * @return 0 on success, negative errno on failure
 */
int mce_sw_set_pf_macaddr(struct mce_vport *vport,
			  struct mce_mac_filter *mac_filter);

/**
 * @brief Remove PF MAC address for vport.
 *
 * Remove a PF MAC address programmed for the given vport.
 *
 * @param vport Pointer to virtual port
 * @param mac_filter MAC filter structure
 * @return 0 on success, negative errno on failure
 */
int mce_sw_remove_pf_macaddr(struct mce_vport *vport,
			 struct mce_mac_filter *mac_filter);

/**
 * @brief Program MAC+VLAN filter into hardware (add/remove).
 *
 * @param handle Pointer to switch handle
 * @param hw Pointer to MCE hardware context
 * @param filter Filter description to program
 * @param add True to add, false to remove
 * @return 0 on success, negative errno on failure
 */
int mce_switch_macvlan_program(struct mce_switch_handle *handle,
			   struct mce_hw *hw,
			   struct mce_switch_filter *filter, bool add);

/**
 * @brief Program tunnel VLAN-related filter into hardware (add/remove).
 *
 * @param handle Pointer to switch handle
 * @param hw Pointer to MCE hardware context
 * @param filter Filter description to program
 * @param add True to add, false to remove
 * @return 0 on success, negative errno on failure
 */
int mce_switch_tunvlan_program(struct mce_switch_handle *handle,
			   struct mce_hw *hw,
			   struct mce_switch_filter *filter, bool add);

/**
 * @brief Program eswitch (virtual switch) entries (add/remove).
 *
 * @param handle Pointer to switch handle
 * @param hw Pointer to MCE hardware context
 * @param filter Filter description to program
 * @param add True to add, false to remove
 * @return 0 on success, negative errno on failure
 */
int mce_switch_eswitch_program(struct mce_switch_handle *handle,
			   struct mce_hw *hw,
			   struct mce_switch_filter *filter, bool add);

/**
 * @brief Configure PF uplink settings.
 *
 * Apply PF uplink related configuration and resources.
 *
 * @param pf Pointer to PF structure
 * @return 0 on success, negative errno on failure
 */
int mce_sw_set_pf_uplink(struct mce_pf *pf);

#endif
