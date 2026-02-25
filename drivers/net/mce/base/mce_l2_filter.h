/**
 * @file mce_l2_filter.h
 * @brief MCE Layer 2 Filtering (MAC, VLAN, Multicast)
 *
 * Provides Layer 2 MAC address and VLAN filtering operations for the MCE driver,
 * including MAC address management, VLAN filtering, and multicast hash updates.
 *
 * @details
 * Supports:
 * - VLAN filter add/remove operations
 * - MAC address filtering and management
 * - Multicast hash table updates
 * - MAC spoofing control
 * - L2 filter mode configuration
 *
 * @see mce_l2_filter.c for implementation
 */

#ifndef _MCE_L2_FILTER_H_
#define _MCE_L2_FILTER_H_

/**
 * @brief Add a VLAN filter entry.
 *
 * @param vport Pointer to VPort structure
 * @param filter Pointer to VLAN filter configuration
 * @return 0 on success, negative error code on failure
 */
int mce_add_vlan_filter(struct mce_vport *vport,
			struct mce_vlan_filter *filter);

/**
 * @brief Remove a VLAN filter entry.
 *
 * @param vport Pointer to VPort structure
 * @param filter Pointer to VLAN filter configuration
 * @return 0 on success, negative error code on failure
 */
int mce_remove_vlan_filter(struct mce_vport *vport,
			   struct mce_vlan_filter *filter);

/**
 * @brief Enable or disable VLAN filtering.
 *
 * @param vport Pointer to VPort structure
 * @param on true to enable, false to disable
 * @return 0 on success, negative error code on failure
 */
int mce_set_vlan_filter(struct mce_vport *vport, bool on);

/**
 * @brief Set MAC address filter.
 *
 * @param vport Pointer to VPort structure
 * @param filter Pointer to MAC filter configuration
 * @return 0 on success, negative error code on failure
 */
int mce_set_mac_addr(struct mce_vport *vport, struct mce_mac_filter *filter);

/**
 * @brief Remove MAC address from filter.
 *
 * @param vport Pointer to VPort structure
 * @param filter Pointer to MAC filter configuration
 * @return 0 on success, negative error code on failure
 */
int mce_remove_mac_addr(struct mce_vport *vport, struct mce_mac_filter *filter);

/**
 * @brief Update multicast hash table entry.
 *
 * @param vport Pointer to VPort structure
 * @param mcaddr Pointer to multicast Ethernet address
 */
void mce_update_mc_hash(struct mce_vport *vport, struct rte_ether_addr *mcaddr);

/**
 * @brief Update MAC filter mode configuration.
 *
 * @param vport Pointer to VPort structure
 * @param mode MAC filter operation mode
 * @param vlan_f_en Enable VLAN filtering
 * @param en Enable/disable the mode
 * @return 0 on success, negative error code on failure
 */
int mce_update_mpfm(struct mce_vport *vport, enum mce_mpf_modes mode,
		    bool vlan_f_en, bool en);

/**
 * @brief Control VF MAC spoofing protection.
 *
 * @param hw Pointer to MCE hardware structure
 * @param vport_id VPort identifier
 * @param on 1 to enable spoofing control, 0 to disable
 * @return 0 on success, negative error code on failure
 */
int mce_vf_mac_spoof_ctrl(struct mce_hw *hw, u16 vport_id, u8 on);

/**
 * @brief Update VF spoofing MAC address.
 *
 * @param hw Pointer to MCE hardware structure
 * @param vf VF identifier
 * @param mac MAC address pointer
 * @return 0 on success, negative error code on failure
 */
int mce_update_vf_spoof_mac(struct mce_hw *hw, u16 vf, u8 *mac);

/**
 * @brief Lookup VLAN filter entry.
 *
 * @param vport Pointer to VPort structure
 * @param entry Pointer to VLAN entry to lookup
 * @return Pointer to matching VLAN filter, or NULL if not found
 */
struct mce_vlan_filter *
mce_vlan_filter_lookup(struct mce_vport *vport, struct mce_vlan_entry *entry);

#endif /*_MCE_L2_FLTER_H_ */
