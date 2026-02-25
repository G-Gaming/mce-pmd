/**
 * @file mce_l2_filter.c
 * @brief Layer 2 (MAC/VLAN) filtering implementation
 *
 * Implements hardware MAC address and VLAN filtering operations for packet
 * classification and forwarding. Provides:
 * - VLAN tag filtering (add/remove VLAN IDs)
 * - MAC address filtering (unicast and multicast)
 * - MAC spoofing protection for VFs
 * - VLAN member port configuration
 * - Multicast address group management via hash tables
 * - Filter lookup and query operations
 *
 * Hardware Features:
 * - VFTA (VLAN Filter Table Array) - 4096-entry VLAN hash table
 * - RAR (Receive Address Register) - MAC address table
 * - MTA (Multicast Table Array) - Multicast hash table
 * - Per-VF MAC spoofing and VLAN enforcement
 *
 * @see mce_l2_filter.h for public API
 * @see mce_switch.h for VEB configuration
 */

#include <string.h>

#include <rte_malloc.h>

#include "../mce.h"
#include "../mce_logs.h"
#include "mce_hw.h"
#include "mce_eth_regs.h"
#include "mce_l2_filter.h"

/**
 * @brief Lookup a VLAN filter entry for a vport.
 *
 * Searches the vport's VLAN list for a matching entry and returns it.
 *
 * @param vport Pointer to vport
 * @param entry VLAN entry to lookup
 * @return Pointer to matching `mce_vlan_filter` or NULL if not found
 */
inline struct mce_vlan_filter *
mce_vlan_filter_lookup(struct mce_vport *vport, struct mce_vlan_entry *entry)
{
	struct mce_vlan_filter *it;

	TAILQ_FOREACH(it, &vport->vlan_list, next) {
		if (entry->vid == it->vlan.vid)
			return it;
	}

	return NULL;
}

 /**
 * @brief Add a VLAN filter for a vport.
 *
 * Programs the VLAN hash table and inserts the filter into the vport
 * VLAN list.
 *
 * @param vport Pointer to vport
 * @param filter VLAN filter to add
 * @return 0 on success, negative errno on failure
 */
int mce_add_vlan_filter(struct mce_vport *vport, struct mce_vlan_filter *filter)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	u32 vid_idx;
	u32 vid_bit;
	u32 vfta;
	u16 vlan = 0;

	vlan = filter->vlan.vid;
	vid_idx = (uint32_t)((vlan >> 5) & 0x7F);
	vid_bit = (uint32_t)(1 << (vlan & 0x1F));

	vfta = MCE_E_REG_READ(hw, MCE_ETH_VLAN_HASH(vid_idx));
	vfta |= vid_bit;
	MCE_E_REG_WRITE(hw, MCE_ETH_VLAN_HASH(vid_idx), vfta);

	filter->vlan.hash_entry = vid_idx;
	filter->vlan.hash_bit = vid_bit;

	TAILQ_INSERT_TAIL(&vport->vlan_list, filter, next);

	return 0;
}

 /**
 * @brief Remove a VLAN filter for a vport.
 *
 * Clears the VLAN hash table bit and removes the filter from the vport
 * list and frees its memory.
 *
 * @param vport Pointer to vport
 * @param filter VLAN filter to remove
 * @return 0 on success
 */
int mce_remove_vlan_filter(struct mce_vport *vport,
			   struct mce_vlan_filter *filter)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	u32 vid_idx;
	u32 vid_bit;
	u32 vfta;

	vid_idx = filter->vlan.hash_entry;
	vid_bit = filter->vlan.hash_bit;

	vfta = MCE_E_REG_READ(hw, MCE_ETH_VLAN_HASH(vid_idx));
	vfta &= ~vid_bit;
	MCE_E_REG_WRITE(hw, MCE_ETH_VLAN_HASH(vid_idx), vfta);

	TAILQ_REMOVE(&vport->vlan_list, filter, next);
	memset(filter, 0, sizeof(*filter));
	rte_free(filter);

	return 0;
}

 /**
 * @brief Enable or disable global VLAN filtering for a vport.
 *
 * Toggles the global L2 VLAN filter enable bit in the hardware.
 *
 * @param vport Pointer to vport
 * @param on True to enable, false to disable
 * @return 0 on success
 */
int mce_set_vlan_filter(struct mce_vport *vport, bool on)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	u32 ctrl = 0;

	ctrl = MCE_E_REG_READ(hw, MCE_ETH_GLOBAL_L2_F_CTRL);
	if (on)
		ctrl |= MCE_G_VLAN_FILTER_EN;
	else
		ctrl &= ~MCE_G_VLAN_FILTER_EN;

	MCE_E_REG_WRITE(hw, MCE_ETH_GLOBAL_L2_F_CTRL, ctrl);

	return 0;
}

 /**
 * @brief Program a MAC address into the hardware RAR/DMA registers.
 *
 * Writes the provided MAC filter entry into the hardware MAC table.
 *
 * @param vport Pointer to vport
 * @param filter MAC filter entry to program
 * @return 0 on success, negative errno on failure
 */
int mce_set_mac_addr(struct mce_vport *vport, struct mce_mac_filter *filter)
{
	struct mce_hw *hw = NULL;
	u32 mac_hi, mac_lo;
	u8 *mac = NULL;
	u16 loc = 0;

	if (vport == NULL || filter == NULL) {
		PMD_DRV_LOG(ERR, "Invalid vport or filter pointer");
		return -EINVAL;
	}
	loc = filter->mac.loc;
	hw = vport->hw;
	if (hw == NULL) {
		PMD_DRV_LOG(ERR, "Invalid hardware pointer");
		return -EINVAL;
	}
	mac = filter->mac.mac_addr.addr_bytes;
	mac_lo = ((uint32_t)mac[2] << 24) | ((uint32_t)mac[3] << 16) |
		((uint32_t)mac[4] << 8) | (uint32_t)mac[5];
	mac_hi = ((uint32_t)mac[0] << 8) | (uint32_t)mac[1];
	mac_hi |= MCE_MAC_FILTER_EN;

	MCE_E_REG_WRITE(hw, MCE_ETH_DMAC_RAH(loc), mac_hi);
	MCE_E_REG_WRITE(hw, MCE_ETH_DMAC_RAL(loc), mac_lo);

	return 0;
}

/**
 * @brief Remove a MAC address from hardware MAC table and vport list.
 *
 * Clears the RAH/RAL registers for the given location and removes the
 * filter from the vport's MAC list.
 *
 * @param vport Pointer to vport
 * @param filter MAC filter to remove
 * @return 0 on success
 */
int mce_remove_mac_addr(struct mce_vport *vport, struct mce_mac_filter *filter)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	u16 loc = filter->mac.loc;

	MCE_E_REG_WRITE(hw, MCE_ETH_DMAC_RAH(loc), 0);
	MCE_E_REG_WRITE(hw, MCE_ETH_DMAC_RAL(loc), 0);

	TAILQ_REMOVE(&vport->mac_list, filter, next);
	memset(filter, 0, sizeof(*filter));

	return 0;
}

/**
 * @brief Sample a MAC address to a multicast hash vector value.
 *
 * Computes the multicast hash vector based on configured hash type.
 *
 * @param vport Pointer to vport
 * @param mc_addr 6-byte multicast MAC address
 * @return 12-bit vector index into the MTA table
 */
static u32 mce_samp_mac_vector(struct mce_vport *vport, u8 *mc_addr)
{
	u32 vector = 0;

	switch (vport->attr.hash_filter_type) {
	case 0: /* Use bits [11:0] of the address */
		vector = ((mc_addr[4] << 8) | (((u16)mc_addr[5])));
		break;
	case 1: /* Use bits [12:1] of the address */
		vector = ((mc_addr[4] << 7) | (((u16)mc_addr[5]) >> 1));
		break;
	case 2: /* Use bits [13:2] of the address */
		vector = ((mc_addr[4] << 6) | (((u16)mc_addr[5]) >> 2));
		break;
	case 3: /* Use bits [14:3] of the address */
		vector = ((mc_addr[4] << 4) | (((u16)mc_addr[5]) >> 4));
		break;
	default: /* Invalid mc_filter_type */
		PMD_DRV_LOG(ERR,
			    "Mac Hash filter type param set incorrectly\n");
		break;
	}

	vector &= MCE_MAC_HASH_MASK;

	return vector;
}

/**
 * @brief Update multicast hash table for a given multicast address.
 *
 * Computes the MTA index and sets the bit in the hardware multicast
 * hash table and local shadow copy.
 *
 * @param vport Pointer to vport
 * @param mcaddr Pointer to multicast MAC address
 */
void mce_update_mc_hash(struct mce_vport *vport, struct rte_ether_addr *mcaddr)
{
	u32 hash_bit, mta_row, mta_col, vector, value, reg;
	struct mce_hw *hw = NULL;

	if (vport == NULL || mcaddr == NULL) {
		PMD_DRV_LOG(ERR, "Invalid vport or mcaddr pointer");
		return;
	}
	hw = vport->hw;
	if (vport->attr.hash_table_shift >= 32) {
		PMD_DRV_LOG(ERR, "Invalid hash_table_shift value: %u",
				vport->attr.hash_table_shift);
		return;
	}
	vector = mce_samp_mac_vector(vport, (uint8_t *)mcaddr);
	/* MC Hash Table Array  of 128 32-bit Register.
	 * It Can Turn To 4096 Bit So For Unicast Hash Filter Algorithm
	 * High 7 Bit Is Hash Table Row Low 5 Bit Is Column
	 */
	mta_row = (vector >> vport->attr.hash_table_shift) & 0x7f;
	mta_col = vector & (MCE_UTA_BIT_MASK);
	/* check weather the Hash Bit has Been Set */
	hash_bit = 1 << mta_col;
	value = vport->mc_hash_table[mta_row];
	if (!(value & hash_bit)) {
		reg = MCE_E_REG_READ(hw, MCE_ETH_MULTICAST_HASH(mta_row));
		reg |= hash_bit;
		MCE_E_REG_WRITE(hw, MCE_ETH_MULTICAST_HASH(mta_row), reg);
		vport->mc_hash_table[mta_row] |= hash_bit;
	}
}

/**
 * @brief Configure multicast/promiscuous filtering mode.
 *
 * Sets global or per-vport flags to enable multicast-promiscuous or
 * full promiscuous modes and optionally VLAN awareness.
 *
 * @param vport Pointer to vport
 * @param mode Mode to set (MCE_MPF_MODE_*)
 * @param vlan_f_en Enable VLAN filtering bit when setting promiscuous
 * @param en True to enable, false to disable
 * @return 0 on success, negative errno otherwise
 */
int mce_update_mpfm(struct mce_vport *vport, enum mce_mpf_modes mode,
		    bool vlan_f_en, bool en)
{
	struct mce_hw *hw = vport->hw;
	u32 vport_ctrl = 0;
	u32 g_ctrl = 0;
	u32 vp_attr_base;
	u32 vport_vlan = 0;
	u32 g_vlan = 0;
	u32 reg = 0;

	PMD_INIT_FUNC_TRACE();
	switch (mode) {
	case MCE_MPF_MODE_ALLMULTI:
		g_ctrl |= MCE_G_MULTICAST_PROMISC;
		vport_ctrl |= MCE_FWD_MPE;
		break;
	case MCE_MPF_MODE_PROMISC:
		g_ctrl |= MCE_G_UNICAST_PROMISC;
		g_ctrl |= MCE_G_MULTICAST_PROMISC;
		vport_ctrl |= MCE_FWD_MPE;
		vport_ctrl |= MCE_FWD_PE;
		if (vlan_f_en) {
			g_vlan |= MCE_G_VLAN_FILTER_EN;
			vport_vlan |= MCE_FWD_VPE;
		}
		break;
	default:
		return -EINVAL;
	}
	vp_attr_base = hw->vp_reg_base[MCE_VP_ATTR];
	if (hw->max_vfs || vport->attr.is_vf) {
		reg = MCE_E_REG_READ(hw, vp_attr_base);
		if (en) {
			reg |= vport_ctrl;
			reg |= vport_vlan;
			reg |= MCE_FWD_VPE;
		} else {
			reg &= ~vport_ctrl;
			reg &= ~vport_vlan;
			reg &= ~MCE_FWD_VPE;
		}
		MCE_E_REG_WRITE(hw, vp_attr_base, reg);
	} else {
		reg = MCE_E_REG_READ(hw, MCE_ETH_GLOBAL_L2_F_CTRL);
		if (en) {
			reg |= g_ctrl;
			reg &= ~g_vlan;
		} else {
			reg &= ~g_ctrl;
			reg |= g_vlan;
		}
		MCE_E_REG_WRITE(hw, MCE_ETH_GLOBAL_L2_F_CTRL, reg);
	}

	return 0;
}

 /**
 * @brief Toggle MAC spoofing protection for a VF vport.
 *
 * Enables or disables the antispoof bits for the given VF index.
 *
 * @param hw Hardware context
 * @param vport_id VF index
 * @param on Non-zero to enable protection, zero to disable
 * @return 0 on success
 */
int mce_vf_mac_spoof_ctrl(struct mce_hw *hw, u16 vport_id, u8 on)
{
	if (on)
		MCE_E_REG_SET_BITS(hw, MCE_ANTISPOOF_MAC_RAHC(vport_id), 0,
				   MCE_ANTISPOOF_MAC_EN);
	else
		MCE_E_REG_SET_BITS(hw, MCE_ANTISPOOF_MAC_RAHC(vport_id),
				   MCE_ANTISPOOF_MAC_EN, 0);

	return 0;
}

 /**
 * @brief Update the VF antispoof MAC registers with a specific MAC.
 *
 * Writes the high and low MAC register fields for the VF antispoof
 * feature.
 *
 * @param hw Hardware context
 * @param vf VF index
 * @param mac 6-byte MAC address to program
 * @return 0 on success
 */
int mce_update_vf_spoof_mac(struct mce_hw *hw, u16 vf, u8 *mac)
{
	u32 mac_hi, mac_lo;

	mac_lo = (mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5];
	mac_hi = (mac[0] << 8) | mac[1];

	MCE_E_REG_SET_BITS(hw, MCE_ANTISPOOF_MAC_RAHC(vf),
			   MCE_ANTISPOOF_MAC_HI_M, mac_hi);
	MCE_E_REG_SET_BITS(hw, MCE_ANTISPOOF_MAC_RAL(vf),
			   MCE_ANTISPOOF_MAC_LO_M, mac_lo);

	return 0;
}
