#ifndef _MCE_PF_H_
#define _MCE_PF_H_

#include "base/mce_osdep.h"
struct rte_eth_dev;
struct mce_pf;
/**
 * @brief Initialize PF state for the provided Ethernet device.
 *
 * Allocates and configures PF data structures and prepares hardware
 * resources for operation.
 *
 * @param eth_dev Pointer to the rte_eth_dev representing the PF
 * @return 0 on success, negative errno on failure
 */
int mce_pf_init(struct rte_eth_dev *eth_dev);

/**
 * @brief Uninitialize PF and free resources.
 *
 * @param eth_dev Pointer to the rte_eth_dev representing the PF
 * @return 0 on success, negative errno on failure
 */
int mce_pf_uinit(struct rte_eth_dev *eth_dev);

/**
 * @brief Set the MAC address for a VF.
 *
 * @param pf PF context
 * @param vf VF index
 * @param mac Pointer to 6-byte MAC address
 * @return 0 on success, negative errno on failure
 */
int mce_set_vf_mac_addr(struct mce_pf *pf, uint16_t vf, uint8_t *mac);

/**
 * @brief Configure a VLAN ID for a VF.
 *
 * @param pf PF context
 * @param vf VF index
 * @param vid VLAN identifier to program
 * @return 0 on success, negative errno on failure
 */
int mce_set_vf_vlan(struct mce_pf *pf, uint16_t vf, uint16_t vid);

/**
 * @brief Enable or disable MAC anti-spoofing for a VF.
 *
 * @param pf PF context
 * @param vf VF index
 * @param promisc_flag Non-zero to enable anti-spoofing/promiscuous behavior
 * @return 0 on success, negative errno on failure
 */
int mce_set_vf_promisc(struct mce_pf *pf, uint16_t vf, uint64_t promisc_flag);

/**
 * @brief Remove or add a VLAN for a VF (alias for set/remove semantics).
 */
int mce_set_vf_vlan(struct mce_pf *pf, uint16_t vf, uint16_t vid);

/**
 * @brief Delete a VLAN entry for a VF.
 *
 * @param pf PF context
 * @param vf VF index
 * @param vid VLAN identifier to remove
 * @return 0 on success, negative errno on failure
 */
int mce_del_vf_vlan(struct mce_pf *pf, uint16_t vf, uint16_t vid);

/**
 * @brief Enable or disable VLAN filtering for a VF.
 *
 * @param pf PF context
 * @param vf VF index
 * @param on True to enable filtering, false to disable
 * @return 0 on success, negative errno on failure
 */
int mce_set_vf_vlan_filter(struct mce_pf *pf, uint16_t vf, bool on);

/**
 * @brief Update a VF VLAN mapping at a specific hardware location.
 *
 * @param pf PF context
 * @param vf VF index
 * @param vid VLAN id to add/remove
 * @param loc Hardware location/index to update
 * @param add True to add, false to remove
 * @return 0 on success, negative errno on failure
 */
int mce_update_vf_vlan_vid(struct mce_pf *pf, uint16_t vf, uint16_t vid,
			   uint16_t loc, bool add);

/**
 * @brief Configure VLAN stripping behavior for a VF at a location.
 *
 * @param pf PF context
 * @param vf VF index
 * @param strip_layers Number of VLAN layers to strip
 * @param loc Hardware location/index
 * @param on True to enable stripping, false to disable
 * @return 0 on success, negative errno on failure
 */
int mce_set_vf_vlan_strip(struct mce_pf *pf, uint16_t vf, uint16_t strip_layers,
			  uint16_t loc, bool on);

/**
 * @brief Enable or disable multicast filtering for a VF.
 *
 * @param pf PF context
 * @param vf VF index
 * @param en True to enable, false to disable
 * @return 0 on success, negative errno on failure
 */
int mce_en_vf_mulcast_filter(struct mce_pf *pf, uint16_t vf, bool en);

/**
 * @brief Add or remove a multicast MAC filter for a VF.
 *
 * @param pf PF context
 * @param vf VF index
 * @param addr Pointer to 6-byte multicast MAC address
 * @param loc Hardware location index
 * @param add True to add, false to remove
 * @return 0 on success, negative errno on failure
 */
int mce_add_vf_mulcast_filter(struct mce_pf *pf, uint16_t vf, u8 *addr, int loc,
			  bool add);

/**
 * @brief Read a VF register via PF-managed interface.
 *
 * @param pf PF context
 * @param vf VF index
 * @param addr Register address to read
 * @param val Out parameter receiving read value
 * @return 0 on success, negative errno on failure
 */
int mce_get_vf_reg(struct mce_pf *pf, uint16_t vf, int addr, int *val);

/**
 * @brief Get VF DMA fragment size information.
 *
 * @param pf PF context
 * @param vf VF index
 * @param frag_len Out parameter receiving fragment length
 * @return 0 on success, negative errno on failure
 */
int mce_get_vf_dma_frag(struct mce_pf *pf, uint16_t vf, int *frag_len);

int mce_set_vf_trust(struct mce_pf *pf, int vf_id, bool trusted);
#endif
