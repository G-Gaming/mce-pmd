#ifndef _MCE_PFVF_H_
#define _MCE_PFVF_H_

#include "../mce.h"
#include "mce_osdep.h"

struct mce_vf_ntuple_pattern {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint8_t l4_type;
	bool is_ipv6;
};
struct mce_vf_ntuple_act {
	bool is_drop;
	uint8_t redir_queue;
	uint16_t mark_id;
};
struct mce_vf_ntuple_rule {
	struct mce_vf_ntuple_pattern pattern;
	struct mce_vf_ntuple_act act;
	bool add;
};
/**
 * @brief Get the number of configured VFs for the device.
 *
 * @param hw Pointer to device hardware context
 * @return Number of VFs
 */
int mce_get_vfnum(struct mce_hw *hw);

/**
 * @brief Allocate and initialize a vport instance.
 *
 * @param hw Pointer to device hardware context
 * @param type Type of vport to allocate
 * @return Pointer to allocated `mce_vport`, or NULL on failure
 */
struct mce_vport *mce_alloc_vport(struct mce_hw *hw, enum mce_vport_type type);

/**
 * @brief Destroy and free a previously allocated vport.
 *
 * @param vport Pointer to vport to destroy
 */
void mce_destory_vport(struct mce_vport *vport);

/**
 * @brief Read the RSS redirection table for a vport.
 *
 * Copies the RETA into the provided `lut` buffer.
 *
 * @param vport Pointer to vport
 * @param lut Output buffer for RETA entries
 */
void mce_get_rss_reta(struct mce_vport *vport, u32 *lut);

/**
 * @brief Program the RSS redirection table for a vport.
 *
 * @param vport Pointer to vport
 * @param lut Input buffer containing RETA entries
 */
void mce_setup_rss_reta(struct mce_vport *vport, u32 *lut);

#endif /* _MCE_PFVF_H_ */
