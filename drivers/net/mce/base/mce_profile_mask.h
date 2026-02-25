#ifndef _MCE_PROFILE_MASK_H_
#define _MCE_PROFILE_MASK_H_

#include "mce_osdep.h"
#include "../mce_flow.h"

struct mce_field_bitmask_block {
	u64 options;
	u16 key_off;
	u16 mask;
	bool used;
};

struct mce_field_bitmask_info {
	struct mce_field_bitmask_block *field_bitmask;

	u16 ref_cnt;
	u16 used_block;
};

struct mce_hw_profile {
	u64 profile_id;
	u64 options;
	u64 fied_mask;

	struct mce_field_bitmask_info *mask_info;
	u64 bitmask_options;
	u32 ref_cnt;
};

struct mce_hw;
struct mce_vport;
struct mce_fdir_handle;
struct mce_fdir_filter;
struct mce_lkup_meta;

/**
 * @brief Allocate an FDIR hardware profile for a filter.
 *
 * Creates and returns a new `mce_hw_profile` representing the hardware
 * encoding for the provided filter and handle.
 *
 * @param handle FDIR handle
 * @param filter Filter description
 * @return Pointer to allocated `mce_hw_profile` on success, NULL on failure
 */
struct mce_hw_profile *mce_fdir_alloc_profile(struct mce_fdir_handle *handle,
					  struct mce_fdir_filter *filter);

/**
 * @brief Add or remove an FDIR profile in hardware.
 *
 * Updates hardware state to add or remove the supplied profile.
 *
 * @param hw Hardware context
 * @param profile Profile to add/remove
 * @param add True to add, false to remove
 * @return 0 on success, negative error on failure
 */
int mce_fdir_profile_update(struct mce_hw *hw, struct mce_hw_profile *profile,
				bool add);

/**
 * @brief Remove a profile associated with a filter.
 *
 * @param hw Hardware context
 * @param handle FDIR handle
 * @param filter Filter whose profile should be removed
 * @return 0 on success, negative error on failure
 */
int mce_fdir_remove_profile(struct mce_hw *hw, struct mce_fdir_handle *handle,
				struct mce_fdir_filter *filter);

/**
 * @brief Allocate bitmask blocks for a profile on a vport.
 *
 * @param vport Pointer to vport
 * @param handle FDIR handle
 * @param mask_info Output mask info to populate
 * @return 0 on success, negative error on failure
 */
int mce_prof_bitmask_alloc(struct mce_vport *vport,
			   struct mce_fdir_handle *handle,
			   struct mce_field_bitmask_info *mask_info);

/**
 * @brief Update the hardware field bitmask options for a profile.
 *
 * @param hw Hardware context
 * @param profile_id Profile identifier
 * @param options Bitmask options to apply
 */
void mce_profile_field_bitmask_update(struct mce_hw *hw, u16 profile_id,
					  u32 options);

/**
 * @brief Check for conflicting field bitmasks between profile and mask_info.
 *
 * @param profile Profile to check
 * @param mask_info Mask info to compare against
 * @return 0 if no conflict, negative if conflict/error
 */
int mce_check_conflct_filed_bitmask(struct mce_hw_profile *profile,
					struct mce_field_bitmask_info *mask_info);

/**
 * @brief Validate a lookup meta field bitmask configuration.
 *
 * @param meta Lookup meta to validate
 * @return 0 if valid, negative otherwise
 */
int mce_check_field_bitmask_valid(struct mce_lkup_meta *meta);

/**
 * @brief Initialize field mask structures for a set of lookup metas.
 *
 * @param meta Array of lookup meta entries
 * @param meta_num Number of meta entries
 * @param mask_info Output mask info to populate
 * @return 0 on success, negative otherwise
 */
int mce_fdir_field_mask_init(struct mce_lkup_meta *meta, u16 meta_num,
				 struct mce_field_bitmask_info *mask_info);

/**
 * @brief Check for profile conflicts when inserting a filter.
 *
 * @param handle FDIR handle
 * @param filter Filter to evaluate
 * @return 0 if no conflict, negative otherwise
 */
int mce_conflct_profile_check(struct mce_fdir_handle *handle,
				  struct mce_fdir_filter *filter);

#endif /* _MCE_PROFILE_MASK_H */
