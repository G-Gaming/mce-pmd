/**
 * @file mce_fdir.h
 * @brief MCE Flow Director (FDIR) Classification
 *
 * Defines Flow Director functionality for hardware-based packet classification
 * and filtering, enabling efficient traffic steering to specific queues.
 *
 * @details
 * Supports:
 * - Flow classification rule insertion/removal
 * - Profile-based key encoding
 * - Direction programming
 * - Dynamic rule management
 *
 * @see mce_fdir_flow.h for flow steering integration
 * @see mce_fdir.c for implementation
 */

#ifndef _MCE_FDIR_H_
#define _MCE_FDIR_H_

struct mce_fdir_handle;
struct mce_fdir_filter;
struct mce_vport;
union mce_atr_input;
#include "../mce_fdir_flow.h"

/** @typedef mce_fdir_profile_key_encode Profile key encoding function pointer */
typedef int (*mce_fdir_profile_key_encode)(struct mce_fdir_filter *filter);

/**
 * @struct mce_fdir_key_encode
 * @brief FDIR key encoding profile
 *
 * Associates a profile ID with its corresponding key encoding function.
 */
struct mce_fdir_key_encode {
	u64 profile_id;                    /**< Profile identifier */
	mce_fdir_profile_key_encode key_encode; /**< Key encoding function */
};

/**
 * @brief Insert a Flow Director filter entry.
 *
 * Adds a new classification rule to direct matching packets to specific queues.
 *
 * @param handle Pointer to FDIR handle
 * @param vport Pointer to VPort structure
 * @param filter Pointer to filter configuration
 * @return 0 on success, negative error code on failure
 */
int mce_fdir_insert_entry(struct mce_fdir_handle *handle,
			  struct mce_vport *vport,
			  struct mce_fdir_filter *filter);

/**
 * @brief Remove a Flow Director filter entry.
 *
 * Removes an existing classification rule.
 *
 * @param handle Pointer to FDIR handle
 * @param vport Pointer to VPort structure
 * @param filter Pointer to filter configuration
 */
void mce_fdir_remove_entry(struct mce_fdir_handle *handle,
			   struct mce_vport *vport,
			   struct mce_fdir_filter *filter);
/**
 * @brief Clear a hardware rule (dispatch by mode).
 *
 * Dispatches to the appropriate clear helper based on the handle's
 * FDIR mode (sign or exact).
 *
 * @param handle Pointer to FDIR handle
 * @param vport Pointer to VPort structure for hardware access
 * @param filter Pointer to filter configuration to clear
 */
void mce_clear_hw_rule(struct mce_fdir_handle *handle, struct mce_vport *vport,
               struct mce_fdir_filter *filter);
/**
 * @brief Edit a hardware rule (dispatch by mode).
 *
 * Dispatches to the appropriate edit helper based on the handle's
 * FDIR mode (sign or exact) to program rule metadata.
 *
 * @param handle Pointer to FDIR handle
 * @param vport Pointer to VPort structure for hardware access
 * @param filter Pointer to filter configuration to program
 */
void mce_edit_hw_rule(struct mce_fdir_handle *handle, struct mce_vport *vport,
              struct mce_fdir_filter *filter);
/**
 * @brief Allocate a free hardware entry location.
 *
 * Scans the handle's entry bitmap for a free slot and returns its
 * index via @p loc.
 *
 * @param handle Pointer to FDIR handle containing entry bitmap
 * @param loc Out parameter receiving the located index
 * @return 0 on success, -ENOMEM when no free slot is available
 */
int mce_get_valid_entry_loc(struct mce_fdir_handle *handle, uint16_t *loc);
/**
 * @brief Lookup a filter from the software hash map.
 *
 * Uses the handle's rte_hash to find an already-inserted filter that
 * matches the given lookup pattern.
 *
 * @param handle Pointer to FDIR handle containing hash structures
 * @param filter Lookup pattern to search for
 * @return Pointer to stored `mce_fdir_filter` or NULL if not found
 */
struct mce_fdir_filter *
mce_fdir_entry_lookup(struct mce_fdir_handle *handle,
		      const struct mce_fdir_filter *filter);
/**
 * @brief Insert a filter into the software lookup hash map.
 *
 * Adds the filter's lookup pattern to the handle's rte_hash and stores
 * the filter pointer in the map array.
 *
 * @param handle Pointer to FDIR handle
 * @param filter Filter to add
 * @return 0 on success or negative rte_hash error code
 */
int mce_fdir_insert_hash_map(struct mce_fdir_handle *handle,
			     struct mce_fdir_filter *filter);
/**
 * @brief Remove a filter from the software lookup hash map.
 *
 * Deletes the lookup key from the handle's rte_hash and clears the
 * corresponding slot in the map array.
 *
 * @param handle Pointer to FDIR handle
 * @param filter Filter whose lookup key will be removed
 * @return 0 on success or negative error code
 */
int mce_fdir_remove_hash_map(struct mce_fdir_handle *handle,
			     const struct mce_fdir_filter *filter);
/**
 * @brief Mark a hardware entry index as allocated in the handle bitmap.
 *
 * @param handle Pointer to FDIR handle
 * @param loc Entry index to mark
 */
void mce_set_fdir_entry_bit(struct mce_fdir_handle *handle, uint16_t loc);
/**
 * @brief Compute the FDIR hash value for a hardware inset and key.
 *
 * Produces the 32-bit hash used for quick lookup programming.
 *
 * @param handle Pointer to FDIR handle (hash mode influences output)
 * @param hw_inset Hardware inset containing key/profile data
 * @param profile_id Profile identifier
 * @param vport_id VPort identifier
 * @param key Seed key used for hashing
 * @return 32-bit hash value
 */
uint32_t mce_inset_compute_hash(struct mce_fdir_handle *handle,
				struct mce_hw_rule_inset *hw_inset,
				uint16_t profile_id, uint16_t vport_id,
				uint32_t key);
/**
 * @brief Initialize key encoding for a filter according to its profile.
 *
 * Chooses and invokes the appropriate profile key encoder which fills
 * the filter's hw_inset fields.
 *
 * @param filter Pointer to filter to prepare
 * @return 0 on success or negative error code
 */
int mce_fdir_key_setup(struct mce_fdir_filter *filter);

#endif /* _MCE_FDIR_H_ */
