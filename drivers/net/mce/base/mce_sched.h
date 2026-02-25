/**
 * @file mce_sched.h
 * @brief MCE Scheduler and Traffic Shaping
 *
 * Provides traffic shaping and scheduling functionality for controlling
 * transmission rates on queues and VFs.
 *
 * @details
 * Supports:
 * - Scheduler initialization
 * - Per-queue rate limiting
 * - Per-VF bandwidth management
 * - Committed rate enforcement
 *
 * @see mce_sched.c for implementation
 */

#ifndef _MCE_SCHED_H_
#define _MCE_SCHED_H_

#include "mce_osdep.h"
#include "mce_hw.h"

/**
 * @brief Initialize the traffic scheduler.
 *
 * Sets up initial scheduler configuration and hardware state.
 *
 * @param hw Pointer to MCE hardware structure
 */
void mce_sched_init(struct mce_hw *hw);

/**
 * @brief Commit scheduler configuration changes.
 *
 * Applies pending scheduler configuration to hardware.
 *
 * @param vport Pointer to VPort structure
 * @param clear_on_fail Clear pending config on failure
 * @return 0 on success, negative error code on failure
 */
int mce_sched_commit(struct mce_vport *vport, int clear_on_fail);

/**
 * @brief Set transmission rate limit for a queue.
 *
 * Configures maximum transmission rate for a specific hardware queue.
 *
 * @param hw Pointer to MCE hardware structure
 * @param hwrid Hardware queue/ring identifier
 * @param max_rate Maximum transmission rate in bps
 */
void mce_set_txq_rate(struct mce_hw *hw, uint16_t hwrid, uint64_t max_rate);

/**
 * @brief Set transmission rate limit for a VF.
 *
 * Configures maximum transmission rate for a virtual function.
 *
 * @param hw Pointer to MCE hardware structure
 * @param vf_num VF identifier
 * @param rate Maximum transmission rate in bps
 * @return 0 on success, negative error code on failure
 */
int mce_set_vf_rate(struct mce_hw *hw, u16 vf_num, u64 rate);

#endif /* _MCE_SCHED_H_ */
