#ifndef _MCE_PTP_H_
#define _MCE_PTP_H_

struct mce_hw;

/**
 * mce_ptp_init - Initialize PTP subsystem for the device
 * @hw: pointer to device hardware context
 *
 * Returns 0 on success.
 */
int mce_ptp_init(struct mce_hw *hw);

/**
 * mce_ptp_setup_ptp - Configure and enable hardware PTP support
 * @hw: pointer to device hardware context
 * @value: value to write to PTP configuration register
 *
 * Returns 0 on success.
 */
int mce_ptp_setup_ptp(struct mce_hw *hw, u32 value);

/**
 * mce_disable_ptp - Disable device PTP functionality
 * @hw: pointer to device hardware context
 *
 * Returns 0 on success.
 */
int mce_disable_ptp(struct mce_hw *hw);

/**
 * mce_ptp_gettime - Read current PTP time
 * @hw: pointer to device hardware context
 * @ts: output timespec to receive current time
 *
 * Returns 0 on success.
 */
int mce_ptp_gettime(struct mce_hw *hw, struct timespec *ts);

/**
 * mce_ptp_settime - Set PTP system time
 * @hw: pointer to device hardware context
 * @ts: input timespec specifying desired time
 *
 * Returns 0 on success.
 */
int mce_ptp_settime(struct mce_hw *hw, const struct timespec *ts);

/**
 * mce_ptp_adjfreq - Adjust PTP frequency
 * @hw: pointer to device hardware context
 * @ppb: frequency adjustment in parts-per-billion
 *
 * Returns 0 on success.
 */
int mce_ptp_adjfreq(struct mce_hw *hw, s64 ppb);

/**
 * mce_ptp_adjtime - Adjust PTP time by delta nanoseconds
 * @hw: pointer to device hardware context
 * @delta: time offset in nanoseconds
 *
 * Returns 0 on success.
 */
int mce_ptp_adjtime(struct mce_hw *hw, s64 delta);

/**
 * mce_ptp_tx_stamp - Read TX hardware timestamp if available
 * @hw: pointer to device hardware context
 * @sec: output seconds part
 * @nsec: output nanoseconds part
 *
 * Returns 0 on success, -1 if no timestamp available.
 */
int mce_ptp_tx_stamp(struct mce_hw *hw, u64 *sec, u64 *nsec);

#endif /* _MCE_PTP_H_ */
