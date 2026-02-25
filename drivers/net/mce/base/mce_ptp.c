// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2024 - 2025 Mucse Corporation. */

#include "../mce.h"
#include "mce_osdep.h"
#include "mce_ptp.h"
#include "mce_hw.h"
#include "mce_eth_regs.h"
#include "mce_mac_regs.h"

#define MCE_COMP_MASK              RTE_GENMASK32(31, 0)
/**
 * mce_get_systime - Read hardware PTP system time
 * @hw: pointer to device hardware context
 * @systime: output parameter, receives system time in nanoseconds (since epoch)
 *
 * Read seconds and nanoseconds registers and combine them into a 64-bit
 * nanosecond time value. If @systime is NULL only logs debug information.
 */
static void mce_get_systime(struct mce_hw *hw, u64 *systime)
{
	u64 ns;

	ns = rd32(hw, MCE_TS_GET_NS);
	ns += rd32(hw, MCE_TS_GET_S) * 1000000000ULL;
	if (systime)
		*systime = ns;
	logd(LOG_PTP_HW, "%s systime:%lu\n", __func__, *systime);
}

/**
 * mce_init_systime - Initialize hardware PTP system time
 * @hw: pointer to device hardware context
 * @sec: seconds to set (32-bit)
 * @nsec: nanoseconds to set (32-bit)
 *
 * Write provided sec/nsec to hardware time registers and trigger an initial
 * update command. Returns 0 on success.
 */
static int mce_init_systime(struct mce_hw *hw, u32 sec, u32 nsec)
{
	wr32(hw, MCE_TS_CFG_S, sec);
	wr32(hw, MCE_TS_CFG_NS, nsec);

	wr32(hw, MCE_INITIAL_UPDATE_CMD, MCE_TM_INIT_CMD);
	logd(LOG_PTP_HW, "%s sec:%u nsec:%u\n", __func__, sec, nsec);

	return 0;
}

/**
 * mce_adjust_systime - Adjust hardware PTP system time (add/subtract)
 * @hw: pointer to device hardware context
 * @sec: seconds to adjust (positive)
 * @nsec: nanoseconds to adjust (positive)
 * @add_sub: 0 to add, non-zero to subtract (format accepted by hardware)
 *
 * Write the adjustment to registers and trigger an update command.
 * Returns 0 on success.
 */
static int mce_adjust_systime(struct mce_hw *hw, u32 sec, u32 nsec, int add_sub)
{
	if (add_sub) {
		/* if sub */
		nsec = 1000000000 - nsec;
		nsec |=  RTE_BIT32(31);
	}

	logd(LOG_PTP_HW, "%s nsec:%u add:%d\n", __func__, nsec, add_sub);

	wr32(hw, MCE_TS_CFG_S, sec);
	wr32(hw, MCE_TS_CFG_NS, nsec);
	/* update time */
	wr32(hw, MCE_INITIAL_UPDATE_CMD, MCE_TM_UPDATE_CMD);

	return 0;
}

/* do adjfine */
/**
 * mce_adjfine - Fine-grained adjustment of PTP clock frequency
 * @hw: pointer to device hardware context
 * @scaled_ppm: scaled frequency offset value as required by hardware
 *               (fixed-point representation, may be negative)
 *
 * Calculate compensation based on device clock rate and program the
 * increment registers to apply a fine frequency adjustment. Returns 0 on
 * success.
 */
static int mce_adjfine(struct mce_hw *hw, long scaled_ppm)
{
	struct mce_ptp_info *ptp_info = &hw->ptp;
	bool neg_adj = false;
	u32 temp, temp1;
	u64 comp, adj;

	if (scaled_ppm < 0) {
		neg_adj = true;
		scaled_ppm = -scaled_ppm;
	}

	logd(LOG_PTP_HW, "%s scaled_ppm:%ld\n", __func__, scaled_ppm);

	/* The hardware adds the clock compensation value to the PTP clock
	 * on every coprocessor clock cycle. Typical convention is that it
	 * represent number of nanosecond betwen each cycle. In this
	 * convention compensation value is in 64 bit fixed-point
	 * representation where upper 32 bits are number of nanoseconds
	 * and lower is fractions of nanosecond.
	 * The scaled_ppm represent the ratio in "parts per bilion" by which the
	 * compensation value should be corrected.
	 * To calculate new compenstation value we use 64bit fixed point
	 * arithmetic on following formula
	 * comp = tbase + tbase * scaled_ppm / (1M * 2^16)
	 * where tbase is the basic compensation value calculated initialy
	 * in cavium_ptp_init() -> tbase = 1/Hz. Then we use endian
	 * independent structure definition to write data to PTP register.
	 */
	comp = ((u64)1000000000ull << 32) / ptp_info->clk_ptp_rate;
	adj = comp * scaled_ppm;
	adj >>= 16;
	adj = div_u64(adj, 1000000ull);
	comp = neg_adj ? comp - adj : comp + adj;
	/* upper 32 is nsec, lower is the fractions of nanosecond */
	temp = (u32)(comp >> 32);

	/* low32 is fractions part, hw must 2 base with 16 bits;
	 * 0.xxxx * 2^16
	 * so we can do it use this :
	 * low32 >> 32 * 2^16 = low32 >> 16
	 */
	wr32(hw, MCE_TS_INCR_CNT, (temp << 16) | temp);
	temp1 = (u32)((comp & MCE_COMP_MASK));
	wr32(hw, MCE_INCR_CNT_NS_FINE, temp1);
	wr32(hw, MCE_INCR_CNT_NS_FINE_2, temp1);
	/* trig to hw INITIAL_UPDATE_CMD bit2 */
	wr32(hw, MCE_INITIAL_UPDATE_CMD, MCE_TM_TS_START);
	return 0;
}

/**
 * ptp_ops - PTP operations vector
 *
 * Collection of function pointers exposed to higher layers.
 */
const struct mce_ptp_ops ptp_ops = {
	.ptp_get_systime = mce_get_systime,
	.ptp_init_systime = mce_init_systime,
	.ptp_adjust_systime = mce_adjust_systime,
	.ptp_adjfine = mce_adjfine,
};

/**
 * mce_ptp_init - Initialize PTP subsystem data for the device
 * @hw: pointer to device hardware context
 *
 * Set default PTP clock rate and bind the operations vector to
 * `hw->ptp.ops`. Returns 0 on success.
 */
int mce_ptp_init(struct mce_hw *hw)
{
	struct mce_ptp_info *ptp_info = &hw->ptp;

	ptp_info->clk_ptp_rate = 500000000U;
	ptp_info->ops = &ptp_ops;

	return 0;
}

/**
 * mce_ptp_setup_ptp - Configure and enable hardware PTP support
 * @hw: pointer to device hardware context
 * @value: value to write to PTP configuration register (enable/mode etc.)
 *
 * Clear MAC bypass flag, program PTP configuration and time increment
 * registers, initialize hardware time with current system time, and set
 * `hw->ptp.ptp_enable`. Returns 0 on success.
 */
int mce_ptp_setup_ptp(struct mce_hw *hw, u32 value)
{
	struct mce_ptp_info *ptp_info = &hw->ptp;
	struct timespec now;
	u32 temp;
	u64 comp;

	logd(LOG_PTP_HW, "%s value:%d\n", __func__, value);
	/* 1 clear mac_cfg bit28 */
	rte_spinlock_lock(&hw->link_lock);
	temp = rd32(hw, MCE_M_MAC_CTRL);
	temp &= (~MCE_BYPASS_PTP_TIMER_EN);
	wr32(hw, MCE_M_MAC_CTRL, temp);
	/* setup mode */
	wr32(hw, MCE_PTP_CFG, value);
	comp = ((u64)1000000000ull << 32) / ptp_info->clk_ptp_rate;
	temp = (u32)(comp >> 32);
	wr32(hw, MCE_TS_INCR_CNT, (temp << 16) | temp);
	ptp_info->ptp_default_int = temp;
	temp = (u32)((comp & MCE_COMP_MASK));
	wr32(hw, MCE_INCR_CNT_NS_FINE, temp);
	wr32(hw, MCE_INCR_CNT_NS_FINE_2, temp);
	/* trig to hw INITIAL_UPDATE_CMD bit2 */
	wr32(hw, MCE_INITIAL_UPDATE_CMD, MCE_TM_TS_START);
	/* initialize system time */
        clock_gettime(CLOCK_REALTIME, &now);
	/* lower 32 bits of tv_sec are safe until y2106 */
	ptp_info->ops->ptp_init_systime(hw, (u32)now.tv_sec, now.tv_nsec);
	wr32(hw, MCE_TS_COMP, 0);
	hw->ptp.ptp_enable = 1;
	rte_spinlock_unlock(&hw->link_lock);

	return 0;
}

/**
 * config_close_tstamping - Disable hardware timestamping TX/RX
 * @hw: pointer to device hardware context
 *
 * Clear TX/RX timestamp enable bits in the PTP configuration register.
 */
static void config_close_tstamping(struct mce_hw *hw)
{
	u32 value;
	value = rd32(hw, MCE_PTP_CFG);
	value &= (~(MCE_PTP_TX_EN | MCE_PTP_RX_EN));
	wr32(hw, MCE_PTP_CFG, value);
}

/**
 * mce_disable_ptp - Disable device PTP functionality
 * @hw: pointer to device hardware context
 *
 * Disable timestamping under lock and clear the `hw->ptp.ptp_enable`
 * flag. Returns 0 on success.
 */
int mce_disable_ptp(struct mce_hw *hw)
{
	rte_spinlock_lock(&hw->link_lock);
	config_close_tstamping(hw);
	rte_spinlock_unlock(&hw->link_lock);
	hw->ptp.ptp_enable = 0;

	return 0;
}
/**
 * mce_ptp_gettime - Get current PTP time
 * @hw: pointer to device hardware context
 * @ts: output parameter, returns current time as struct timespec (sec + nsec)
 *
 * Read system time from hardware and convert to timespec. Returns 0 on
 * success.
 */
int mce_ptp_gettime(struct mce_hw *hw, struct timespec *ts)
{
        u64 ns = 0;

	rte_spinlock_lock(&hw->link_lock);
        hw->ptp.ops->ptp_get_systime(hw, &ns);
	rte_spinlock_unlock(&hw->link_lock);
        *ts = rte_ns_to_timespec(ns);

        return 0;
}

/**
 * mce_ptp_settime - Set PTP system time
 * @hw: pointer to device hardware context
 * @ts: input parameter specifying desired time (struct timespec)
 *
 * Write given sec/nsec to hardware and update the system time. Returns 0
 * on success.
 */
int mce_ptp_settime(struct mce_hw *hw,
			const struct timespec *ts)
{
	rte_spinlock_lock(&hw->link_lock);
        hw->ptp.ops->ptp_init_systime(hw, ts->tv_sec, ts->tv_nsec);
	rte_spinlock_unlock(&hw->link_lock);

        return 0;
}

/**
 * mce_ptp_adjfine - Thread-safe wrapper: fine-grained PTP clock frequency adjustment
 * @hw: pointer to device hardware context
 * @scaled_ppm: scaled ppm value passed to underlying ptp_adjfine
 *
 * Acquire lock and call the underlying implementation to perform the
 * frequency adjustment. Returns 0 on success.
 */
static int mce_ptp_adjfine(struct mce_hw *hw, long scaled_ppm)
{
	rte_spinlock_lock(&hw->link_lock);
		hw->ptp.ops->ptp_adjfine(hw, scaled_ppm);
	rte_spinlock_unlock(&hw->link_lock);

	return 0;
}

/**
 * mce_ptp_adjfreq - Adjust PTP frequency based on ppb
 * @hw: pointer to device hardware context
 * @ppb: frequency offset in parts-per-billion
 *
 * Convert ppb to the scaled ppm representation required by the lower
 * layer and call `mce_ptp_adjfine`. Returns the underlying call's return
 * value.
 */
int mce_ptp_adjfreq(struct mce_hw *hw, s64 ppb)
{
        s64 scaled_ppm;

        /*
         * We want to calculate
         *
         *    scaled_ppm = ppb * 2^16 / 1000        *
         * which simplifies to
         *
         *    scaled_ppm = ppb * 2^13 / 125
         */
        scaled_ppm = ((s64)ppb << 13) / 125;
        return mce_ptp_adjfine(hw, scaled_ppm);
}

/**
 * mce_ptp_adjtime - Adjust PTP time by delta nanoseconds
 * @hw: pointer to device hardware context
 * @delta: time offset in nanoseconds, positive to advance, negative to retard
 *
 * Split delta into seconds and nanoseconds and call the lower-level adjust
 * function. Returns 0 on success.
 */
int mce_ptp_adjtime(struct mce_hw *hw, s64 delta)
{
        u32 quotient, reminder;
        int neg_adj = 0;
        u32 sec, nsec;

        if (delta < 0) {
                neg_adj = 1;
                delta = -delta;
        }

        if (delta == 0)
                return 0;

        quotient = div_u64_rem(delta, 1000000000ULL, &reminder);
        sec = quotient;
        nsec = reminder;
	rte_spinlock_lock(&hw->link_lock);
        hw->ptp.ops->ptp_adjust_systime(hw, sec, nsec, neg_adj);
	rte_spinlock_unlock(&hw->link_lock);
        return 0;
}

/* get tx status */
/**
 * mce_ptp_tx_status - Check if TX timestamp is ready
 * @hw: pointer to device hardware context
 *
 * Read the status register and return whether a TX timestamp flag is
 * available (non-zero indicates ready).
 */
static int mce_ptp_tx_status(struct mce_hw *hw)
{
	u32 value;
#define MCE_TM_TX_NS_READY RTE_BIT32(0)
	value = rd32(hw, MCE_ETH_PTP_TX_TSVALUE_STATUS);
	return (value & MCE_TM_TX_NS_READY);
}

/**
 * mce_get_tx_stamp - Read and clear TX timestamp registers from hardware
 * @hw: pointer to device hardware context
 * @sec: output parameter, returns the seconds part of the timestamp
 * @nsec: output parameter, returns the nanoseconds part of the timestamp
 *
 * Read high/low time registers, set the clear bit to reset status, and
 * return 0 on success.
 */
static int
mce_get_tx_stamp(struct mce_hw *hw , u64 *sec, u64 *nsec)
{
	u32 temp;
	/* read tx stamp */
	*nsec = rd32(hw, MCE_ETH_PTP_TX_LTIMES);
	*sec = rd32(hw, MCE_ETH_PTP_TX_HTIMES);

	/* clean tx */
#define MCE_CLEAR_MASK BIT(15)
	temp = rd32(hw, MCE_ETH_PTP_TX_CLEAR);
	temp |= MCE_CLEAR_MASK;
	wr32(hw, MCE_ETH_PTP_TX_CLEAR, temp);
	wmb();
	temp &= (~MCE_CLEAR_MASK);
	wr32(hw, MCE_ETH_PTP_TX_CLEAR, temp);
	logd(LOG_PTP_HW, "*sec:%lu *nsec:%lu\n", *sec, *nsec);

	return 0;
}

/* get tx hwstamp and clear flags */
/**
 * mce_ptp_tx_stamp - Get ready TX hardware timestamp
 * @hw: pointer to device hardware context
 * @sec: output parameter, returns the seconds part of the timestamp
 * @nsec: output parameter, returns the nanoseconds part of the timestamp
 *
 * If a TX timestamp is ready, read it and return 0; otherwise return -1
 * indicating no timestamp is available.
 */
int mce_ptp_tx_stamp(struct mce_hw *hw, u64 *sec, u64 *nsec)
{
        if (mce_ptp_tx_status(hw)) {
                /* read and add nsec, sec turn to nsec*/
#define PTP_HWTX_TIME_VALUE_MASK        RTE_GENMASK32(31, 0)
		return mce_get_tx_stamp(hw, sec, nsec);
        }

	return -1;
}
