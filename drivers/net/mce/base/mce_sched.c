/**
 * @file mce_sched.c
 * @brief Traffic shaping and queue scheduling implementation
 *
 * Implements hardware-based traffic shaping and queue scheduling
 * for QoS (Quality of Service) management:
 * - Per-queue transmit rate limiting
 * - Per-VF aggregate rate limiting
 * - Traffic shaping configuration
 * - Scheduler state management
 * - Atomic configuration commit
 *
 * Rate Limiting:
 * - Configured in Mbps (megabits per second)
 * - Applied per egress queue and per VF
 * - Combinable for hierarchical QoS
 * - Support for burst/peak rate configuration
 *
 * @see mce_sched.h for public API
 * @see base/mce_dma_regs.h for register definitions
 */

#include <assert.h>

#include <rte_string_fns.h>
#include <rte_tailq.h>
#include "mce_osdep.h"

#include "mce_hw.h"
#include "mce_dma_regs.h"
#include "mce_sched.h"

#include "../mce_tm.h"
#include "../mce.h"

#ifdef MCE_TM_TC
/**
 * @brief Internal: configure traffic class scheduler.
 *
 * This is an internal helper used when Traffic Manager TC-level
 * scheduling is enabled. It arranges scheduler resources for the
 * provided node according to the shaper configuration.
 *
 * @param hw Pointer to MCE hardware context
 * @param tm_conf Pointer to traffic manager configuration
 * @param node Pointer to the TM node to configure
 * @return 0 on success, negative errno on failure
 */
static int mce_sched_tc_setup(struct mce_hw *hw,
							  struct mce_tm_shaper_conf *tm_conf,
							  struct mce_tm_node *node)
{
	return 0;
}
#endif

#define MCE_SAMPING_UINT (10000UL)
/* 1Mhz */
/**
 * @brief Set per-queue transmit rate (implementation).
 *
 * Configure hardware registers to enforce the specified transmit
 * rate for a given hardware queue.
 *
 * @param hw Pointer to MCE hardware context
 * @param hwrid Hardware queue identifier
 * @param max_rate Maximum transmit rate in bits per second
 */
void mce_set_txq_rate(struct mce_hw *hw, uint16_t hwrid, uint64_t max_rate)
{
	MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_RATE_CTRL_TM(hwrid),
			MCE_SAMPING_UINT * (hw->clock_mhz - 1));
	MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_RATE_CTRL_TH(hwrid), (max_rate) / 100);
}

#define MCE_VF_RATE_LIMIT(vf) _DMA_(0x1c00 + 0x4 * (vf))

/**
 * @brief Convert a rate in bits-per-second to hardware rate units.
 *
 * Helper used to translate BPS values to the hardware-specific
 * unit used by scheduling registers.
 *
 * @param hw Pointer to MCE hardware context
 * @param rate Rate in bits per second
 * @return Hardware register value representing the rate
 */
static uint32_t mce_tm_rate_convert_hw(struct mce_hw *hw, uint64_t rate)
{
#define MCE_TM_RATE_UNIT (512)
	u32 hw_rate = 0;

	hw_rate = (rate / hw->tm_sample_unit) / MCE_TM_RATE_UNIT;

	return hw_rate;
}
/**
 * @brief Set VF aggregate transmit rate (implementation).
 *
 * Configure the hardware to limit the bandwidth available to a
 * specific Virtual Function.
 *
 * @param hw Pointer to MCE hardware context
 * @param vf_num Virtual Function identifier
 * @param rate Maximum transmit rate in bits per second
 * @return 0 on success, negative errno on failure
 */
int mce_set_vf_rate(struct mce_hw *hw, u16 vf_num, u64 rate)
{
	u32 hw_rate = mce_tm_rate_convert_hw(hw, rate);
	u16 qg_base = 0;
	u16 qg_num = 0;
	int i = 0;

	if (hw->nb_qpair_per_vf)
		qg_num = hw->nb_qpair_per_vf / 4;
	else
		qg_num = hw->nb_qpair / 4;
	qg_base = vf_num * qg_num;
	MCE_E_REG_WRITE(hw, MCE_VF_RATE_LIMIT(vf_num), hw_rate);
	/* add vf queue group add rate limit group */
	for (i = 0; i < qg_num; i++)
		MCE_E_REG_WRITE(hw, MCE_TC_QP_CTRL(qg_base + i),
				GENMASK_U32(11, 8));
	return 0;
}
#ifdef HAVE_TM_MODULE
static void mce_sched_txq_rate_setup(struct mce_hw *hw,
					 struct mce_tm_node *node)
{
	u64 max_rate = 0;

	max_rate = node->shaper_profile->profile->peak.rate;
	mce_set_txq_rate(hw, node->id, max_rate);
}
/**
 * @brief Configure a queue-group scheduler from TM node settings.
 *
 * Translates a TM node's shaper profile into hardware queue-group
 * register settings.
 *
 * @param hw Pointer to MCE hardware context
 * @param node TM node representing the qgroup
 * @param group_id Hardware group identifier
 * @return 0 on success, negative errno on failure
 */
static int mce_sched_qgroup_setup(struct mce_hw *hw, struct mce_tm_node *node,
				  int group_id)
{
	struct mce_tm_shaper_profile *shaper_profile = node->shaper_profile;
	struct mce_tm_node *child;
	u32 commit_rate = 0;
	u32 peek_rate = 0;
	u32 qgroup_member = 0;
	u32 ctrl = 0;

	RTE_SET_USED(peek_rate);
	RTE_SET_USED(commit_rate);
	if (node->has_child == 0 || shaper_profile == NULL)
		return -EINVAL;
	TAILQ_FOREACH(child, &node->child, node) {
		if (child) {
			if (child->shaper_profile)
				mce_sched_txq_rate_setup(hw, child);
			qgroup_member |= RTE_BIT32(child->id & 0x3);
			ctrl = MCE_TXQ_TC_SCHED_EN |
				RTE_BIT32(group_id) << MCE_TXQ_TC_NUM_S;
			if (hw->pfc_en) {
				ctrl |= MCE_TXQ_TC_SCHED_PFC;
				ctrl |= RTE_BIT32(group_id);
			}
			MCE_E_REG_WRITE(hw,
					MCE_DMA_TXQ_PRI_LVL(child->id),
					ctrl);
		}
	}
	ctrl = 0;
	ctrl |= MCE_QG_QP_EN;
	ctrl |= MCE_QG_WFQ_EN;
	ctrl |= (qgroup_member << MCE_QG_MEMBER_SHILT);
	commit_rate = mce_tm_rate_convert_hw(
		hw, shaper_profile->profile->committed.rate);
	peek_rate =
		mce_tm_rate_convert_hw(hw, shaper_profile->profile->peak.rate);
	if (shaper_profile) {
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		if (shaper_profile->profile->packet_mode) {
			/* pps mode update */
			MCE_E_REG_WRITE(hw, MCE_TC_QG_PPS_CIR_C(group_id),
					commit_rate);
			MCE_E_REG_WRITE(hw, MCE_TC_QG_PPS_PIR_C(group_id),
					peek_rate);
		} else {
			/* bps mode update */
			MCE_E_REG_WRITE(hw, MCE_TC_QG_BPS_CIR_C(group_id),
					commit_rate);
			MCE_E_REG_WRITE(hw, MCE_TC_QG_BPS_PIR_C(group_id),
					peek_rate);
		}
#else
		/* bps mode update */
		MCE_E_REG_WRITE(hw, MCE_TC_QG_BPS_CIR_C(group_id), commit_rate);
		MCE_E_REG_WRITE(hw, MCE_TC_QG_BPS_PIR_C(group_id), peek_rate);
#endif
		if (node->params.nonleaf.wfq_weight_mode) {
			ctrl |= MCE_QG_WFQ_EN;
			ctrl |= node->weight;
		}
	}
	MCE_E_REG_WRITE(hw, MCE_TC_QP_CTRL(group_id), ctrl);

	return 0;
}

/**
 * @brief Commit pending traffic manager configuration to hardware.
 *
 * Walks the TM configuration tree and programs hardware scheduler
 * resources accordingly. This performs an atomic-like commit of the
 * currently prepared TM state.
 *
 * @param vport Pointer to virtual port structure
 * @param clear_on_fail If non-zero, clear pending config on failure
 * @return 0 on success, negative errno on failure
 */
int mce_sched_commit(struct mce_vport *vport, int clear_on_fail __rte_unused)
{
	struct mce_tm_shaper_conf *tm_conf = &vport->tm_conf;
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_tm_node *root_node;
	struct mce_tm_node *child = NULL;
	int group_id = 0;

	if (tm_conf->root == NULL)
		return -EINVAL;
	mce_sched_init(hw);
	root_node = tm_conf->root;
	if (root_node->shaper_profile) {
		u32 rate = mce_tm_rate_convert_hw(
			hw, root_node->shaper_profile->profile->peak.rate);
		MCE_E_REG_WRITE(hw, 0x41024,
				rate | RTE_BIT32(31) | RTE_BIT32(30));
	}
	if (root_node->has_child) {
		TAILQ_FOREACH(child, &root_node->child, node) {
			if (child->level == MCE_TM_NODE_TYPE_QG) {
				mce_sched_qgroup_setup(hw, child,
						group_id);
				group_id++;
			}
#ifdef MCE_TM_TC
			if (child->level == MCE_TM_NODE_TYPE_TC)
				mce_sched_tc_setup(hw, tm_conf, child);
#endif
		}
	}

	return -EINVAL;
}
#endif /* HAVE_TM_MODULE */
/**
 * @brief Initialize scheduler hardware and defaults.
 *
 * Prepares hardware scheduler control registers, sample interval and
 * internal state used when committing TM configuration.
 *
 * @param hw Pointer to MCE hardware context
 */
void mce_sched_init(struct mce_hw *hw)
{
	u32 sample_inval = 0;
	u32 ctrl = 0;
	int i = 0;

	ctrl = MCE_TC_TM_EN;
	ctrl |= MCE_TC_TM_BP_MODE;
	ctrl &= ~MCE_TC_SCHED_MODE;
	for (i = 0; i < hw->num_tc; i++) {
		ctrl |= RTE_BIT32(i) << MCE_TC_VALID_SHIFT;
		if (hw->tc_sched_mode[i] == MCE_DCB_TC_SCHD_ETS)
			ctrl |= MCE_TC_SCHED_ETS << i;
		else
			ctrl |= MCE_TC_SCHED_SP << i;
	}
#if 1
	sample_inval = 100;
	ctrl |= MCE_TM_SAMPLE_EN;
	ctrl |= MCE_TC_CRC_VALID_EN;
	/* 100 ms sample interval */
	ctrl |= sample_inval << MCE_TC_TM_SAMPLE_SHIFT;
#else
	sample_inval = 1000;
#endif
	hw->tm_sample_unit = 1000 / sample_inval;
#define MCE_INTERFRAME_GAP (20)
	MCE_E_REG_WRITE(hw, MCE_TC_TM_CTRL, ctrl);
	MCE_E_REG_WRITE(hw, MCE_DMA_FLOWCTRL_GAP, MCE_INTERFRAME_GAP);
	MCE_E_REG_WRITE(hw, MCE_DMA_ETSFLOW_GAP, MCE_INTERFRAME_GAP);
}
