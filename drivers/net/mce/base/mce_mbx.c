/**
 * @file mce_mbx.c
 * @brief Mailbox (MBX) communication protocol implementation
 *
 * Implements PF<->VF and PF<->FW mailbox communication protocols over
 * shared memory regions with reliable message passing, timeout handling,
 * and retry mechanisms.
 *
 * Mailbox Channels:
 * - VF2PF: VF requests to PF with responses
 * - PF2FW: PF commands to firmware with responses
 * - FW2PF: Firmware notifications to PF
 *
 * Key Features:
 * - Shared memory based communication (no PCIe payload)
 * - Automatic retry on timeout
 * - Lock mechanism for multi-VF scenarios
 * - Message versioning
 * - Isolated vs non-isolated VF support
 * - Interrupt-driven notification
 *
 * Message Types:
 * - Device capability queries
 * - Queue configuration and management
 * - MAC address assignment
 * - Link state notification
 * - Statistics collection
 * - Reset and recovery
 * - Trust mode and spoofing control
 *
 * @see mce_mbx.h for public API and message definitions
 * @see mce_pfvf.h for PF-VF data structures
 */

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hexdump.h>

#include "mce_mbx.h"
#include "mce_irq.h"
#include "mce_hw.h"
#include "mce_pfvf.h"
#include "mce_common.h"

#include "../mce_logs.h"

/* ============MBX ==== */
#define N20_MBX_BASE	 (0x20000 + 0x10000)
#define N20_MBX_OFF(off) (N20_MSIX_MBX_BASE + (off))

#define PF2FW_SHM_SZ	 64
#define PF2FW_SHM	 0x6000
#define PF2FW_MBX_CTRL	 (0x6100)

#define FW2PF_SHM_SZ	 64
#define FW2PF_SHM	 (0x6040)
#define FW2PF_MBX_CTRL	 (0x6200)
#define FW2PF_MB_VEC	 0x8600

#define PF2VF_SHM_SIZE	 32
#define PF2VF_SHM(nr_vf) \
	(0x4000 + (nr_vf) * PF2VF_SHM_SIZE) /* CPU2VF_SHM,pf as CPU */
#define PF2VF_SHM(nr_vf) \
	(0x4000 + (nr_vf) * PF2VF_SHM_SIZE) /* CPU2VF_SHM,pf as CPU */
#define PF2VF_SHM_LOCK(nr_vf) \
	(0x5200 + (nr_vf) * 4) /* CPU2VF_MBX_CTRL, pf as cpu */
#define PF2VF_REQ_CTRL(nr_vf) (0x2200 + (nr_vf) * 4)

#define VF2PF_SHM_SIZE	      64
#define VF2PF_SHM(nr_vf)      (0x0000 + (nr_vf) * VF2PF_SHM_SIZE)
#define VF2PF_SHM_LOCK(nr_vf) (0x2200 + (nr_vf) * 4)
#define VF2PF_REQ_CTRL(nr_vf) (0x2000 + (nr_vf) * 4)
#define VF2PF_MB_VEC(nr_vf)   (0x8200 + (nr_vf) * 4)

#define VF2PF_REQ_ST0	      (0x2500)

/* === vf2pf isolated disabled == */
#define PF2VF_SHM_NO_ISOLATED(nr_vf) \
	(0x4000 + (nr_vf) * PF2VF_SHM_SIZE) /* CPU3VF_SHM,pf as CPU */
#define PF2VF_SHM_LOCK_NO_ISOLATED(nr_vf) \
	(0x5000 + (nr_vf) * 4) /* VF2CPU_MBX_CTRL, pf as cpu */
#define PF2VF_REQ_CTRL_NO_ISOLATED(nr_vf) (0x2200 + (nr_vf) * 4)
#define PF2VF_MB_VEC_NO_ISOLATED(nr_vf)	  (0x8000 + (nr_vf) * 4)

#define VF2PF_SHM_NO_ISOLATED(nr_vf)	  (0x0000 + (nr_vf) * VF2PF_SHM_SIZE)
#define VF2PF_SHM_LOCK_NO_ISOLATED(nr_vf) (0x2000 + (nr_vf) * 4)
#define VF2PF_REQ_CTRL_NO_ISOLATED(nr_vf) (0x2000 + (nr_vf) * 4)

/* === vf2pf isolated enabled == */
#define PF2VF_SHM_ISOLATED		  (0x19800) /* CPU2VF_SHM,pf as CPU */
#define PF2VF_SHM_LOCK_ISOLATED		  (0x1a000) /* VF2CPU_MBX_CTRL, pf as cpu */
#define PF2VF_REQ_CTRL_ISOLATED		  (0x19000)
#define PF2VF_MB_VEC_ISOLATED		  (0x1c000)

#define VF2PF_SHM_ISOLATED		  (0x18000)
#define VF2PF_SHM_LOCK_ISOLATED		  (0x18800)
#define VF2PF_REQ_CTRL_ISOLATED		  VF2PF_SHM_LOCK_ISOLATED

/* ==== common flags === */
#define MBX_CTRL_REQ_IRQ_MSK		  BIT(0) /* WO */
#define MBX_CTRL_FW_HOLD_PF_SHM_MSK	  BIT(2) /* PFU:RO, CFU:WR */
#define MBX_CTRL_FW_HOLD_PF_SHM		  BIT(2) /* PFU:RO, CFU:WR */
#define MBX_CTRL_FW_HOLD_VF_SHM_MSK	  BIT(3) /* CFU:RW, VFU:RO */
#define MBX_CTRL_FW_HOLD_VF_SHM		  BIT(3) /* CFU:RW, VFU:RO */
#define MBX_CTRL_IRQ_MSK		  BIT(4)

#define MBX_CTRL_PFFW_REQ_STAT_SHIFT	  (5)
#define MBX_CTRL_PFFW_REQ_STAT_MSK	  (0b11 << MBX_CTRL_PFFW_REQ_STAT_SHIFT)
#define MBX_CTRL_GET_PF_REQ_STAT(v) \
	(((v) & MBX_CTRL_PFFW_REQ_STAT_MSK) >> MBX_CTRL_PFFW_REQ_STAT_SHIFT)

#define MBX_CTRL_PFFW_EVENT_ID_SHIFT (12)
#define MBX_CTRL_PFFW_EVENT_ID_MASK  (0b1111 << MBX_CTRL_PFFW_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_PFFW_EVENT_ID(v) \
	(((v) & MBX_CTRL_PFFW_EVENT_ID_MASK) >> MBX_CTRL_PFFW_EVENT_ID_SHIFT)

/* === PF2FW MBX FLAGS == */
#define MBX_CTRL_PF2FW_REQ_STAT_SHIFT		  (5)
#define MBX_CTRL_PF2FW_REQ_STAT_MSK		  (0b11 << MBX_CTRL_PF2FW_REQ_STAT_SHIFT)
#define MBX_CTRL_PF2FW_STAT_VALID_SHIFT		  7
#define MBX_CTRL_PF2FW_STAT_VALID_MSK		  BIT(MBX_CTRL_PF2FW_STAT_VALID_SHIFT)
#define MBX_CTRL_PF2FW_STAT_VALID		  MBX_CTRL_PF2FW_STAT_VALID_MSK
#define MBX_CTRL_PF2FW_LINK_STAT_SHIFT		  (8)
#define MBX_CTRL_PF2FW_LINK_STAT_MSK		  BIT(MBX_CTRL_PF2FW_LINK_STAT_SHIFT)
#define MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_EN_SHIFT 10
#define MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_MSK \
	BIT(MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_EN_SHIFT)
#define MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_EN_SHIFT 11
#define MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_MSK \
	BIT(MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_EN_SHIFT)
#define MBX_CTRL_PF2FW_EVENT_ID_SHIFT	     (12)
#define MBX_CTRL_PF2FW_EVENT_ID_MASK	     (0b1111 << MBX_CTRL_PF2FW_EVENT_ID_SHIFT)

/* === FW2PF MBX CTRL == */
#define MBX_CTRL_FW2PF_REQ_STAT_SHIFT	     (5)
#define MBX_CTRL_FW2PF_REQ_STAT_MSK	     (0b11 << MBX_CTRL_FW2PF_REQ_STAT_SHIFT)
#define MBX_CTRL_FW2PF_STAT_VALID_MSK	     BIT(7)
#define MBX_CTRL_FW2PF_STAT_VALID	     BIT(7)
#define MBX_CTRL_FW2PF_FW_LINKUP_MSK	     BIT(8)
#define MBX_CTRL_FW2PF_FW_NIC_RESET_DONE_MSK BIT(9)
#define MBX_CTRL_FW2PF_NR_PF_MSK	     BIT(10)
#define MBX_CTRL_FW2PF_EVENT_ID_SHIFT	     (12)
#define MBX_CTRL_FW2PF_EVENT_ID_MASK	     (0b1111 << MBX_CTRL_FW2PF_EVENT_ID_SHIFT)

#define MBX_IRQ_EN			     (0 << 4)
#define MBX_IRQ_DISABLE			     (1 << 4)

/* ==== PF2VF MBX FLAGS == */
#define MBX_CTRL_PF2VF_REQ_STAT_SHIFT	     (5)
#define MBX_CTRL_PF2VF_REQ_STAT_MSK	     (0b11 << MBX_CTRL_PF2VF_REQ_STAT_SHIFT)
#define MBX_CTRL_PF2VF_STAT_VALID_SHIFT	     7
#define MBX_CTRL_PF2VF_STAT_VALID_MSK	     BIT(MBX_CTRL_PF2VF_STAT_VALID_SHIFT)
#define MBX_CTRL_PF2VF_STAT_VALID	     MBX_CTRL_PF2VF_STAT_VALID_MSK
#define MBX_CTRL_PF2VF_LINK_STAT_SHIFT	     8
#define MBX_CTRL_PF2VF_LINK_STAT_MSK	     BIT(MBX_CTRL_PF2VF_LINK_STAT_SHIFT)
#define MBX_CTRL_PF2VF_SPEED_SHIFT	     9
#define MBX_CTRL_PF2VF_PF_SPEED_MSK	     (0b111 << MBX_CTRL_PF2VF_SPEED_SHIFT)
#define MBX_CTRL_PF2VF_EVENT_ID_SHIFT	     (12)
#define MBX_CTRL_PF2VF_EVENT_ID_MASK	     (0b1111 << MBX_CTRL_PF2VF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_PF2VF_EVENT_ID(v) \
	(((v) & MBX_CTRL_PF2VF_EVENT_ID_MASK) >> MBX_CTRL_PF2VF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_PF2VF_REQ_STAT(v) \
	(((v) & MBX_CTRL_PF2VF_REQ_STAT_MSK) >> MBX_CTRL_PF2VF_REQ_STAT_SHIFT)

/* === VF2PF MBX CTRL == */
#define MBX_CTRL_VF2PF_REQ_ST_CLR_SHIFT	   5
#define MBX_CTRL_VF2PF_REQ_ST_CLR_MSK	   BIT(MBX_CTRL_VF2PF_REQ_ST_CLR_SHIFT)
#define MBX_CTRL_VF2PF_REQ_STAT_SHIFT	   (6)
#define MBX_CTRL_VF2PF_REQ_STAT_MSK	   (0b11 << MBX_CTRL_VF2PF_REQ_STAT_SHIFT)
#define MBX_CTRL_VF2PF_STAT_VALID_MSK	   BIT(8)
#define MBX_CTRL_VF2PF_STAT_VALID	   MBX_CTRL_VF2PF_STAT_VALID_MSK
#define MBX_CTRL_VF2PF_RESET_DONE_SHIFT	   (9)
#define MBX_CTRL_VF2PF_RESET_DONE_MSK	   BIT(MBX_CTRL_VF2PF_RESET_DONE_SHIFT)
#define MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT 10
#define MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK   BIT(MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT)
#define MBX_CTRL_VF2PF_EVENT_ID_SHIFT	   (13)
#define MBX_CTRL_VF2PF_EVENT_ID_MASK	   (0b111 << MBX_CTRL_VF2PF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_VF2PF_EVENT_ID(v) \
	(((v) & MBX_CTRL_VF2PF_EVENT_ID_MASK) >> MBX_CTRL_VF2PF_EVENT_ID_SHIFT)
#define MBX_CTRL_GET_VF2PF_REQ_STAT(v) \
	(((v) & MBX_CTRL_VF2PF_REQ_STAT_MSK) >> MBX_CTRL_VF2PF_REQ_STAT_SHIFT)

#define MBX_SEND_REQ_WITH_IRQ BIT(0)

#if 1
#else
#define mbx_rd32(reg)	   prd32((reg))
#define mbx_wr32(reg, val) pwr32((reg), (val))
#endif
#define mbx_wr32_masked(reg, mask16, val16) \
        mbx_wr32((reg), ((val16) & 0xFFFF) | (((uint32_t)(mask16) << 16)))
static inline int test_bit(uint32_t bit, uint32_t *bit_array)
{
	uint32_t word_index = bit / 32;
	uint32_t bit_offset = bit % 32;

	return (bit_array[word_index] >> bit_offset) & 1;
}


void mce_mbx_clear_peer_req_irq_with_stat(struct mce_mbx_info *mbx,
					  enum MBX_REQ_STAT stat)
{
	switch (mbx->dst) {
	case MBX_PF2VF: {
		mbx_wr32_masked(mbx->peer2thiz_ctrl,
				MBX_CTRL_VF2PF_REQ_STAT_MSK |
					MBX_CTRL_REQ_IRQ_MSK,
				(stat << MBX_CTRL_VF2PF_REQ_STAT_SHIFT) | 0);
		break;
	}
	case MBX_PF2FW: {
		mbx_wr32_masked(mbx->peer2thiz_ctrl,
				MBX_CTRL_PFFW_REQ_STAT_MSK |
					MBX_CTRL_REQ_IRQ_MSK,
				(stat << MBX_CTRL_PFFW_REQ_STAT_SHIFT) | 0);
		break;
	}
	case MBX_VF2PF: {
		mbx_wr32_masked(mbx->peer2thiz_ctrl,
				MBX_CTRL_PF2VF_REQ_STAT_MSK |
					MBX_CTRL_REQ_IRQ_MSK,
				(stat << MBX_CTRL_PF2VF_REQ_STAT_SHIFT) | 0);
	} break;
	}
}

#if 0
static void
mce_mbx_clear_peer_req_irq_with_no_stat_change(struct mce_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->peer2thiz_ctrl, MBX_CTRL_REQ_IRQ_MSK, 0);
}
#endif
/**
 * @brief Acquire request shared-memory lock with timeout.
 *
 * Tries to acquire the request shared-memory lock for `mbx` and waits
 * up to `timeout_us` microseconds. Returns 0 on success or -ETIMEDOUT
 * on timeout.
 *
 * @param mbx Mailbox info pointer
 * @param timeout_us Timeout in microseconds (0 for immediate)
 * @return 0 on success, -ETIMEDOUT on timeout
 */
static inline int mce_mbx_get_req_shm_lock(struct mce_mbx_info *mbx,
				   int timeout_us)
{
	while (1) {
		mbx_wr32_masked(mbx->thiz2peer_shm_lock,
				mbx->thiz2peer_shm_lock_msk,
				mbx->thiz2peer_shm_lock_msk);
		rte_mb();
		if (mbx_rd32(mbx->thiz2peer_shm_lock) &
		    mbx->thiz2peer_shm_lock_msk) {
			return 0;
		}

		if (timeout_us > 0) {
			rte_delay_us(1);
			timeout_us--;
		} else {
			break;
		}
	}
	rte_errno = ETIMEDOUT;
	return -ETIMEDOUT;
}

/**
 * @brief Release the request shared-memory lock.
 *
 * Releases the lock taken by `mce_mbx_get_req_shm_lock` so the peer can
 * access the shared request memory.
 *
 * @param mbx Mailbox info pointer
 */
static void mce_mbx_put_req_shm_lock(struct mce_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->thiz2peer_shm_lock, mbx->thiz2peer_shm_lock_msk,
				0);
}

/**
 * @brief Acquire peer shared-memory lock with timeout.
 *
 * Attempts to acquire the peer->this shared-memory lock for `mbx`.
 *
 * @param mbx Mailbox info pointer
 * @param timeout_us Timeout in microseconds
 * @return 0 on success, -ETIMEDOUT on timeout
 */
static int mce_mbx_get_peer_shm_lock(struct mce_mbx_info *mbx, int timeout_us)
{
	while (1) {
		mbx_wr32_masked(mbx->peer2thiz_shm_lock,
				mbx->peer2thiz_shm_lock_msk,
				mbx->peer2thiz_shm_lock_msk);
		rte_mb();
		if (mbx_rd32(mbx->peer2thiz_shm_lock) &
		    mbx->peer2thiz_shm_lock_msk) {
			return 0;
		}

		if (timeout_us > 0) {
			rte_delay_us(1);
			timeout_us--;
		} else {
			break;
		}
	}

	rte_errno = ETIMEDOUT;
	return -ETIMEDOUT;
}

/**
 * @brief Release peer shared-memory lock.
 *
 * Releases the peer-to-this shared-memory lock so the peer can proceed.
 *
 * @param mbx Mailbox info pointer
 */
static inline void mce_mbx_put_peer_shm_lock(struct mce_mbx_info *mbx)
{
	mbx_wr32_masked(mbx->peer2thiz_shm_lock, mbx->peer2thiz_shm_lock_msk,
				0);
}

/**
 * @brief Initialize mailbox configuration and clear shared memory.
 *
 * Sets initial control register values, clears shared memory region and
 * releases any locks so mailbox is ready for use.
 *
 * @param mbx Pointer to mailbox info structure
 * @return 0 on success
 */
int mce_mbx_init_configure(struct mce_mbx_info *mbx)
{
	int i;
#define MCE_MBX_EVENT_MASK RTE_GENMASK32(15, 0)
	mbx_wr32_masked(mbx->thiz2peer_ctrl, MCE_MBX_EVENT_MASK, 0);
	/* disable (vf/fw mbx irq to pf) or  (pf to vf) */
	if (mbx->irq_enabled)
		mbx_wr32_masked(mbx->peer2thiz_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_EN);
	else
		mbx_wr32_masked(mbx->peer2thiz_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_DISABLE);
	logd(LOG_MISC_IRQ, "%s: %s vector:%d enable:%d\n", __func__, mbx->name,
	     0, mbx->irq_enabled);

	/* clear req-shm to 0 */
	for (i = 0; i < mbx->thiz_req_shm_size / 4; i++)
		mbx_wr32(mbx->thiz2peer_shm + i * 4, 0);

	/* release (pf to vf/fw) or (vf to pf) shm lock (if have) */
	mbx_wr32_masked(mbx->thiz2peer_shm_lock, mbx->thiz2peer_shm_lock_msk,
				0);
	mbx_wr32(mbx->thiz2peer_shm, 0);

	/* release (vf/fw to pf) or ( pf to vf) shm lock (if have) */
	mbx_wr32_masked(mbx->peer2thiz_shm_lock, mbx->peer2thiz_shm_lock_msk,
				0);

	return 0;
}

/**
 * @brief Reset mailbox configuration for the device.
 *
 * Reinitializes PF/FW and PF/VF mailbox instances by calling
 * `mce_mbx_init_configure` appropriately for PF and VFs.
 *
 * @param hw Pointer to MCE hardware structure
 */
void mce_mbx_reset(struct mce_hw *hw)
{
	if (hw->is_vf) {
		mce_mbx_init_configure(&hw->vf2pf_mbx);
	} else {
		int i;
		mce_mbx_init_configure(&hw->pf2fw_mbx);

		for (i = 0; i < hw->max_vfs; i++)
			mce_mbx_init_configure(&hw->pf2vf_mbx[i]);
	}
}

/**
 * @brief Enable or disable mailbox interrupt vector and update state.
 *
 * @param mbx Pointer to mailbox info structure
 * @param nr_vector Vector number to program
 * @param enable True to enable, false to disable
 * @return 0 on success
 */
int mce_mbx_vector_set(struct mce_mbx_info *mbx, int nr_vector, bool enable)
{
	if (enable) {
		mbx_wr32(mbx->mbx_vec_base, nr_vector);
		mbx_wr32_masked(mbx->peer2thiz_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_EN);
		mbx->irq_enabled = true;
	} else {
		mbx_wr32_masked(mbx->peer2thiz_ctrl, MBX_CTRL_IRQ_MSK,
				MBX_IRQ_DISABLE);
		mbx->irq_enabled = false;
	}
	logd(LOG_MISC_IRQ, "%s: %s vector:%d enable:%d v:0x%x\n", __func__, mbx->name,
	     nr_vector, enable, mbx_rd32(mbx->peer2thiz_ctrl));

	if (mbx->hw->is_vf)
		mcevf_mbx_set_vf2pf_stat(mbx->hw);
	else
		mce_mbx_set_pf_stat_reg(mbx->hw);

	return 0;
}

/**
 * @brief Update cached firmware statistics from hardware registers.
 *
 * Reads firmware status registers and updates the `hw->fw_stat` cache.
 *
 * @param hw Pointer to MCE hardware structure
 */
void mce_update_fw_stat(struct mce_hw *hw)
{
	hw->fw_stat.stat0.v = _rd32(hw->dm_stat);
	hw->fw_stat.stat1.v = _rd32(hw->nic_stat);
	hw->fw_stat.stat2.ext.v =
		_rd32(hw->ext_stat + offsetof(struct ext_stat, ext));
}

/**
 * @brief Set mailbox vector for all VF->PF mailboxes.
 *
 * Iterates over all VFs and programs their mailbox interrupt vector.
 *
 * @param hw Pointer to MCE hardware structure
 * @param nr_vector Vector number to program
 * @param enable True to enable, false to disable
 * @return 0 on success
 */
int mce_pf_set_all_vf2pf_mbx_vector(struct mce_hw *hw, int nr_vector,
				    bool enable)
{
	int i;

	for (i = 0; i < hw->max_vfs; i++)
		mce_mbx_vector_set(&hw->pf2vf_mbx[i], nr_vector, enable);

	return 0;
}

int mce_mbx_send_event(struct mce_mbx_info *mbx, int event_id, int timeout_us)
{
	int ret = 0;
	int need_lock = timeout_us ? 1 : 0;

	if (need_lock)
		rte_spinlock_lock(&mbx->req_lock);

	if (mbx->dst == MBX_PF2VF)
		mbx_wr32_masked(mbx->thiz2peer_ctrl,
				MBX_CTRL_PF2VF_EVENT_ID_MASK |
					MBX_CTRL_PF2VF_REQ_STAT_MSK |
					MBX_CTRL_REQ_IRQ_MSK,
				(event_id << MBX_CTRL_PF2VF_EVENT_ID_SHIFT) |
					(EVENT_REQ
					 << MBX_CTRL_PF2VF_REQ_STAT_SHIFT) |
					MBX_SEND_REQ_WITH_IRQ);
	else if (mbx->dst == MBX_PF2FW)
		mbx_wr32_masked(mbx->thiz2peer_ctrl,
				MBX_CTRL_PFFW_EVENT_ID_MASK |
					MBX_CTRL_PFFW_REQ_STAT_MSK |
					MBX_CTRL_REQ_IRQ_MSK,
				(event_id << MBX_CTRL_PFFW_EVENT_ID_SHIFT) |
					(EVENT_REQ
					 << MBX_CTRL_PFFW_REQ_STAT_SHIFT) |
					MBX_SEND_REQ_WITH_IRQ);
	else if (mbx->dst == MBX_VF2PF)
		mbx_wr32_masked(mbx->thiz2peer_ctrl,
				MBX_CTRL_VF2PF_EVENT_ID_MASK |
					MBX_CTRL_VF2PF_REQ_STAT_MSK |
					MBX_CTRL_REQ_IRQ_MSK,
				(event_id << MBX_CTRL_VF2PF_EVENT_ID_SHIFT) |
					(EVENT_REQ
					 << MBX_CTRL_VF2PF_REQ_STAT_SHIFT) |
					MBX_SEND_REQ_WITH_IRQ);
	mbx->stats.tx_event_cnt++;

	if (timeout_us == 0) {
		ret = 0;
		goto quit;
	}

	/* wait ack */
	ret = -ETIMEDOUT;
	while (timeout_us > 0) {
		int stat;
		u32 v = mbx_rd32(mbx->thiz2peer_ctrl);
		if (mbx->dst == MBX_VF2PF)
			stat = MBX_CTRL_GET_VF2PF_REQ_STAT(v);
		else
			stat = MBX_CTRL_GET_PF_REQ_STAT(v);

		if (stat != EVENT_REQ) {
			if (stat == RESP_OR_ACK)
				ret = 0;
			else
				ret = -EIO;
			break;
		}
		rte_delay_us(10);
		timeout_us -= 10;
	}

	if (ret != 0) {
		mbx->stats.tx_event_err_cnt++;
		rte_errno = EIO;
	}

quit:
	if (need_lock)
		rte_spinlock_unlock(&mbx->req_lock);

	return ret;
}

int mce_mbx_send_resp_isr(struct mce_mbx_info *mbx, struct mbx_resp *resp)
{
	int i, total_sz, ret = 0;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;

	if (!mbx || !resp) {
		PMD_HW_ERR(mbx->hw,
			   "%s:%s should be called in interrupt ctx. opcode:%d "
			   "arg_cnt:%d\n",
			   __func__, mbx->name, resp->cmd.opcode,
			   resp->cmd.arg_cnts);
		stat = HAS_ERR;
		ret = -EINVAL;
		goto quit;
	}

	/* 	 no lock needed, as can only be called from irq handler */
	if (!resp->cmd.flag_no_resp) {
		total_sz = resp->cmd.arg_cnts * 4 +
			   offsetof(struct mbx_resp, data);
		if (total_sz > mbx->peer_req_shm_size) {
			PMD_HW_ERR(
				mbx->hw,
				"%s:%s opcode:%d  total_sz:%d > max size:%d\n",
				__func__, mbx->name, resp->cmd.opcode, total_sz,
				mbx->peer_req_shm_size);
			stat = HAS_ERR;
			ret = -EINVAL;
			goto quit;
		}

		logd_if(LOG_MBX_IN_REQ) {
			printf("\n== %s shm:0x%x==\n", mbx->name,
			       (int)mbx_info_reg_bar_off(mbx,
							 mbx->peer2thiz_shm));
			rte_hexdump(stdout, "req-in-resp: ", (char *)resp,
				    total_sz);
		}

		if (mce_mbx_get_peer_shm_lock(mbx, 200) < 0) { /* 200us */
			PMD_HW_ERR(
				mbx->hw,
				"%s:%s get resp shm lock timeout.opcode:%d\n",
				__func__, mbx->name, resp->cmd.opcode);
			mbx->stats.rx_resp_shm_lock_timeout++;
			stat = HAS_ERR;
			ret = -ETIMEDOUT;
			goto quit;
		}

		for (i = 0; i < total_sz / 4; i++)
			mbx_wr32(mbx->peer2thiz_shm + i * 4, ((int *)resp)[i]);
		rte_mb();
		mce_mbx_put_peer_shm_lock(mbx);
	}

quit:
	mce_mbx_clear_peer_req_irq_with_stat(mbx, stat);

	return ret;
}

static int mce_mbx_read_incomming_req_isr(struct mce_mbx_info *mbx,
					  struct mbx_req *req)
{
	int total_sz, i;
	unsigned int *req_arr = (unsigned int *)req;

	if (!req || !mbx)
		return -EINVAL;

	if (mce_mbx_get_peer_shm_lock(mbx, 200) < 0) { /* 200us */
		PMD_HW_ERR(mbx->hw, "%s:%s get req shm lock timeout\n",
			   __func__, mbx->name);
		mbx->stats.rx_req_shm_lock_timeout++;
		return -ETIMEDOUT;
	}

	req_arr[0] = mbx_rd32(mbx->peer2thiz_shm);
	rmb();
	if (req->cmd.arg_cnts > (sizeof(req->data) / 4) ||
	    req->cmd.arg_cnts > (mbx->peer_req_shm_size / 4)) {
		PMD_HW_ERR(
			mbx->hw,
			"%s:%s opcode req hdr arg_cnts:%d, cmd:0x%x error!\n",
			__func__, mbx->name, req->cmd.arg_cnts, req->cmd.v);
		mce_mbx_put_peer_shm_lock(mbx);
		return -EIO;
	}

	total_sz = offsetof(struct mbx_req, data) + req->cmd.arg_cnts * 4;

	/* disable irq && schedule */
	rte_spinlock_lock(&mbx->peer_shm_lock);
	for (i = 0; i < total_sz / 4; i++) {
		req_arr[i] = mbx_rd32(mbx->peer2thiz_shm + i * 4);
	}
	rte_rmb();
	/* set to 0 */
	mbx_wr32(mbx->peer2thiz_shm + 0, 0);
	rte_mb();
	mce_mbx_put_peer_shm_lock(mbx);
	rte_spinlock_unlock(&mbx->peer_shm_lock);

	logd_if(LOG_MBX_IN_REQ) {
		printf("\n== %s ==\n", mbx->name);
		rte_hexdump(stdout, "req-in: ", req, total_sz);
	}

	return total_sz;
}

int mce_mbx_clean_all_incomming_req(struct mce_hw *hw,
				    mbx_event_req_cb *event_cb,
				    mbx_req_with_data_cb *req_cb)
{
	unsigned int i, v, stat = 0, mbx_cnt = 0;
	struct mce_mbx_info *mbx;
	struct mce_mbx_info *irq_valid_mbxs[128 + 1] = { NULL };

	if (!event_cb || !hw || !req_cb)
		return -EINVAL;

	if (hw->is_vf == 0) { /*  PF */
		unsigned int vf_req_status[4] = { 0 };
		unsigned int sum = 0;

		/* get vf2pf mbx irq status */
		if (hw->max_vfs > 0)
			for (i = 0; i < ARRAY_SIZE(vf_req_status); i++) {
				vf_req_status[i] = mbx_rd32(
					hw->pf2fw_mbx.vf2pf_irq_stat + i * 4);
			}

		/* + PF2FW mailbox */
		irq_valid_mbxs[mbx_cnt++] = &hw->pf2fw_mbx;
		sum = vf_req_status[0]+ vf_req_status[1]+vf_req_status[2]+vf_req_status[3];
		if(sum)
			logd(LOG_MBX_IN_REQ, "\nvf_req_st:%08x %08x %08x %08x\n",
				vf_req_status[0], vf_req_status[1], vf_req_status[2],
				vf_req_status[3]);

		/* + PF2VF mailbox(if have req) */
		for (i = 0; i < hw->max_vfs; i++) {
			if (test_bit(i, vf_req_status)) {
				/* check if vf has req 2pf*/
				irq_valid_mbxs[mbx_cnt++] = &hw->pf2vf_mbx[i];
				/* clear st irq */
				mbx_wr32_masked(hw->pf2vf_mbx[i].peer2thiz_ctrl,
						MBX_CTRL_VF2PF_REQ_ST_CLR_MSK,
						MBX_CTRL_VF2PF_REQ_ST_CLR_MSK);
				rte_mb();
				mbx_wr32_masked(hw->pf2vf_mbx[i].peer2thiz_ctrl,
						MBX_CTRL_VF2PF_REQ_ST_CLR_MSK,
						0);
			}
		}
	} else { /* VF2PF */
		irq_valid_mbxs[mbx_cnt++] = &hw->vf2pf_mbx;
	}

	for (i = 0; i < mbx_cnt; i++) {
		mbx = irq_valid_mbxs[i];

		v = mbx_rd32(mbx->peer2thiz_ctrl);
		if (mbx->dst == MBX_PF2VF) /* VF2pf req */
			stat = MBX_CTRL_GET_VF2PF_REQ_STAT(v);
		else if (mbx->dst == MBX_PF2FW) /* fw2pf req */
			stat = MBX_CTRL_GET_PF_REQ_STAT(v);
		else /* pf2vf req */
			stat = MBX_CTRL_GET_PF2VF_REQ_STAT(v);

		if (stat == EVENT_REQ) {
			int event_id;
			if (mbx->dst == MBX_PF2VF)
				event_id = MBX_CTRL_GET_VF2PF_EVENT_ID(v);
			else if (mbx->dst == MBX_PF2FW)
				event_id = MBX_CTRL_GET_PFFW_EVENT_ID(v);
			else
				event_id = MBX_CTRL_GET_PF2VF_EVENT_ID(v);

			mce_mbx_clear_peer_req_irq_with_stat(mbx, RESP_OR_ACK);
			logd(LOG_MBX_IN_REQ, "\n%s: get event:%d\n", mbx->name,
			     event_id);
			event_cb(mbx, event_id);
		} else if (stat == REQ_WITH_DATA) {
			struct mbx_req req = {};

			int total_size =
				mce_mbx_read_incomming_req_isr(mbx, &req);
			if (total_size < 0)
				mce_mbx_clear_peer_req_irq_with_stat(mbx,
								     HAS_ERR);
			else
				req_cb(mbx, &req);
		}
	}
	return 0;
}

static int mce_mbx_req_read_resp_out(struct mce_mbx_info *mbx,
				     struct mbx_resp *resp)
{
	int total_sz, i;
	unsigned int *resp_arr = (unsigned int *)resp;

	if (!resp)
		return -EINVAL;

	resp_arr[0] = mbx_rd32(mbx->thiz2peer_shm);
	rmb();
	if (resp->cmd.arg_cnts > (sizeof(resp->data) / 4) ||
	    resp->cmd.arg_cnts > (mbx->thiz_req_shm_size / 4)) {
		PMD_HW_ERR(mbx->hw,
			   "%s: opcode resp hdr arg_cnts:%d, 0x%x error!\n",
			   __func__, resp->cmd.arg_cnts, resp->cmd.v);
		return -EIO;
	}

	total_sz = offsetof(struct mbx_resp, data) + resp->cmd.arg_cnts * 4;

	if (mce_mbx_get_req_shm_lock(mbx, 1000) < 0) { /* 1ms */
		PMD_HW_ERR(mbx->hw, "%s: get req shm lock timeout\n", __func__);
		mbx->stats.tx_shm_lock_timeout++;
		return -ETIMEDOUT;
	}
	/* disable irq && schedule after get mbx share memory hw-lock */
	rte_spinlock_lock(&mbx->thiz_req_shm_lock);
	for (i = 1; i < total_sz / 4; i++)
		resp_arr[i] = mbx_rd32(mbx->thiz2peer_shm + i * 4);

	rte_rmb();
	mbx_wr32(mbx->thiz2peer_shm + 0, 0); /* clear opcode */
	rte_mb();
	mce_mbx_put_req_shm_lock(mbx);
	rte_spinlock_unlock(&mbx->thiz_req_shm_lock);

	logd_if(LOG_MBX_REQ_OUT) {
		printf("\n== %s ==\n", mbx->name);
		rte_hexdump(stdout, "req-resp: ", resp_arr, total_sz);
	}

	return total_sz;
}

int mce_mbx_send_req(struct mce_mbx_info *mbx, int opcode, unsigned int *data,
		     int data_bytes, struct mbx_resp *resp, int timeout_us)
{
	struct mbx_req req = {};
	int i, total_sz = data_bytes + offsetof(struct mbx_req, data);
	int ret = 0, err = 0;

	if (total_sz > mbx->thiz_req_shm_size) {
		PMD_HW_ERR(mbx->hw,
			   "%s:%s opcode:0x%x data_bytes:%d > max_size:%d\n",
			   __func__, mbx->name, opcode, data_bytes,
			   mbx->thiz_req_shm_size);
		return -EINVAL;
	}
	req.cmd.opcode = opcode;
	req.cmd.arg_cnts = round_up(data_bytes, 4) / 4;
	if (mbx->hw->is_vf)
		req.cmd.flag_peer2pf_req = 1;
	else
		req.cmd.flag_pf2peer_req = 1;

	memcpy(req.data, data, data_bytes);

	if (resp == NULL)
		req.cmd.flag_no_resp = 1;

	logd_if(LOG_MBX_REQ_OUT) {
		printf("\n== %s  req-code:%d ==\n", mbx->name, req.cmd.opcode);
		rte_hexdump(stdout, "req: ", &req, total_sz);
	}

	/* send req */
	rte_spinlock_lock(&mbx->req_lock);

	if (mce_mbx_get_req_shm_lock(mbx, 1000) < 0) { /* 1ms */
		PMD_HW_ERR(mbx->hw,
			   "%s:%s opcode:0x%x get req shm lock timeout\n",
			   __func__, mbx->name, opcode);
		ret = -ETIMEDOUT;
		mbx->stats.tx_shm_lock_timeout++;
		goto quit;
	}
	/* disable irq && schedule after get mbx share memory hw-lock */
	rte_spinlock_lock(&mbx->thiz_req_shm_lock);
	for (i = 0; i < total_sz / 4; i++)
		mbx_wr32(mbx->thiz2peer_shm + i * 4, ((int *)&req)[i]);
	mce_mbx_put_req_shm_lock(mbx);
	rte_spinlock_unlock(&mbx->thiz_req_shm_lock);

	rte_mb();
	/* send req with irq to peer */
	if (mbx->dst == MBX_PF2VF)
		mbx_wr32_masked(
			mbx->thiz2peer_ctrl,
			MBX_CTRL_PF2VF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK,
			(REQ_WITH_DATA << MBX_CTRL_PF2VF_REQ_STAT_SHIFT) |
				MBX_SEND_REQ_WITH_IRQ);
	else if (mbx->dst == MBX_PF2FW)
		mbx_wr32_masked(
			mbx->thiz2peer_ctrl,
			MBX_CTRL_PF2FW_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK,
			(REQ_WITH_DATA << MBX_CTRL_PF2FW_REQ_STAT_SHIFT) |
				MBX_SEND_REQ_WITH_IRQ);
	else /* VF2PF */
		mbx_wr32_masked(
			mbx->thiz2peer_ctrl,
			MBX_CTRL_VF2PF_REQ_STAT_MSK | MBX_CTRL_REQ_IRQ_MSK,
			(REQ_WITH_DATA << MBX_CTRL_VF2PF_REQ_STAT_SHIFT) |
				MBX_SEND_REQ_WITH_IRQ);

	mbx->stats.tx_req_cnt++;

	rte_mb();

	if (timeout_us == 0) {
		ret = 0;
		goto quit;
	}

	ret = -ETIMEDOUT;
	/* wait response or ack */
	while (timeout_us > 0) {
		int stat;
		u32 v = mbx_rd32(mbx->thiz2peer_ctrl);
		if (mbx->dst == MBX_PF2VF)
			stat = MBX_CTRL_GET_PF2VF_REQ_STAT(v);
		else if (mbx->dst == MBX_PF2FW)
			stat = MBX_CTRL_GET_PF_REQ_STAT(v);
		else /* VF2PF */
			stat = MBX_CTRL_GET_VF2PF_REQ_STAT(v);

		if (stat != REQ_WITH_DATA) {
			ret = 0;
			if (stat == RESP_OR_ACK) {
				if (resp) {
					err = mce_mbx_req_read_resp_out(mbx,
									resp);
					if (err > 0 &&
					    resp->cmd.opcode != opcode) {
						ret = -EIO;
					}
				}
			} else {
				ret = -EIO;
			}
			break;
		}
		rte_delay_us(10);
		timeout_us -= 10;
	}

quit:
	rte_spinlock_unlock(&mbx->req_lock);

	return ret;
}

void mcevf_mbx_set_vf2pf_stat(struct mce_hw *hw)
{
	struct mce_mbx_info *vf2pf_mbx = &hw->vf2pf_mbx;
	int stat_valid = MBX_CTRL_VF2PF_STAT_VALID; /* default valid */

	mbx_wr32_masked(vf2pf_mbx->thiz2peer_ctrl,
			MBX_CTRL_VF2PF_STAT_VALID_MSK |
				MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK |
				MBX_CTRL_VF2PF_RESET_DONE_MSK,
			(stat_valid) |
				(vf2pf_mbx->irq_enabled
				 << MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT) |
				(hw->reset_done
				 << MBX_CTRL_VF2PF_RESET_DONE_SHIFT));
}

int mcevf_update_pf_stat(struct mce_hw *hw)
{
	struct mce_mbx_info *vf2pf_mbx = &hw->vf2pf_mbx;
	int v = mbx_rd32(vf2pf_mbx->peer2thiz_ctrl);

	if (!(v & MBX_CTRL_PF2VF_STAT_VALID_MSK)) {
		PMD_HW_ERR(hw, "[%s] %s failed!\n", vf2pf_mbx->name, __func__);
		return -EIO;
	}

	hw->pf_stat.pf_link_speed =
		speed_unzip((v & MBX_CTRL_PF2VF_PF_SPEED_MSK) >>
			    MBX_CTRL_PF2VF_SPEED_SHIFT);
	hw->pf_stat.pf_link_status = !!(v & MBX_CTRL_PF2VF_LINK_STAT_MSK);

	logd(LOG_LINK, "%s: nr_pf%d link_stat:%d link_speed:%d\n",
	     vf2pf_mbx->name, hw->pf_stat.nr_pf, hw->pf_stat.pf_link_speed,
	     hw->pf_stat.pf_link_status);

	return 0;
}

int mcevf_mbx_get_pf_stat(struct mce_mbx_info *vf2pf_mbx, enum MBX_PF_STAT stat)
{
	struct mce_hw *hw = vf2pf_mbx->hw;

	if (mcevf_update_pf_stat(hw))
		return -EIO;

	switch (stat) {
	case PF_NR_PF: {
		return hw->pf_stat.nr_pf;
	}
	case PF_SPEED: {
		return hw->pf_stat.pf_link_speed;
	}
	case PF_LINKUP: {
		return hw->pf_stat.pf_link_status;
	}
	}
	return -EINVAL;
}

static int mcevf_n20_get_nr_pf(struct mce_hw *hw)
{
	int ret;
	ret = mcevf_mbx_get_pf_stat(&hw->vf2pf_mbx, PF_NR_PF);
	if (ret < 0) {
		PMD_HW_ERR(hw,
			   "%s: mce_mbx_get_pf_stat should not be error! "
			   "ret:%d\n",
			   __func__, ret);
		return 0;
	}
	return ret & 1;
}

void mce_mbx_clear_vf_reset_done_stat(struct mce_mbx_info *pf2vf_mbx)
{
	mbx_wr32_masked(pf2vf_mbx->peer2thiz_ctrl,
			MBX_CTRL_VF2PF_RESET_DONE_MSK, 0);
}

/* get rte_eth link status (showed to user not pmd saved link-status) */
static int mce_get_rte_eth_link_nowait(struct mce_hw *hw,
				       struct rte_eth_link *eth_link)
{
	struct rte_eth_dev *dev;

	if (hw->is_vf)
		dev = hw->back->vf.dev;
	else
		dev = hw->back->pf.dev;
	/* && dev->data->dev_started */
	if (dev->data->dev_conf.intr_conf.lsc) {
		rte_eth_linkstatus_get(dev, eth_link);
	} else {
		if (dev->dev_ops->link_update == NULL)
			return -ENOTSUP;

		dev->dev_ops->link_update(dev, 0);
		*eth_link = dev->data->dev_link;
	}

	if (hw->ifup_status == 0){
		hw->link_status = 0;
		if (eth_link->link_status)
			mce_report_link(hw);
		eth_link->link_status  = 0;
	}
	logd(LOG_LINK, "[%s] %s ifstat:%d linkup:%d speed:%d\n", hw->device_name,
	     __func__, hw->ifup_status,eth_link->link_status, eth_link->link_speed);

	return 0;
}

static void mcepf_mbx_set_pf_stat2vf(struct mce_mbx_info *pf2vf_mbx)
{
	bool pf_netdev_is_linkup = false;
	int pf_speed;
	int stat_valid = MBX_CTRL_PF2VF_STAT_VALID; /* default valid */
	struct rte_eth_link eth_link = {};

	mce_get_rte_eth_link_nowait(pf2vf_mbx->hw, &eth_link);
	pf_speed = speed_zip_to_bit3(eth_link.link_speed);
	pf_netdev_is_linkup = eth_link.link_status;

	mbx_wr32_masked(
		pf2vf_mbx->thiz2peer_ctrl,
		MBX_CTRL_PF2VF_STAT_VALID_MSK | MBX_CTRL_PF2VF_LINK_STAT_MSK |
			 MBX_CTRL_PF2VF_PF_SPEED_MSK,
		(stat_valid) |
			(pf_netdev_is_linkup
			 << MBX_CTRL_PF2VF_LINK_STAT_SHIFT) |
			(pf_speed << MBX_CTRL_PF2VF_SPEED_SHIFT));
}

static void mce_mbx_set_pf_stat2fw(struct mce_mbx_info *pf2fw_mbx)
{
	struct rte_eth_link eth_link = {};
	bool pf_netdev_is_linkup = false;
	int stat_valid = MBX_CTRL_PF2FW_STAT_VALID; /* default valid */

	mce_get_rte_eth_link_nowait(pf2fw_mbx->hw, &eth_link);
	pf_netdev_is_linkup = eth_link.link_status;

	/* update pf2hw status */
	mbx_wr32_masked(pf2fw_mbx->thiz2peer_ctrl,
			MBX_CTRL_PF2FW_STAT_VALID_MSK |
				MBX_CTRL_PF2FW_LINK_STAT_MSK |
				MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_MSK |
				MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_MSK,
			stat_valid |
				(pf_netdev_is_linkup
				 << MBX_CTRL_PF2FW_LINK_STAT_SHIFT) |
				(pf2fw_mbx->hw->fw_link_change_notify_en
				 << MBX_CTRL_FW2PF_LINK_CHANG_NOTIFY_EN_SHIFT) |
				(pf2fw_mbx->hw->fw_sfp_pluginout_notify_en
				 << MBX_CTRL_FW2PF_SFP_PLUG_NOTIFY_EN_SHIFT));

	logd(LOG_LINK, "[%s] %s is_link:%d irq_enabled:%d reg:0x%lx noti:%d v:0x%x,0x%x\n",
	     pf2fw_mbx->name, __func__, pf_netdev_is_linkup,
	     pf2fw_mbx->irq_enabled,
	     pf2fw_mbx->thiz2peer_ctrl - pf2fw_mbx->hw->nic_base,pf2fw_mbx->hw->fw_link_change_notify_en,
	     mbx_rd32(pf2fw_mbx->thiz2peer_ctrl), mbx_rd32(pf2fw_mbx->peer2thiz_ctrl));
}

/*
    update pf wr status register.
*/
int mce_mbx_set_pf_stat_reg(struct mce_hw *hw)
{
	int vf;

	/* update pf2fw status */
	mce_mbx_set_pf_stat2fw(&hw->pf2fw_mbx);

	/* update pf2vf status */
	for (vf = 0; vf < hw->max_vfs; vf++)
		mcepf_mbx_set_pf_stat2vf(&hw->pf2vf_mbx[vf]);

	return 0;
}

void mcevf_mbx_clear_reset_done_flag(struct mce_hw *hw)
{
	mbx_wr32_masked(hw->vf2pf_mbx.thiz2peer_ctrl,
			MBX_CTRL_VF2PF_RESET_DONE_MSK, 0);
}

void mce_mbx_clear_fw_nic_reset_done_flag(struct mce_mbx_info *pf2fw_mbx)
{
	mbx_wr32_masked(pf2fw_mbx->peer2thiz_ctrl,
			MBX_CTRL_FW2PF_FW_NIC_RESET_DONE_MSK, 0);
}

int mce_pf_mbx_get_fw_stat(struct mce_mbx_info *pf2fw_mbx,
			   enum MBX_FW_STAT stat)
{
	int v = mbx_rd32(pf2fw_mbx->peer2thiz_ctrl);

	if (!(v & MBX_CTRL_FW2PF_STAT_VALID_MSK))
		return -EIO;

	switch (stat) {
	case FW_LINK_STAT: {
		return !!(v & MBX_CTRL_FW2PF_FW_LINKUP_MSK);
	}
	case FW_NIC_RESET_DONE_STAT: {
		return !!(v & MBX_CTRL_FW2PF_FW_NIC_RESET_DONE_MSK);
	}
	case FW_NR_PF: {
		return !!(v & MBX_CTRL_FW2PF_NR_PF_MSK);
	}
	}
	return -EINVAL;
}

int mce_mbx_get_vf_stat(struct mce_mbx_info *pf2vf_mbx, enum MBX_VF_STAT stat)
{
	int v = mbx_rd32(pf2vf_mbx->peer2thiz_ctrl);

	if (!(v & MBX_CTRL_VF2PF_STAT_VALID_MSK))
		return -EIO;

	switch (stat) {
	case VF_RESET_DONE: {
		return !!(v & MBX_CTRL_VF2PF_RESET_DONE_MSK);
	}
	case VF_MBX_IRQ_INIT_DONE: {
		return !!(v & MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK);
	}
	}
	return -EINVAL;
}

static void mce_mbx_set_vf_stat(struct mce_mbx_info *vf_mbx)
{
        int stat_valid = MBX_CTRL_VF2PF_STAT_VALID;
        u32 mask;
        u32 val;


        mask = MBX_CTRL_VF2PF_STAT_VALID_MSK |
               MBX_CTRL_VF2PF_MBX_INIT_DONE_MSK | MBX_CTRL_VF2PF_RESET_DONE_MSK;
        val = stat_valid |
              (vf_mbx->irq_enabled << MBX_CTRL_VF2PF_MBX_INIT_DONE_SHIFT) |
              (vf_mbx->hw->reset_done << MBX_CTRL_VF2PF_RESET_DONE_SHIFT);
        mbx_wr32_masked(vf_mbx->thiz2peer_ctrl, mask, val);
}

int mce_setup_pf_mbx_info(struct mce_hw *hw, struct mce_mbx_info *mbx)
{
	/* pf2vf */
	mbx->vf2pf_irq_stat = hw->nic_base + N20_MBX_BASE + VF2PF_REQ_ST0;
	mbx->mbx_vec_base = hw->nic_base + N20_MBX_BASE + FW2PF_MB_VEC;
	rte_spinlock_init(&mbx->req_lock);

	mbx->peer2thiz_shm = hw->nic_base + N20_MBX_BASE + FW2PF_SHM;
	mbx->peer2thiz_ctrl = hw->nic_base + N20_MBX_BASE + FW2PF_MBX_CTRL;
	mbx->hw = hw;

	return 0;
}

int mce_setup_pf2fw_mbx_info(struct mce_hw *hw, struct mce_mbx_info *mbx)
{
	mbx->hw = hw;
	mbx->dst = MBX_PF2FW;

	rte_spinlock_init(&mbx->thiz_req_shm_lock);
	rte_spinlock_init(&mbx->peer_shm_lock);

	mbx->thiz_req_shm_size = PF2FW_SHM_SZ;
	mbx->peer_req_shm_size = FW2PF_SHM_SZ;

	/* pf2fw */
	mbx->thiz2peer_shm = hw->nic_base + N20_MBX_BASE + PF2FW_SHM;
	mbx->thiz2peer_ctrl = hw->nic_base + N20_MBX_BASE + PF2FW_MBX_CTRL;
	mbx->thiz2peer_shm_lock = mbx->thiz2peer_ctrl;
	mbx->thiz2peer_shm_lock_msk = BIT(3); /* PFU */

	/* fw2pf */
	mbx->peer2thiz_shm = hw->nic_base + N20_MBX_BASE + FW2PF_SHM;
	mbx->peer2thiz_ctrl = hw->nic_base + N20_MBX_BASE + FW2PF_MBX_CTRL;
	mbx->peer2thiz_shm_lock = mbx->thiz2peer_shm_lock;
	mbx->peer2thiz_shm_lock_msk = BIT(3); /* PFU */

	mbx->nr_vf = 0;
	mbx->nr_pf = mce_pf_mbx_get_fw_stat(mbx, FW_NR_PF);
	if (mbx->nr_vf < 0) {
		PMD_INIT_LOG(ERR, "Failed to get NR_PF from FW");
		return -EIO;
	}
	snprintf(mbx->name, sizeof(mbx->name), "%s-mbx-pf%d", hw->device_name,
		 mbx->nr_pf);

	hw->nr_pf = mbx->nr_pf;
	mbx->setup_done = true;

	return 0;
}

int mce_setup_pf2vf_mbx_info(struct mce_hw *hw, int nr_vf,
			     struct mce_mbx_info *mbx)
{
	mbx->hw = hw;
	mbx->dst = MBX_PF2VF;

	mbx->vfinfo = &hw->back->pf.vfinfos[nr_vf];

	rte_spinlock_init(&mbx->req_lock);
	rte_spinlock_init(&mbx->thiz_req_shm_lock);
	rte_spinlock_init(&mbx->peer_shm_lock);

	mbx->thiz_req_shm_size = PF2FW_SHM_SZ;
	mbx->peer_req_shm_size = FW2PF_SHM_SZ;

	/* pf2vf */
	mbx->thiz2peer_shm = hw->nic_base + N20_MBX_BASE + PF2VF_SHM(nr_vf);
	mbx->thiz2peer_ctrl = hw->nic_base + N20_MBX_BASE + PF2VF_REQ_CTRL(nr_vf);
	mbx->thiz2peer_shm_lock = mbx->thiz2peer_ctrl;
	mbx->thiz2peer_shm_lock_msk = BIT(3); /* PFU */

	/* vf2pf */
	mbx->peer2thiz_shm = hw->nic_base + N20_MBX_BASE + VF2PF_SHM(nr_vf);
	mbx->peer2thiz_ctrl = hw->nic_base + N20_MBX_BASE + VF2PF_REQ_CTRL(nr_vf);
	mbx->peer2thiz_shm_lock =
		mbx->thiz2peer_shm_lock; /* fw & pf use same mbx shm-lock */
	mbx->peer2thiz_shm_lock_msk = BIT(3); /* PFU */

	mbx->vf2pf_irq_stat = hw->nic_base + N20_MBX_BASE + VF2PF_REQ_ST0;

	mbx->mbx_vec_base = hw->nic_base + N20_MBX_BASE + VF2PF_MB_VEC(nr_vf);

	mbx->nr_vf = nr_vf;
	mbx->nr_pf = hw->nr_pf;
	snprintf(mbx->name, sizeof(mbx->name), "%s-mbx-pf%dvf%d",
		 hw->device_name, mbx->nr_pf, mbx->nr_vf);

	mbx->setup_done = true;

	return 0;
}

int mce_setup_vf2pf_mbx_info(struct mce_hw *hw, struct mce_mbx_info *mbx)
{
	mbx->hw = hw;
	mbx->dst = MBX_VF2PF;

	rte_spinlock_init(&mbx->req_lock);
	rte_spinlock_init(&mbx->thiz_req_shm_lock);
	rte_spinlock_init(&mbx->peer_shm_lock);

	mbx->thiz_req_shm_size = VF2PF_SHM_SIZE;
	mbx->peer_req_shm_size = PF2VF_SHM_SIZE;

	if (hw->is_vf_isolated_enabled) {
		mbx->peer2thiz_shm = hw->nic_base + PF2VF_SHM_ISOLATED;
		mbx->peer2thiz_shm_lock =
			hw->nic_base + PF2VF_SHM_LOCK_ISOLATED;
		mbx->peer2thiz_ctrl = hw->nic_base + PF2VF_REQ_CTRL_ISOLATED;
		mbx->peer2thiz_shm_lock_msk = BIT(2); /* VFU */

		mbx->thiz2peer_shm = hw->nic_base + VF2PF_SHM_ISOLATED;
		mbx->thiz2peer_shm_lock =
			hw->nic_base + VF2PF_SHM_LOCK_ISOLATED;
		mbx->thiz2peer_ctrl = hw->nic_base + VF2PF_REQ_CTRL_ISOLATED;
		mbx->thiz2peer_shm_lock_msk = BIT(2); /* VFU */

		mbx->mbx_vec_base = hw->nic_base + PF2VF_MB_VEC_ISOLATED;
	} else {
		int nr_vf = hw->vfnum;
		mbx->peer2thiz_shm = hw->nic_base + N20_MBX_BASE +
				     PF2VF_SHM_NO_ISOLATED(nr_vf);
		mbx->peer2thiz_shm_lock = hw->nic_base + N20_MBX_BASE +
					  PF2VF_SHM_LOCK_NO_ISOLATED(nr_vf);
		mbx->peer2thiz_ctrl = hw->nic_base + N20_MBX_BASE +
				      PF2VF_REQ_CTRL_NO_ISOLATED(nr_vf);
		mbx->peer2thiz_shm_lock_msk = BIT(2); /* VFU */

		mbx->thiz2peer_shm = hw->nic_base + N20_MBX_BASE +
				     VF2PF_SHM_NO_ISOLATED(nr_vf);
		mbx->thiz2peer_shm_lock = hw->nic_base + N20_MBX_BASE +
					  VF2PF_SHM_LOCK_NO_ISOLATED(nr_vf);
		mbx->thiz2peer_ctrl = hw->nic_base + N20_MBX_BASE +
				      VF2PF_REQ_CTRL_NO_ISOLATED(nr_vf);
		mbx->thiz2peer_shm_lock_msk = BIT(2); /* VFU */

		mbx->mbx_vec_base = hw->nic_base + N20_MBX_BASE +
				    PF2VF_MB_VEC_NO_ISOLATED(nr_vf);
	}

	mbx->nr_vf = hw->vfnum;
	mbx->nr_pf = mcevf_n20_get_nr_pf(hw);
	snprintf(mbx->name, sizeof(mbx->name), "%s-mbx-pf%dvf%d",
		 hw->device_name, mbx->nr_pf, mbx->nr_vf);

	mbx->setup_done = true;
	return 0;
}

void mce_mbx_link_state_change_notify_en(struct mce_hw *hw, int enable)
{
	hw->fw_link_change_notify_en = !!enable;
	logd(LOG_LINK,"%s: %s en:%d\n", __func__, hw->device_name, hw->fw_link_change_notify_en);
	mce_mbx_set_pf_stat2fw(&hw->pf2fw_mbx);
}

void mce_mbx_sfp_plug_notify_en(struct mce_hw *hw, int enable)
{
	hw->fw_sfp_pluginout_notify_en = !!enable;
	mce_mbx_set_pf_stat2fw(&hw->pf2fw_mbx);
}

void mce_mbx_drv_send_uninstall_notify_fw(struct mce_hw *hw)
{
	mce_mbx_send_event(&hw->pf2fw_mbx, EVT_DRV_REMOVE, 0);
}

int mcevf_set_mbx_init_done(struct mce_hw *hw, bool en)
{
        enum VF2PF_EVENT_ID event;

        mce_mbx_set_vf_stat(&hw->vf2pf_mbx);
        event = en ? EVT_VF_MBX_INIT_DONE : VF_DRV_REMOVR;
        mce_mbx_send_event(&hw->vf2pf_mbx, event, 5000);
        return 0;
}

void mce_report_link(struct mce_hw *hw)
{
	struct mce_adapter *adapter = hw->back;
	struct rte_eth_dev *dev = adapter->pf.dev;
	struct mce_pf *pf = &adapter->pf;
	struct rte_eth_link link = {};
	int i = 0;

	if (hw->link_status) {
		link.link_speed = hw->link_speed;
		link.link_duplex = hw->link_duplex;
#if RTE_VERSION_NUM(17, 8, 0, 0) < RTE_VERSION
		link.link_autoneg = hw->link_autoneg;
#endif
		link.link_status = hw->link_status;
#if RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
		link.link_connector = hw->connect_type;
#endif
	}
	logd(LOG_LINK, "[%s] %s link:%d speed:%d\n", hw->device_name, __func__,
	     link.link_status, link.link_speed);

	/* Report Link Info To Upper Firmwork */
	rte_eth_linkstatus_set(dev, &link);
	if (hw->max_vfs && pf->nr_repr_ports) {
		for (i = 0; i < pf->nr_repr_ports; i++)
			rte_eth_linkstatus_set(pf->vf_reprs[i]->repr_dev, &link);
	}
	/* Notice Event Process Link Status Change */
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
#elif (RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION &&  \
       RTE_VERSION_NUM(17, 8, 0, 0) > RTE_VERSION) ||   \
	(RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION && \
	 RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION)
	_rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL);
#elif RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
	_rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC, NULL, NULL);
#else
	_rte_eth_dev_callback_process(dev, RTE_ETH_EVENT_INTR_LSC);
#endif
}
