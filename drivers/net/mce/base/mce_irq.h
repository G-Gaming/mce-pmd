/**
 * @file mce_irq.h
 * @brief MCE Interrupt and MSIX Configuration
 *
 * Defines interrupt vectors, MSIX register addresses, and interrupt control
 * bits for MCE hardware interrupt handling in both PF and VF modes.
 *
 * @details
 * Includes:
 * - MSIX table and PBA (Pending Bit Array) offsets for PF/VF
 * - Mailbox interrupt operation bits
 * - Ring vector configuration for Rx/Tx queues
 * - SR-IOV interrupt control
 *
 * @see mce_intr.h for software interrupt handling
 */

#ifndef _MCE_IRQ_H_
#define _MCE_IRQ_H_

#include "mce_osdep.h"

/** @def MCE_PF_MSIX_TAC(n) PF MSIX table address for vector n */
#define MCE_PF_MSIX_TAC(n)	    _MSIX_(0x0000 + ((n) * BIT_TO_BYTES(32)))

/** @def MCE_VF_MSIX_TAC(n) VF MSIX table address for vector n */
#define MCE_VF_MSIX_TAC(n)	    _MSIX_(0x8000 + ((n) * BIT_TO_BYTES(32)))

/** @def MCE_PF_PBA_TAC(n) PF PBA table address for vector n */
#define MCE_PF_PBA_TAC(n)	    _MSIX_(0xe000 + ((n) * BIT_TO_BYTES(32)))

/** @def MCE_VF_PBA_TAC(n) VF PBA table address for vector n */
#define MCE_VF_PBA_TAC(n)	    _MSIX_(0xf000 + ((n) * BIT_TO_BYTES(32)))

/** @def MCE_MB_OP_CLR_IRQ Mailbox operation: clear interrupt */
#define MCE_MB_OP_CLR_IRQ	    RTE_BIT32(21)

/** @def MCE_MB_OP_IRQ_MASK Mailbox operation: mask interrupt */
#define MCE_MB_OP_IRQ_MASK	    RTE_BIT32(20)

/** @def MCE_MB_OP_PFU Mailbox operation: PF update bit */
#define MCE_MB_OP_PFU		    RTE_BIT32(19)

/** @def MCE_MB_OP_VFU Mailbox operation: VF update bit */
#define MCE_MB_OP_VFU		    RTE_BIT32(18)

/** @def MCE_MB_OP_REQ Mailbox operation: request bit */
#define MCE_MB_OP_REQ		    RTE_BIT32(16)

/** @def MCE_MM_CLR_IRQ Mailbox: clear interrupt bit */
#define MCE_MM_CLR_IRQ		    RTE_BIT32(5)

/** @def MCE_MB_IRQ_MASK Mailbox: interrupt mask bit */
#define MCE_MB_IRQ_MASK		    RTE_BIT32(4)

/** @def MCE_MB_PFU Mailbox: PF update bit */
#define MCE_MB_PFU		    RTE_BIT32(3)

/** @def MCE_MB_VFU Mailbox: VF update bit */
#define MCE_MB_VFU		    RTE_BIT32(2)

/** @def MCE_MB_REQ Mailbox: request bit */
#define MCE_MB_REQ		    RTE_BIT32(0)

/* option module trigger vector ctrl */
#define MCE_RING_VEC_C(n)	    _MSIX_EX_(0x7000 + ((n) * BIT_TO_BYTES(32)))
#define MCE_RING_VEC_RXID_MASK	    GENMASK_U32(10, 0)
#define MCE_RING_VEC_TXID_MASK	    GENMASK_U32(21, 11)
#define MCE_RING_VEC_TXID_S	    (11)
#define MCE_RING_VEC_VFID_MASK	    GENMASK_U32(30, 24)
#define MCE_RING_VEC_VFID_S	    (24)
#define MCE_RING_VEC_SRIOV_EN	    RTE_BIT32(31)

#define MCE_MAILBOX_VEC_MASK	    GENMASK_U32(10, 0)
#define MCE_PF2VF_VEC_C(n)	    _MSIX_EX_(0x8000 + ((n) * BIT_TO_BYTES(32)))
#define MCE_VF2PF_VEC_C(n)	    _MSIX_EX_(0x8200 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FW2VF_VEC_C(n)	    _MSIX_EX_(0x8400 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FW2PF_VEC_C(n)	    _MSIX_EX_(0x8600 + ((n) * BIT_TO_BYTES(32)))
#define MCE_RDMA_VEC_C(n)	    _MSIX_EX_(0x9000 + ((n) * BIT_TO_BYTES(32)))
#define MCE_RDMA_VEC_CEQ_MASK	    GENMASK_U32(15, 11)
#define MCE_RDMA_VEC_CEQ_S	    (11)
#define MCE_RDMA_VEC_AEQ_MASK	    GENMASK_U32(10, 10)
/*----------------------------------------------------------------------------------*/
/* only valid for fpga */
#define MCE_FPGA_IRQ_MB_STATE	    _MSIX_EX_(0xf104)
#define MCE_FPGA_IRQ_VF2PF_REQ	    GENMASK_U32(3, 0)
#define MCE_FPGA_IRQ_PF2PF_REQ	    GENMASK_U32(7, 4)
#define MCE_FPGA_IRQ_FW2PF_REQ	    GENMASK_U32(11, 8)
#define MCE_FPGA_IRQ_FW2VF_REQ	    GENMASK_U32(15, 12)
#define MCE_FPGA_IRQ_STATE_CLEAR    _MSIX_(0xf108)
/* queue vector mapping */
#define MCE_FPGA_RING_VEC_C(n)	    _MSIX_EX_(0xf000 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FPGA_RING_VEC_RXID_MASK GENMASK_U32(7, 0)
#define MCE_FPGA_RING_VEC_TXID_MASK GENMASK_U32(15, 8)
#define MCE_FPGA_RING_VEC_R_VF_S    (16)
#define MCE_FPGA_RING_VEC_T_VF_S    (24)
#define MCE_FPGA_RING_VEC_FUNC_MASK GENMASK_U32(31, 16)

#define MCE_FPGA_MAILBOX_VEC_S	    (8)
#define MCE_FPGA_VF2PF_VEC_C(n)	    _MSIX_EX_(0xf040 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FPGA_PF2VF_VEC_C(n)	    _MSIX_EX_(0xf048 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FPGA_FW2PF_VEC_C(n)	    _MSIX_EX_(0xf050 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FPGA_FW2VF_VEC_C(n)	    _MSIX_EX_(0xf058 + ((n) * BIT_TO_BYTES(32)))

enum mce_irq_ring_type { MCE_IRQ_RING_TYPE_TX, MCE_IRQ_RING_TYPE_RX };

struct mce_hw;
void mce_pf_irq0_setup(struct mce_hw *hw);
void mce_pf_irq0_enable(struct mce_hw *hw);
void mce_pf_irq0_disable(struct mce_hw *hw);
void mce_ring_vec_setup(struct mce_hw *hw, u16 vf_num,
			enum mce_irq_ring_type ring_type, u16 ring_id,
			u16 vec_id);
void mce_ring_vec_disable(struct mce_hw *hw, u16 vf_num, u16 ring_id,
			  u16 vec_id);
void mce_ring_vec_enable(struct mce_hw *hw, u16 vf_num, u16 ring_id,
			 u16 vec_id);

#endif /* _MCE_IRQ_H_ */
