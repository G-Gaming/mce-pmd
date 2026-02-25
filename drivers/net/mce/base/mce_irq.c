/**
 * @file mce_irq.c
 * @brief Interrupt (IRQ) and MSIX configuration implementation
 *
 * Implements interrupt vector configuration and MSIX (Message Signaled
 * Interrupts extended) setup for the MCE hardware.
 *
 * Interrupt Types:
 * - MSIX - Modern interrupt delivery (preferred, up to 1024 vectors)
 * - MSI - Older message-based interrupts
 * - Legacy - Pin-based interrupts (fallback)
 *
 * Features:
 * - Per-queue interrupt vector configuration
 * - Interrupt coalescing (bundling) support
 * - PF and VF interrupt isolation
 * - Mailbox interrupt handling
 * - Link state change notification
 * - Error/exception interrupt routing
 *
 * @see mce_irq.h for interrupt macros and vector definitions
 * @see base/mce_mbx.c for mailbox interrupt handling
 */

#include <string.h>

#include "mce_irq.h"
#include "../mce.h"

void mce_pf_irq0_setup(struct mce_hw *hw)
{
	MCE_E_REG_WRITE(hw, MCE_FPGA_VF2PF_VEC_C(0), 0);
	MCE_E_REG_WRITE(hw, MCE_FPGA_VF2PF_VEC_C(1), 0);

	MCE_E_REG_WRITE(hw, MCE_FPGA_PF2VF_VEC_C(0), 0);
	MCE_E_REG_WRITE(hw, MCE_FPGA_PF2VF_VEC_C(1), 0);

	MCE_E_REG_WRITE(hw, MCE_FPGA_FW2PF_VEC_C(0), 0);
	MCE_E_REG_WRITE(hw, MCE_FPGA_FW2PF_VEC_C(1), 1);
}

void mce_pf_irq0_enable(struct mce_hw *hw)
{
	RTE_SET_USED(hw);
	/* setup chip intrerupt 0 enable */
}

void mce_pf_irq0_disable(struct mce_hw *hw)
{
	RTE_SET_USED(hw);
	/* setup chip intrerupt 0 disable */
}

void mce_ring_vec_setup(struct mce_hw *hw, u16 vf_num,
			enum mce_irq_ring_type ring_type, u16 ring_id,
			u16 vec_id)
{
	u32 irq_map = 0;
	u16 q_tb = 0;

	/* do this need to calc for this api */
	if (vf_num == UINT16_MAX)
		q_tb = ring_id;
	else
		q_tb = ring_id + vf_num * hw->nb_qpair_per_vf;
	irq_map = MCE_E_REG_READ(hw, MCE_FPGA_RING_VEC_C(q_tb));
	if (ring_type == MCE_IRQ_RING_TYPE_RX) {
		irq_map &= MCE_FPGA_RING_VEC_RXID_MASK;
		irq_map |= vec_id;
	}
	if (ring_type == MCE_IRQ_RING_TYPE_TX) {
		irq_map &= ~MCE_FPGA_RING_VEC_TXID_MASK;
		irq_map |= vec_id;
	}
	/* clear sriov pattern */
	irq_map &= MCE_FPGA_RING_VEC_FUNC_MASK;
	if (vf_num != UINT16_MAX) {
		irq_map |= vf_num << MCE_FPGA_RING_VEC_R_VF_S;
		irq_map |= vf_num << MCE_FPGA_RING_VEC_T_VF_S;
	}
	MCE_E_REG_WRITE(hw, MCE_FPGA_RING_VEC_C(q_tb), irq_map);
}

void mce_ring_vec_disable(struct mce_hw *hw, u16 vf_num, u16 ring_id,
			  u16 vec_id)
{
	RTE_SET_USED(hw);
	RTE_SET_USED(vf_num);
	RTE_SET_USED(ring_id);
	RTE_SET_USED(vec_id);
}

void mce_ring_vec_enable(struct mce_hw *hw, u16 vf_num, u16 ring_id, u16 vec_id)
{
	RTE_SET_USED(hw);
	RTE_SET_USED(vf_num);
	RTE_SET_USED(ring_id);
	RTE_SET_USED(vec_id);
}
