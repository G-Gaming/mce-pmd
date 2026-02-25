#ifndef MCE_PF2VF_CHNL_H
#define MCE_PF2VF_CHNL_H

#include "mce_mbx.h"

/**
 * @brief Handle VF->PF mailbox requests (ISR context).
 *
 * Processes an incoming mailbox request from a VF and generates an
 * appropriate response.
 *
 * @param mbx Mailbox info pointer for this VF
 * @param req Pointer to received mailbox request
 */
void mce_mbx_vf2pf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req);

/**
 * @brief Handle VF->PF mailbox events (ISR context).
 *
 * Called when a VF generates an event notification (no request payload).
 *
 * @param mbx Mailbox info pointer
 * @param event_id Event identifier
 */
void mce_mbx_vf2pf_event_req_isr(struct mce_mbx_info *mbx, int event_id);

/**
 * @brief Notify VF FCS state change via PF helpers.
 *
 * Sends FCS configuration change events to VFs when PF changes FCS state.
 *
 * @param pf Pointer to PF context
 * @param on True if FCS is enabled, false if disabled
 */
void mce_vf_notify_fcs_state(struct mce_pf *pf, bool on);

static inline struct mce_mbx_info *mce_get_vf_mbx(struct mce_hw *hw, int vfd)
{
	if (vfd >= MAX_VF_CNT)
		return NULL;

	return &hw->pf2vf_mbx[vfd];
}

/**
 * @brief Broadcast an event to all VFs.
 *
 * Sends `event` to every VF's mailbox and returns combined status.
 *
 * @param hw Pointer to hardware context
 * @param event Event identifier to broadcast
 * @param timeout_us Timeout for each send_event call
 * @return 0 on success (all sent), non-zero if any send failed
 */
int mce_broadcast_event_to_vf(struct mce_hw *hw, enum PF2VF_EVENT_ID event,
				  int timeout_us);

/**
 * @brief Send VF reset event to a specific VF.
 *
 * @param hw Pointer to hardware context
 * @param vfd VF identifier
 * @return 0 on success, negative on failure
 */
int mce_mbx_pf_send_reset_vf_cmd(struct mce_hw *hw, int vfd);

/**
 * @brief Notify VFs about link state changes.
 *
 * Broadcasts link change notifications to all VFs.
 *
 * @param hw Pointer to hardware context
 */
void mce_vf_notify_link_state(struct mce_hw *hw);
/**
 * @brief Broadcast a mailbox command to all VFs.
 *
 * @param hw Pointer to hardware context
 * @param opcode Opcode to send
 * @param data Command data payload
 * @param data_bytes Size of payload in bytes
 * @param timeout_us Timeout for each call
 * @return 0 on success, non-zero if any send failed
 */
int mce_broadcast_cmd_to_vf(struct mce_hw *hw, enum PF2VF_MBX_REQ opcode,
				unsigned int *data, int data_bytes, int timeout_us);
/**
 * @brief Notify all VFs of current link state.
 *
 * Convenience wrapper to broadcast link state to all VFs.
 *
 * @param hw Pointer to hardware context
 */
void mce_pf_notify_all_vf_link_state(struct mce_hw *hw);

int mce_vf_notify_trust_state(struct mce_hw *hw, int vfid, bool on);

#endif /* MCE_PF2VF_CHNL_H */
