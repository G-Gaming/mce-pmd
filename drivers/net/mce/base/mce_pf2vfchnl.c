#include "mce_mbx.h"
#include "mce_pfvf.h"
#include "mce_pf2vfchnl.h"
#include "../mce.h"
#include "../mce_logs.h"
#include "../mce_pf.h"
#include "../mce_generic_flow.h"

static inline int
mce_mbx_send_cmd_to_vf(struct mce_hw *hw, int vfd, int opcode,
					   unsigned int *data, int data_bytes,
					   struct mbx_resp *resp, int timeout_us)
{
	struct mce_mbx_info *mbx = mce_get_vf_mbx(hw, vfd);
	if (!mbx)
		return -EINVAL;

	return mce_mbx_send_req(mbx, opcode, data, data_bytes, resp,
				timeout_us);
}

static inline int
mce_mbx_send_event_to_vf(struct mce_hw *hw, int vfd,
					     enum PF2VF_EVENT_ID event_id,
					     int timeout_us)
{
	struct mce_mbx_info *mbx = mce_get_vf_mbx(hw, vfd);
	if (!mbx)
		return -EINVAL;

	return mce_mbx_send_event(mbx, event_id, timeout_us);
}

/**
 * @brief Broadcast a PF->VF event to all configured VFs.
 *
 * Iterates over configured VFs and sends the specified event.
 *
 * @param hw Pointer to hardware context
 * @param event Event identifier to broadcast
 * @param timeout_us Timeout for each send
 * @return 0 if all sends returned 0, non-zero otherwise
 */
int mce_broadcast_event_to_vf(struct mce_hw *hw, enum PF2VF_EVENT_ID event,
			  int timeout_us)
{
	int ret = 0, vfd;

	mce_mbx_set_pf_stat_reg(hw);

	for (vfd = 0; vfd < hw->max_vfs; vfd++)
		ret |= mce_mbx_send_event_to_vf(hw, vfd, event, timeout_us);

	return ret;
}

/**
 * @brief Broadcast a mailbox command to all VFs.
 *
 * Sends an MBX request with `opcode` and `data` to every VF mailbox.
 *
 * @param hw Pointer to hardware context
 * @param opcode Mailbox opcode to send
 * @param data Pointer to payload data
 * @param data_bytes Payload size in bytes
 * @param timeout_us Timeout for each send
 * @return 0 if all sends returned 0, non-zero otherwise
 */
int mce_broadcast_cmd_to_vf(struct mce_hw *hw, enum PF2VF_MBX_REQ opcode,
			unsigned int *data, int data_bytes, int timeout_us)
{
	int vfd, ret = 0;

	mce_mbx_set_pf_stat_reg(hw);

	for (vfd = 0; vfd < hw->max_vfs; vfd++) {
		ret |= mce_mbx_send_cmd_to_vf(hw, vfd, opcode, data, data_bytes,
						  NULL, timeout_us);
	}
	return ret;
}

/**
 * @brief Send a reset event to a single VF through mailbox.
 *
 * @param hw Pointer to hardware context
 * @param vfd VF index
 * @return 0 on success, negative on failure
 */
int mce_mbx_pf_send_reset_vf_cmd(struct mce_hw *hw, int vfd)
{
	struct mce_mbx_info *mbx = &hw->pf2vf_mbx[vfd];

	mce_mbx_clear_vf_reset_done_stat(mbx);
	return mce_mbx_send_event_to_vf(hw, vfd, EVT_PF_RESET_VF, 1000);
}

/**
 * @brief Send a link_change event to a all VF through mailbox.
 *
 * @param hw Pointer to hardware context
 * @return 0 on success, negative on failure
 */
void mce_pf_notify_all_vf_link_state(struct mce_hw *hw)
{
	mce_broadcast_event_to_vf(hw, EVT_PF_LINK_CHANGED, 1000);
}

/**
 * @brief Handle a PF change to VF FCS state.
 *
 * Currently a placeholder; when SR-IOV is enabled this will notify VFs
 * about FCS configuration changes.
 *
 * @param pf Pointer to PF context
 * @param on True if enabling FCS, false otherwise
 */
void mce_vf_notify_fcs_state(struct mce_pf *pf, bool on)
{
	enum PF2VF_EVENT_ID event;
	int vfid;

	RTE_SET_USED(vfid);
	RTE_SET_USED(event);
	RTE_SET_USED(on);
	RTE_SET_USED(pf);
#if 0 /* FIXME */
	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
		return;
	event = on ? EVT_PF_FORECE_FCS_ON : EVT_PF_FORECE_FCS_OFF;
	mce_for_each_vf_id(pf, vfid)
		mce_mbx_send_event_to_vf(&pf->hw, vfid, event, 1000);
#endif
}

/**
 * @brief Handle VF reset message and populate response payload.
 *
 * Copies VF MAC, configuration and status into `resp` for the VF reset
 * completion response.
 *
 * @param hw Pointer to hardware context
 * @param vfid VF identifier
 * @param req Incoming request (unused)
 * @param resp Outgoing response to populate
 * @param vfinfo VF info struct containing VF state
 * @return 0 on success, negative on failure
 */
static int mce_vf_reset_msg(struct mce_hw *hw, u32 vfid,
							__maybe_unused struct mbx_req *req,
							struct mbx_resp *resp, struct mce_vf_info *vfinfo)
{
	/* existing implementation */
	/* struct mce_vf_info* vfinfo = &pf->vfinfos[vfid]; */
	struct mce_pf *pf __maybe_unused = &hw->back->pf;
	unsigned char *vf_mac = vfinfo->mac_addr.addr_bytes;

	u8 *mac_addr = (u8 *)(&resp->data[F_VF_MAC_ADDR]);

	if (rte_is_unicast_ether_addr((struct rte_ether_addr *)vf_mac)) {
		memcpy(mac_addr, vf_mac, RTE_ETHER_ADDR_LEN);
	} else {
		PMD_HW_ERR(hw,
			   "VF %d has no MAC address assigned,use ramdom "
			   "mac-addr\n",
			   vfid);
		rte_eth_random_addr(vf_mac);
		vf_mac[4] = vfid | (hw->nr_pf << 7);
		memcpy(mac_addr, vf_mac, ETH_ALEN);
	}

	/* enable VF mailbox for further messages */
	resp->data[F_VF_RESET_RING_MAX_CNT] = hw->vf_max_ring;
	resp->data[F_VF_RESET_FW_VERSION] = hw->fw_version;
	resp->data[F_VF_RESET_VLAN] = 0 /*FIXME*/;

	resp->data[F_VF_RESET_LINK_ST] = hw->link_speed |
					 (hw->link_status << 31);
	resp->data[F_VF_NR_PF] = hw->nr_pf;
	resp->data[F_VF_RXFCS_STATE] = hw->pf_rxfcs_en;
	resp->cmd.arg_cnts = F_VF_RESET_RESP_CNT;
#if 0
	ether_addr_copy(vf->t_info.macaddr, vf_mac);
	vf->t_info.bcmc_bitmap = mce_F_SET;
	mce_vf_set_veb_misc_rule(hw,
		vfid, __VEB_POLICY_TYPE_UC_ADD_MACADDR_WITH_ACT);
#endif
	mce_mbx_set_pf_stat_reg(hw);
	mce_update_fw_stat(hw);
	return 0;
}

/**
 * @brief Handle VF->PF mailbox requests (ISR context).
 *
 * Processes an incoming mailbox request from a VF and generates an
 * appropriate response.
 *
 * @param mbx Mailbox info pointer for this VF
 * @param req Pointer to received mailbox request
 */
void mce_mbx_vf2pf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req)
{
	struct mce_hw *hw = mbx->hw;
	struct mce_pf *pf = &hw->back->pf;
	struct mbx_resp resp = {};
	int opcode = req->cmd.opcode;
	struct mce_vf_info *vfinfo = mbx->vfinfo;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;
	int vfid = mbx->nr_vf;
	u8 *new_mac;
	int err;

	resp.cmd.v = req->cmd.v;
	resp.cmd.err_code = 0;
	resp.cmd.flag_no_resp = 1; /* default no resp */

	logd(LOG_MBX_IN_REQ, "%s: req-opcode:%d 0x%08x 0x%08x 0x%08x 0x%08x\n",
	     mbx->name, req->cmd.opcode, req->data[0], req->data[1],
	     req->data[2], req->data[3]);

	switch (opcode) {
	case MCE_VF_RESET:
		resp.cmd.flag_no_resp = 0;
		err = mce_vf_reset_msg(mbx->hw, vfid, req, &resp, vfinfo);
		if (err)
			resp.cmd.err_code = err;
		break;
	case MCE_VF_SET_VLAN: {
		int add = req->data[0];
		int vid = req->data[1];

		if (vid) {
			if (add)
				mce_set_vf_vlan(pf, vfid, vid);
			else
				mce_del_vf_vlan(pf, vfid, vid);
		}
		break;
	}
	case MCE_VF_SET_VLAN_STRIP: {
		bool vlan_strip_on = !!(req->data[0] >> 31);
		int vlan = req->data[0] & 0xffff;

		mce_set_vf_vlan_strip(pf, vfid, vlan, 0 /*FIXME*/,
				      vlan_strip_on);
		break;
	}
	case MCE_VF_SET_MAC_ADDR: {
		u8 *new_mac = ((u8 *)(&req->data[0]));
		if (!rte_is_unicast_ether_addr(
			    (struct rte_ether_addr *)new_mac)) {
			dev_err(mce_hw_to_dev(hw),
				"VF %d attempted to set invalid mac "
				"addr\n",
				mbx->nr_vf);
			break;
		}
		mce_set_vf_mac_addr(pf, vfid, new_mac);
		break;
	}
	case MCE_VF_SET_NTUPLE: {
		struct mce_vf_ntuple_rule *rule = (struct mce_vf_ntuple_rule *)(&req->data[0]);

		if (rule->add)
			err = mce_vf_add_ntuple(pf, vfid, rule);
		else
			err = mce_vf_del_ntuple(pf, vfid, rule);
		if (err < 0) {
			resp.cmd.flag_no_resp = 0;
			resp.cmd.err_code = err;
		}
		printf("ret ==> %d\n", err);
		break;
	}
	case MCE_VF_SET_PROMISC_MODE: {
		u32 flags = req->data[0];
		mce_set_vf_promisc(pf, vfid, flags);
		break;
	}
#if 0
	case MCE_VF_SET_MACVLAN_ADDR:
		new_mac = ((u8 *)(&req->data[1]));
		break;
	case MCE_VF_DEL_MACVLAN_ADDR:
		new_mac = ((u8 *)(&req->data[1]));
		break;
#endif
	case MCE_VF_NOTIFY_RING_CNT:
		/* TODO */
		break;
	default:
		stat = HAS_ERR;

		PMD_HW_ERR(hw, "recv vf unknown cmd, vfnum:%d opcode:%8.8x\n",
			   vfid, opcode);

		break;
	}
	RTE_SET_USED(new_mac);

	mce_mbx_send_resp_isr(mbx, &resp);
	mce_mbx_clear_peer_req_irq_with_stat(mbx, stat);
}

/**
 * @brief Handle VF->PF mailbox events (ISR context).
 *
 * Called when a VF generates an event notification (no request payload).
 *
 * @param mbx Mailbox info pointer
 * @param event_id Event identifier
 */
void mce_mbx_vf2pf_event_req_isr(struct mce_mbx_info *mbx, int event_id)
{
	struct mce_vf_info *vfinfo = mbx->vfinfo;

	logd(LOG_MBX_IN_REQ, "%s: event_id:%d\n", mbx->name, event_id);

	switch (event_id) {
	case EVT_VF_MBX_INIT_DONE:
		vfinfo->init_done = 1;
#if 0
		if (vfinfo->init_done)
			vfinfo->clear_to_send = true;
		else
			vfinfo->clear_to_send = false;
#endif
		break;
	case VF_DRV_REMOVR:
		vfinfo->init_done = 1;
		break;
	}
}

int mce_vf_notify_trust_state(struct mce_hw *hw, int vfid, bool on)
{
        enum PF2VF_EVENT_ID event;

        event = on ? EVT_PF_TRUST_ON : EVT_PF_TRUST_OFF;
        return mce_mbx_send_event_to_vf(hw, vfid, event, 1000);
}
