/**
 * @file mce_vf.c
 * @brief VF (Virtual Function) hardware initialization and management implementation
 *
 * Provides VF-specific hardware initialization, configuration, and communication
 * with the host PF (Physical Function). Implements VF lifecycle management
 * through the PF-VF mailbox protocol
 * Key Functions:\n * - mce_init_hw_vf()
 * - VF hardware initialization (minimal)
 * - mce_reset_hw_vf()
 * - VF reset via mailbox to PF
 * - VF capability negotiation
 * - MAC address and VLAN configuration from PF
 * - Link state and speed reporting
 * - Trust mode and FCS stripping negotiation
 * VF Constraints:
 * - Limited direct hardware access compared to PF
 * - All configuration changes go through PF-VF mailbox
 * - MAC addresses assigned by PF (anti-spoofing)
 * - VLAN configuration enforced by PF
 * - RSS configuration per VF
 * - Rate limiting configured at VF level
 * @see mce_pfvf.h for PF-VF communication structures
 * @see mce_mbx.h for mailbox protocol
 * @see base/mce_common.c for shared hardware initialization
 */
#include <rte_malloc.h>
#include "mce_hw.h"
#include "mce_mbx.h"
#include "mce_pfvf.h"
#include "mce_vf.h"
#include "mce_eth_regs.h"

static s32 mce_init_hw_vf(struct mce_hw *hw __maybe_unused)
{
	return 0;
}

/**
 * @brief Minimal VF hardware initialization.
 *
 * Performs any platform-specific VF hardware initialization required
 * on systems where the VF has limited direct control. Currently a
 * no-op placeholder.
 *
 * @param hw Pointer to the VF hardware context
 * @return 0 on success
 */


static s32 mce_reset_hw_vf(struct mce_hw *hw)
{
	int err = 0, try_cnt = 1;
	struct mce_mbx_info *mbx = &hw->vf2pf_mbx;
	struct mbx_resp resp = {};
	unsigned int *resp_data = resp.data;

	logd(LOG_MBX_REQ_OUT, "%s: %s L%d\n", __func__, mbx->name, __LINE__);

	while (try_cnt--) {
		err = mce_mbx_send_req(mbx, MCE_VF_RESET, NULL, 0, &resp, 5000);
		if (err == 0)
			break;

		rte_delay_us(1000);
	}
	if (err) {
		PMD_HW_ERR(hw, "%s:send VF_RESET to pf timeout\n", mbx->name);
		return err;
	}

	/* we get mac address from mailbox */
	memcpy(hw->perm_mac_addr, &resp_data[F_VF_MAC_ADDR],
	       RTE_ETHER_ADDR_LEN);
	if (!rte_is_unicast_ether_addr(
		    (struct rte_ether_addr *)hw->perm_mac_addr)) {
		PMD_HW_ERR(hw,
			   "invalid mac address:%02x:%02x:%02x:%02x:%02x:%02x, "
			   "gen random mac addr\n",
			   hw->perm_mac_addr[0], hw->perm_mac_addr[1],
			   hw->perm_mac_addr[2], hw->perm_mac_addr[3],
			   hw->perm_mac_addr[4], hw->perm_mac_addr[5]);
		rte_eth_random_addr(hw->perm_mac_addr);
	}

	hw->nb_qpair_per_vf = hw->vf_max_ring =
		resp_data[F_VF_RESET_RING_MAX_CNT];
	hw->fw_version = resp_data[F_VF_RESET_FW_VERSION];
	/* pf->vf_vlan = resp_data[F_VF_RESET_VLAN] & 0xffff;*/
	/* get link state from pf */
	hw->link_status = !!(resp_data[F_VF_RESET_LINK_ST] & (1 << 31));
	hw->link_speed = resp_data[F_VF_RESET_LINK_ST] & 0xffff;
	hw->link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	hw->link_autoneg = RTE_ETH_LINK_FIXED;
	hw->pf_stat.nr_pf = !!resp_data[F_VF_NR_PF];
	hw->pf_rxfcs_en = !!resp_data[F_VF_RXFCS_STATE];
	hw->trust_on = !!resp_data[F_VF_TRUST_STATE];
	hw->vf_bar_isolate_on = 1;
	hw->max_pkt_len = MCE_MAX_FRAME_SIZE;
	hw->max_reta_num = hw->nb_qpair_per_vf;
	PMD_HW_INFO(
		hw,
		"%s: macaddr %02x:%02x:%02x:%02x:%02x:%02x, ring_max_cnt:%d "
		"fw-version:0x%08x, link_status:%d speed:%d mtu:%d reta:%d "
		"mac_peer_vf:%d irq_peer_vf:%d\n",
		mbx->name, hw->perm_mac_addr[0], hw->perm_mac_addr[1],
		hw->perm_mac_addr[2], hw->perm_mac_addr[3],
		hw->perm_mac_addr[4], hw->perm_mac_addr[5], hw->vf_max_ring,
		hw->fw_version, hw->link_status, hw->link_speed,
		hw->max_pkt_len, hw->max_reta_num, hw->nb_mac_per_vf,
		hw->nb_irq_per_vf);

	memcpy(&hw->mac.assign_addr, hw->perm_mac_addr, RTE_ETHER_ADDR_LEN);

	if (hw->nb_qpair_per_vf == 0 || hw->nb_qpair_per_vf > 128) {
		PMD_HW_ERR(hw, "vf ring_max_cnt:%d is invalid!\n",
			   hw->nb_qpair_per_vf);
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief Reset VF by issuing VF_RESET to the PF via mailbox.
 *
 * Sends a VF reset command and waits for the PF response which
 * includes MAC, ring counts and link state. On success the VF
 * hardware context is populated from the PF-provided data.
 *
 * @param hw Pointer to VF hardware context
 * @return 0 on success, negative errno on failure
 */


static s32 mce_get_mac_addr_vf(struct mce_hw *hw, u8 *mac)
{
	RTE_SET_USED(hw);
	RTE_SET_USED(mac);

	return 0;
}

/**
 * @brief Retrieve the permanent MAC address for VF (stub).
 *
 * For VF builds the MAC is normally provided by the PF via mailbox.
 * This helper is a stub for compatibility.
 *
 * @param hw Pointer to hardware context
 * @param mac Output buffer for MAC address (6 bytes)
 * @return 0 on success
 */


static s32 mce_set_mac_addr_vf(struct mce_hw *hw, u8 *addr)
{
	int err;
	struct mce_mbx_info *mbx = &hw->vf2pf_mbx;
	u32 msgbuf[2] = { 0 };
	u8 *mac_addr = (u8 *)(&msgbuf[0]);

	memcpy(mac_addr, addr, 6);

	err = mce_mbx_send_req(mbx, MCE_VF_SET_MAC_ADDR, msgbuf, sizeof(msgbuf),
			       NULL, 5 * 1000);

	logd(LOG_MBX_REQ_OUT,
	     "%s: %s mac-addr:%02x:%02x:%02x:%02x:%02x:%02x err:%d\n", __func__,
	     mbx->name, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
	     err);
	return err;
}

/**
 * @brief Request PF to set VF MAC address via mailbox.
 *
 * Sends a MCE_VF_SET_MAC_ADDR request with the provided MAC.
 *
 * @param hw Pointer to hardware context
 * @param addr MAC address to set
 * @return 0 on success, negative errno on failure
 */


static s32 mce_en_vlan_filter_vf(struct mce_hw *hw, bool en)
{
	u32 vp_attr_base = 0;
	u32 reg = 0;

	vp_attr_base = hw->vp_reg_base[MCE_VP_ATTR];
	reg = MCE_E_REG_READ(hw, vp_attr_base);
	if (en)
		reg &= ~MCE_FWD_VPE;
	else
		reg |= MCE_FWD_VPE;
	MCE_E_REG_WRITE(hw, vp_attr_base, reg);

	return 0;
}

/**
 * @brief Enable or disable VLAN filtering for VF.
 *
 * Updates VP attribute register to toggle VLAN filtering (VPE).
 *
 * @param hw Pointer to hardware context
 * @param en True to enable filtering, false to disable
 * @return 0 on success
 */


static s32 mce_add_vlan_vid_vf(struct mce_hw *hw, u16 vid, bool add)
{
	struct mce_mbx_info *mbx = &hw->vf2pf_mbx;
	u32 msgbuf[2] = { 0 };
	int err = -EINVAL;

	msgbuf[0] = add;
	msgbuf[1] = vid;
	err = mce_mbx_send_req(mbx, MCE_VF_SET_VLAN, msgbuf, sizeof(msgbuf),
			NULL, 5 * 1000);
	logd(LOG_MBX_REQ_OUT,
			"%s: %s vlan:%d vlan_on:%d\n",
			__func__, mbx->name, vid, add);
	return err;
}

/**
 * @brief Add or remove a VLAN ID for the VF via PF mailbox.
 *
 * Sends a mailbox request to program VLAN membership for the VF.
 *
 * @param hw Pointer to hardware context
 * @param vid VLAN ID to add/remove
 * @param add True to add, false to remove
 * @return 0 on success, negative errno on failure
 */


static s32 mce_en_vlan_strip_vf(struct mce_hw *hw, uint16_t strip_layers,
				u16 loc, bool on)
{
	u32 base = 0;
	u32 reg = 0;

	base = hw->vp_reg_base[MCE_VP_RSS_ACT];
	base += loc * 0x4;
	reg = MCE_E_REG_READ(hw, base);
	reg &= ~MCE_QUEUE_STRIP_MASK;
	if (on) {
		reg |= strip_layers << MCE_QUEUE_STRIP_S;
		reg |= MCE_QUEUE_STRIP_VLAN_EN;
	} else {
		reg &= ~MCE_QUEUE_STRIP_VLAN_EN;
	}
	MCE_E_REG_WRITE(hw, base, reg);

	return -1;
}

/**
 * @brief Enable or disable VLAN strip settings per queue for VF.
 *
 * Updates the per-queue strip configuration register to enable/disable
 * VLAN stripping and set strip layer mask.
 *
 * @param hw Pointer to hardware context
 * @param strip_layers Bitmask of layers to strip
 * @param loc Queue index/location
 * @param on True to enable, false to disable
 * @return 0 on success or negative on error
 */


static s32 mce_en_mulcast_filter_vf(struct mce_hw *hw, bool en)
{
	RTE_SET_USED(hw);
	RTE_SET_USED(en);
	return -1;
}

/**
 * @brief Enable/disable multicast filtering for VF (stub).
 *
 * Placeholder for multicast filtering support on VF contexts.
 */


static s32 mce_add_mulcast_vf(struct mce_hw *hw, u8 *addr, u16 loc)
{
	u32 addr_lo = 0, addr_hi = 0;
	u32 val_lo = 0, val_hi = 0;
	u16 rank = 0, list = 0;
	u32 base = 0;

	if (loc >= MCE_VF_MULCAST_MAX_NUM) {
		PMD_INIT_LOG(INFO,
				"vf set mulcast overflow\n");
		return -EINVAL;
	}
	if (loc < 8) {
		base = hw->vp_reg_base[MCE_VP_MULTICAST_LO_F];
		rank = (loc * 3) / 2;
		list = loc % 2;
	} else {
		base = hw->vp_reg_base[MCE_VP_MULTICAST_HI_F];
		rank = ((loc - 8) * 3) / 2;
		list = (loc - 8) % 2;
	}
	addr_lo = base + rank * 0x4;
	addr_hi = base + rank * 0x4 + 0x4;
	val_lo = MCE_E_REG_READ(hw, addr_lo);
	val_hi = MCE_E_REG_READ(hw, addr_hi);
	if (!list) {
		val_lo = addr[5];
		val_lo |= addr[4] << 8;
		val_lo |= addr[3] << 16;
		val_lo |= addr[2] << 24;
		val_hi &= ~(GENMASK_U32(15, 0));
		val_hi |= addr[1];
		val_hi |= addr[0] << 8;
	} else {
		addr_lo &= ~(GENMASK_U32(31, 16));
		addr_lo |= addr[5] << 16;
		addr_lo |= addr[4] << 24;
		addr_hi = addr[3];
		addr_hi |= addr[2] << 8;
		addr_hi |= addr[1] << 16;
		addr_hi |= addr[0] << 24;
	}
	MCE_E_REG_WRITE(hw, addr_lo, val_lo);
	MCE_E_REG_WRITE(hw, addr_hi, val_hi);

	return 0;
}

/**
 * @brief Add a multicast MAC entry for VF into hardware table.
 *
 * Programs the multicast address into the appropriate VP multicast
 * registers at the provided index.
 *
 * @param hw Pointer to hardware context
 * @param addr 6-byte multicast MAC address
 * @param loc Location/index to program
 * @return 0 on success, negative errno on failure
 */


static s32 mce_clear_mc_filter_vf(struct mce_hw *hw)
{
	u8 mac_addr[RTE_ETHER_ADDR_LEN] = { 0 };
	u16 index = 0;
	int ret;

	/* clean all vf mc_addr first */
	for (index = 0; index < hw->nb_mulcast_per_vf; index++) {
		if (hw->mac.ops->update_mta) {
			ret = hw->mac.ops->update_mta(hw, mac_addr, index);
			if (ret < 0) {
				PMD_DRV_LOG(ERR,
					    "set multicast address failed.");
				return ret;
			}
		}
	}

	return 0;
}

/**
 * @brief Clear all multicast entries for VF.
 *
 * Iterates configured multicast slots and clears them via MAC ops.
 *
 * @param hw Pointer to hardware context
 * @return 0 on success
 */


static s32 mce_get_reg_vf(struct mce_hw *hw, u32 addr, u32 *val)
{
	RTE_SET_USED(hw);
	RTE_SET_USED(addr);
	RTE_SET_USED(val);
	return -1;
}

/**
 * @brief Read a hardware register for VF contexts (stub).
 *
 * VF cannot always access all registers directly; this function is a
 * placeholder that may be implemented per-platform.
 *
 * @param hw Pointer to hardware context
 * @param addr Register address
 * @param val Output value pointer
 * @return 0 on success, negative errno on failure
 */


void mcevf_mbx_pf2vf_event_req_isr(struct mce_mbx_info *mbx, int event_id)
{
	int v;
	struct mce_hw *hw = mbx->hw;
	struct mce_vf *vf __maybe_unused = &hw->back->vf;

	logd(LOG_MBX_IN_REQ, "%s: event_id:%d\n", mbx->name, event_id);

	switch (event_id) {
	case EVT_PF_LINK_CHANGED: {
		v = mcevf_mbx_get_pf_stat(mbx, PF_LINKUP);
		if (v < 0) {
			PMD_HW_DBG(hw, "%s:%s mcevf_mbx_get_pf_stat failed!\n",
				   __func__, mbx->name);
		} else {
			if (v > 0) {
				hw->link_status = true;
				hw->link_speed =
					mcevf_mbx_get_pf_stat(mbx, PF_SPEED);
			} else {
				hw->link_status = false;
				hw->link_speed = 0;
			}
		}
		mce_report_link(hw);

		break;
	}
	case EVT_PF_RESET_VF:
		PMD_HW_DBG(hw, "%s get reset from pf\n", mbx->name);
		mcevf_mbx_clear_reset_done_flag(hw);
		break;
	case EVT_PF_DRV_REMOVE:
		break;
	case EVT_PF_FORCE_VF_LINK_UP:
		hw->link_status = true;
		hw->link_speed = mcevf_mbx_get_pf_stat(mbx, PF_SPEED);
		mce_report_link(hw);
		break;
	case EVT_PF_FORCE_VF_LINK_DOWN:
		hw->link_status = false;
		hw->link_speed = 0;

		mce_report_link(hw);
		break;
	case EVT_PF_TRUST_ON:
		hw->back->vf.vf_vport->attr.trust_on = 1;
		break;
	case EVT_PF_TRUST_OFF:
		hw->back->vf.vf_vport->attr.trust_on = 0;
		break;
	}
}

/**
 * @brief Handle PF->VF mailbox events (ISR context).
 *
 * Processes simple event notifications from PF (link change, reset,
 * trust mode, etc.) and updates local VF hardware context.
 *
 * @param mbx Mailbox info for PF->VF channel
 * @param event_id Event identifier
 */


void mcevf_mbx_pf2vf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req)
{
	struct mce_hw *hw = mbx->hw;
	struct mce_vf *vf __maybe_unused = &hw->back->vf;
	struct mbx_resp resp = {};
	int opcode = req->cmd.opcode;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;

	resp.cmd.v = req->cmd.v;
	resp.cmd.err_code = 0;
	resp.cmd.flag_no_resp = 1; /* default no resp */

	logd(LOG_MBX_IN_REQ,
	     "%s: req-opcode:%d d:0x%08x 0x%08x 0x%08x 0x%08x\n", mbx->name,
	     req->cmd.opcode, req->data[0], req->data[1], req->data[2],
	     req->data[3]);

	switch (opcode) {
	case MCE_PF2VF_SET_VLAN:
		PMD_HW_DBG(hw, "%s: pf set vlan:0x%08x\n", mbx->name,
			   req->data[0]);
		/* FIXME need update vlan */
		break;
	}
	mce_mbx_send_resp_isr(mbx, &resp);
	mce_mbx_clear_peer_req_irq_with_stat(mbx, stat);
}

int mce_request_set_vf_ntuple(struct mce_vport *vport, struct mce_vf_ntuple_rule *rule)
{
	struct mce_mbx_info *mbx = &vport->hw->vf2pf_mbx;
	int err;

	err = mce_mbx_send_req(mbx, MCE_VF_SET_NTUPLE, (uint32_t *)rule,
			sizeof(struct mce_vf_ntuple_rule),
			NULL, 5 * 1000);
	return err;
}

/**
 * @brief Handle PF->VF mailbox requests carrying data (ISR context).
 *
 * Processes incoming mailbox requests from the PF and sends responses
 * where applicable.
 *
 * @param mbx Mailbox info for PF->VF channel
 * @param req Pointer to received mailbox request
 */
const struct mce_mac_ops mcevf_mac_ops = {
	.init_hw = &mce_init_hw_vf,
	.reset_hw = &mce_reset_hw_vf,
	.get_reg = &mce_get_reg_vf,
	.get_mac_addr = &mce_get_mac_addr_vf,
	.set_rafb = &mce_set_mac_addr_vf,
	.enable_mta = &mce_en_mulcast_filter_vf,
	.update_mta = &mce_add_mulcast_vf,
	.clear_mc_filter = &mce_clear_mc_filter_vf,
	.en_vlan_f = &mce_en_vlan_filter_vf,
	.add_vlan_f = &mce_add_vlan_vid_vf,
	.en_strip_f = &mce_en_vlan_strip_vf,
};

/**
 * @brief Initialize VF-specific MAC operation callbacks.
 *
 * Installs the VF implementation of `mce_mac_ops` into the hardware
 * `mce_mac_info` structure.
 *
 * @param hw Pointer to hardware context
 * @return 0 on success
 */
s32 mce_init_ops_vf(struct mce_hw *hw)
{
	struct mce_mac_info *mac = &hw->mac;

	mac->ops = &mcevf_mac_ops;

	return 0;
}
