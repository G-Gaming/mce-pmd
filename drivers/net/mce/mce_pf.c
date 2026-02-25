#include <assert.h>

#include <rte_ether.h>
#include <rte_tailq.h>

#include "mce.h"
#include "mce_flow.h"
#include "mce_logs.h"
#include "mce_compat.h"
#include "mce_pf.h"

#include "base/mce_pfvf.h"
#include "base/mce_eth_regs.h"
#include "base/mce_mbx.h"
#include "base/mce_l2_filter.h"
#include "base/mce_switch.h"
#include "base/mce_pf2vfchnl.h"

/**
 * @brief Initialize PF-specific data structures and mailbox configuration.
 *
 * Allocates VF info array, configures per-VF mailbox structures and default
 * MAC addresses, and sets initial PF-level hardware settings.
 *
 * @param eth_dev Pointer to the Ethernet device representing the PF.
 * @return 0 on success, negative errno on failure.
 */
int mce_pf_init(struct rte_eth_dev *eth_dev)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(eth_dev);
	struct mce_hw *hw = NULL;
	struct mce_mbx_info *pf2vf_mbx;
	int ret = 0;
	int i = 0;

	pf->vfinfos =
		rte_zmalloc(NULL, sizeof(struct mce_vf_info) * pf->max_vfs, 0);
	if (pf->vfinfos == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate VF_infos for %d VFs",
				pf->max_vfs);
		return -ENOMEM;
	}
	pf->dev_data = eth_dev->data;
	hw = pf->pf_vport->hw;
	pf->vf_nb_qp_max = 4;
	/* default spoofcheck is enabled */
	for (i = 0; i < pf->max_vfs; i++) {
		/* pf2vf mailbox */
		pf2vf_mbx = &hw->pf2vf_mbx[i];
		mce_setup_pf2vf_mbx_info(hw, i, pf2vf_mbx);
		mce_mbx_init_configure(pf2vf_mbx);

		rte_eth_random_addr(pf->vfinfos[i].mac_addr.addr_bytes);
		pf->vfinfos[i].max_qps = pf->vf_nb_qp_max;
		pf->vfinfos[i].max_ntuple = MCE_MAX_NTUPLE_NUM / pf->max_vfs;
		/*   pf->vfinfos[i].spoofchk = 1; */
		TAILQ_INIT(&pf->vfinfos[i].mac_list);
		mce_vf_mac_spoof_ctrl(hw, i + 1, true);
		mce_update_vf_spoof_mac(
			hw, i + 1,
			(uint8_t *)&pf->vfinfos[i].mac_addr.addr_bytes);
	}
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	ret = rte_eth_switch_domain_alloc(&pf->switch_domain_id);
	if (ret) {
		PMD_INIT_LOG(WARNING,
			     "failed to allocate switch domain for device %d",
			     ret);
	}
	/* setup vet tx to rx atf filter match */
#define MCE_E_POST_CTRL		 _ETH_(0x047c)
#define MCE_VEB_DOWN_MATCH_TO_UP RTE_BIT32(0)
	MCE_E_REG_SET_BITS(hw, 0x8047c, 0, MCE_VEB_DOWN_MATCH_TO_UP);
	/* enable antispoof */
	MCE_E_REG_SET_BITS(hw, MCE_ETH_GLOBAL_L2_F_CTRL, 0,
			   MCE_G_ANTI_SPOOF_MAC_F_EN |
				   MCE_G_ANTI_SPOO_VLAN_F_EN);
#else
	RTE_SET_USED(ret);
#endif
	return 0;
}

static void mce_free_vfinfo_mac_list(struct mce_vf_info *vfinfo)
{
	struct mce_mac_filter *it = NULL;
	void *temp = NULL;

	if (TAILQ_EMPTY(&vfinfo->mac_list)) {
		return;
	}

	RTE_TAILQ_FOREACH_SAFE(it, &vfinfo->mac_list, next, temp) {
		rte_free(it);
	}
}

/**
 * @brief Uninitialize PF resources and free per-VF state.
 *
 * Frees VF info arrays, clears MAC lists and releases any allocated
 * switch domain resources.
 *
 * @param eth_dev Pointer to the Ethernet device representing the PF.
 * @return 0 on success.
 */
int mce_pf_uinit(struct rte_eth_dev *eth_dev)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(eth_dev);
	int i = 0;

	for (i = 0; i < pf->max_vfs; i++) {
		mce_free_vfinfo_mac_list(&pf->vfinfos[i]);
	}
	rte_free(pf->vfinfos);
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	rte_eth_switch_domain_free(pf->switch_domain_id);
#endif
	return 0;
}

/**
 * @brief Set a VF's user MAC address and program PF/VF switch or spoof rules.
 *
 * Updates the per-VF MAC filter list and programs the hardware to forward
 * or anti-spoof based on current PF mode.
 *
 * @param pf Pointer to the PF structure.
 * @param vf VF index to configure.
 * @param mac 6-byte MAC address to assign to the VF.
 * @return 0 on success, negative errno on failure.
 */
int mce_set_vf_mac_addr(struct mce_pf *pf, uint16_t vf, uint8_t *mac)
{
	struct mce_vf_info *vfinfo = &pf->vfinfos[vf];
	struct mce_mac_filter *mac_filter = NULL;
	struct mce_hw *hw = pf->pf_vport->hw;
	struct mce_mac_entry entry;
	struct mce_mac_filter *it;
	char mac_buf[128] = { 0 };
	bool new = false;
	int ret = 0;

	rte_ether_format_addr(mac_buf, 128, (const struct rte_ether_addr *)mac);
	if (vfinfo == NULL) {
		PMD_INIT_LOG(ERR, "VF info is NULL for VF %u", vf);
		return -EINVAL;
	}
	if (rte_is_zero_ether_addr((const struct rte_ether_addr *)mac) ||
	    !rte_is_unicast_ether_addr((const struct rte_ether_addr *)mac)) {
		return -EINVAL;
	}
	if (!memcmp(&vfinfo->set_addr, mac, 6)) {
		PMD_INIT_LOG(INFO, "vf set mac aleady setup");
		return 0;
	}
	/* find already set mac filter */
	memset(&entry, 0, sizeof(entry));
	memcpy(&entry.mac_addr, &vfinfo->set_addr, 6);
	it = mce_mac_filter_lookup(&vfinfo->mac_list, &entry);
	if (it == NULL) {
		it = rte_zmalloc(NULL, sizeof(*mac_filter), 0);
		if (it == NULL) {
			PMD_INIT_LOG(INFO, "vf_mac_addr alloc failed");
			return -ENOMEM;
		}
		new = true;
	}
	memcpy(&vfinfo->set_addr, mac, 6);
	if (pf->is_switchdev == 0) {
		if (!new) {
			/* remove old legend switch rule */
			ret = mce_sw_remove_vf_macaddr(hw, it, vf);
			if (ret < 0) {
				PMD_INIT_LOG(ERR, "remove old mac failed\n");
				return ret;
			}
		}
		/* add legend switch rule forward to sriov */
		memcpy(&it->mac, mac, 6);
		ret = mce_sw_set_vf_macaddr(hw, it, vf);
		if (ret) {
			return ret;
		}
	} else {
		memcpy(&it->mac, mac, 6);
	}
	if (new)
		TAILQ_INSERT_TAIL(&vfinfo->mac_list, it, next);
	it->mac.loc = vf;
	/*  mce_set_mac_addr(pf->pf_vport, it); */
	printf("mac_loc %d\n", it->mac.loc);
	if (vfinfo->spoofchk) {
		mce_update_vf_spoof_mac(hw, vf, mac);
		printf("update_vf_spoof_mac\n");
	}

	return 0;
}

/**
 * @brief Enable or disable VLAN filtering for a VF.
 *
 * @param pf Pointer to the PF structure.
 * @param vf VF index.
 * @param on true to enable filtering, false to disable.
 * @return 0 on success.
 */
int mce_set_vf_vlan_filter(struct mce_pf *pf, uint16_t vf, bool on)
{
	struct mce_hw *hw = pf->pf_vport->hw;
	uint16_t rank, vf_bit = 0;

	rank = vf / 32;
	vf_bit = vf & (32 - 1);
	if (on)
		MCE_E_REG_SET_BITS(hw, MCE_VF_VLAN_FILTER_CTRL(rank), 0,
				   RTE_BIT32(vf_bit));
	else
		MCE_E_REG_SET_BITS(hw, MCE_VF_VLAN_FILTER_CTRL(rank),
				   RTE_BIT32(vf_bit), 0);

	return 0;
}

/**
 * @brief Add or remove a VLAN VID mapping for a VF at a given location.
 *
 * @param pf Pointer to the PF structure.
 * @param vf VF index.
 * @param vid VLAN identifier to add or remove.
 * @param loc Location/index in the VF's VLAN mapping table.
 * @param add true to add the VID, false to remove it.
 * @return 0 on success.
 */
int mce_update_vf_vlan_vid(struct mce_pf *pf, uint16_t vf, uint16_t vid,
			   uint16_t loc, bool add)
{
	struct mce_hw *hw = pf->pf_vport->hw;
	uint16_t rank = 0, list = 0;
	uint32_t reg = 0;

	rank = loc / 2;
	list = loc % 2;
	reg = MCE_E_REG_READ(hw, MCE_VF_VLAN_VID_CTRL(vf, rank));
	if (add) {
		if (!list) {
			reg &= ~GENMASK_U32(15, 0);
			reg |= vid;
		} else {
			reg &= ~GENMASK_U32(31, 16);
			reg |= (vid << 16);
		}
		MCE_E_REG_WRITE(hw, MCE_VF_VLAN_VID_CTRL(vf, rank), reg);
	} else {
		if (!list)
			reg &= ~GENMASK_U32(15, 0);
		else
			reg &= ~GENMASK_U32(31, 16);

		MCE_E_REG_WRITE(hw, MCE_VF_VLAN_VID_CTRL(vf, rank), reg);
	}

	return 0;
}

/**
 * @brief Configure VLAN strip/insert behavior for a VF's queue.
 *
 * @param pf Pointer to the PF structure.
 * @param vf VF index.
 * @param strip_layers Number of VLAN layers to strip when enabled.
 * @param loc Queue location/index associated with this configuration.
 * @param on true to enable stripping, false to disable.
 * @return 0 on success.
 */
int mce_set_vf_vlan_strip(struct mce_pf *pf, uint16_t vf, uint16_t strip_layers,
			  uint16_t loc, bool on)
{
	struct mce_hw *hw = pf->pf_vport->hw;
	uint16_t offset;
	uint32_t reg = 0;

	offset = vf * 4 + loc;

	reg = MCE_E_REG_READ(hw, MCE_PF_QUEUE_VLAN_STRIP_CTRL(offset));
	reg &= ~MCE_QUEUE_STRIP_MASK;
	if (on) {
		reg |= strip_layers << MCE_QUEUE_STRIP_S;
		reg |= MCE_QUEUE_STRIP_VLAN_EN;
	} else {
		reg &= ~MCE_QUEUE_STRIP_VLAN_EN;
	}
	MCE_E_REG_WRITE(hw, MCE_PF_QUEUE_VLAN_STRIP_CTRL(offset), reg);

	return 0;
}

int mce_en_vf_mulcast_filter(struct mce_pf *pf, uint16_t vf, bool en)
{
	struct mce_hw *hw = pf->pf_vport->hw;
	uint16_t rank, vf_bit = 0;

	rank = vf / 32;
	vf_bit = vf & (32 - 1);
	if (en)
		MCE_E_REG_SET_BITS(hw, MCE_VF_MC_FILTER_CTRL(rank), 0,
				   RTE_BIT32(vf_bit));
	else
		MCE_E_REG_SET_BITS(hw, MCE_VF_MC_FILTER_CTRL(rank),
				   RTE_BIT32(vf_bit), 0);

	return 0;
}

int mce_add_vf_mulcast_filter(struct mce_pf *pf, uint16_t vf, u8 *addr, int loc,
			      bool add)
{
	struct mce_hw *hw = pf->pf_vport->hw;
	uint32_t reg0 = 0, reg1 = 0;
	uint16_t rank = 0, list = 0;

	RTE_SET_USED(add);
	if (loc >= MCE_VF_MULCAST_MAX_NUM) {
		PMD_INIT_LOG(INFO, "vf set mulcast overflow\n");
		return -EINVAL;
	}
	if (loc < 8) {
		rank = (loc * 3) / 2;
		list = loc % 2;
	} else {
		rank = ((loc - 8) * 3) / 2;
		list = (loc - 8) % 2;
	}
	reg0 = MCE_E_REG_READ(hw, MCE_VF_MULCAST_CTRL0(vf, rank));
	reg1 = MCE_E_REG_READ(hw, MCE_VF_MULCAST_CTRL0(vf, rank + 1));
	if (!list) {
		reg0 = addr[5];
		reg0 |= addr[4] << 8;
		reg0 |= addr[3] << 16;
		reg0 |= addr[2] << 24;
		reg1 &= ~(GENMASK_U32(15, 0));
		reg1 |= addr[1];
		reg1 |= addr[0] << 8;
	} else {
		reg0 &= ~(GENMASK_U32(31, 16));
		reg0 |= addr[5] << 16;
		reg0 |= addr[4] << 24;
		reg1 = addr[3];
		reg1 |= addr[2] << 8;
		reg1 |= addr[1] << 16;
		reg1 |= addr[0] << 24;
	}
	MCE_E_REG_WRITE(hw, MCE_VF_MULCAST_CTRL0(vf, rank), reg0);
	MCE_E_REG_WRITE(hw, MCE_VF_MULCAST_CTRL0(vf, rank + 1), reg1);

	return 0;
}

int mce_get_vf_reg(struct mce_pf *pf, uint16_t vf, int addr, int *val)
{
	struct mce_hw *hw = pf->pf_vport->hw;

	RTE_SET_USED(vf);
	*val = MCE_E_REG_READ(hw, addr);

	return 0;
}

int mce_get_vf_dma_frag(struct mce_pf *pf, uint16_t vf, int *frag_len)
{
	RTE_SET_USED(pf);
	RTE_SET_USED(vf);
	RTE_SET_USED(pf);
	/* we fixed 1536 bytes */
	*frag_len = 1536;

	return 0;
}

int mce_set_vf_vlan(struct mce_pf *pf, uint16_t vf, uint16_t vid)
{
	RTE_SET_USED(pf);
	RTE_SET_USED(vf);
	RTE_SET_USED(vid);

	return 0;
}

int mce_del_vf_vlan(struct mce_pf *pf, uint16_t vf, uint16_t vid)
{
	RTE_SET_USED(pf);
	RTE_SET_USED(vf);
	RTE_SET_USED(vid);

	return 0;
}

int mce_set_vf_promisc(struct mce_pf *pf, uint16_t vf, uint64_t promisc_flag)
{
	RTE_SET_USED(pf);
	RTE_SET_USED(vf);
	RTE_SET_USED(promisc_flag);

	return 0;
}

#define MCE_SET_TRUST_VPORT(hw, vf_id) \
do { \
	uint32_t reg_index = (vf_id) / 32; \
	uint32_t bit_pos = (vf_id) % 32; \
	uint32_t reg_addr = 0xe000 + (reg_index * 4); \
	uint32_t reg_val = MCE_E_REG_READ(hw, reg_addr); \
	reg_val |= (1 << bit_pos); \
	MCE_E_REG_WRITE(hw, reg_addr, reg_val); \
} while(0)

#define MCE_CLEAR_TRUST_VPORT(hw, vf_id) \
do { \
        uint32_t reg_index = (vf_id) / 32; \
        uint32_t bit_pos = (vf_id) % 32; \
        uint32_t reg_addr = 0xe000 + (reg_index * 4); \
	uint32_t reg_val = MCE_E_REG_READ(hw, reg_addr);\
        reg_val &= ~(1 << bit_pos); \
	MCE_E_REG_WRITE(hw, reg_addr, reg_val);\
} while(0)

static void
mce_vf_set_trusted(struct mce_hw *hw, int vf_id, bool trusted)
{
	if (trusted)
		MCE_SET_TRUST_VPORT(hw, vf_id);
	else
		MCE_CLEAR_TRUST_VPORT(hw, vf_id);
}

int mce_set_vf_trust(struct mce_pf *pf, int vf_id, bool trusted)
{
	struct mce_vf_info *vfinfo = &pf->vfinfos[vf_id];
	struct mce_hw *hw = pf->pf_vport->hw;

	if (vfinfo->trusted != trusted) {
		vfinfo->trusted = trusted;
		mce_vf_set_trusted(hw, vf_id, trusted);
		mce_vf_notify_trust_state(hw, vf_id, trusted);
	}

        return 0;
}
