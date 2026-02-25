/**
 * @file mce_pfvf.c
 * @brief PF-VF integration and shared resource management implementation
 *
 * Implements PF-VF integration layer providing:
 * - VF resource allocation and configuration
 * - Capability negotiation between PF and VF
 * - Queue assignment and management
 * - Per-VF rate limiting and traffic policies
 * - VF link state synchronization
 * - VF statistics collection
 *
 * PF Responsibilities:
 * - VF creation and initialization
 * - MAC address assignment
 * - VLAN enforcement
 * - Queue bandwidth allocation
 * - Trust mode configuration
 * - Link state updates
 *
 * @see mce_pfvf.h for data structures
 * @see base/mce_mbx.c for PF-VF communication
 * @see mce_pf.h for PF implementation
 */
#include "../mce_pf.h"

#include "mce_pfvf.h"
#include "mce_mbx.h"
#include "mce_eth_regs.h"

/**
 * @brief Initialize flow engine modules for a vport.
 *
 * Creates and registers available flow engines (generic, RSS, FDIR,
 * switch) for the vport and invokes their init callbacks.
 *
 * @param vport Pointer to vport to configure
 */
static void mce_init_flow_engine(struct mce_vport *vport)
{
	struct mce_flow_engine_module *flow_engine;

	TAILQ_INIT(&vport->flow_engine_list);
	TAILQ_INIT(&vport->flow_list);
	/* generic filter register */
	flow_engine = rte_zmalloc("mce_generic_filter",
				  sizeof(struct mce_flow_engine_module), 0);
	*flow_engine = mce_generic_engine;
	TAILQ_INSERT_TAIL(&vport->flow_engine_list, flow_engine, node);
	flow_engine->init(vport, &flow_engine->handle);
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	/* rss configure register */
	flow_engine = rte_zmalloc("mce_rss_fd",
				  sizeof(struct mce_flow_engine_module), 0);
	*flow_engine = mce_rss_engine;
	TAILQ_INSERT_TAIL(&vport->flow_engine_list, flow_engine, node);
	flow_engine->init(vport, &flow_engine->handle);
#endif
	/* fdir register */
	flow_engine = rte_zmalloc("mce_fdir",
				  sizeof(struct mce_flow_engine_module), 0);
	*flow_engine = mce_fdir_engine;
	TAILQ_INSERT_TAIL(&vport->flow_engine_list, flow_engine, node);
	flow_engine->init(vport, &flow_engine->handle);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	/* switch register */
	flow_engine = rte_zmalloc("mce_switch",
				  sizeof(struct mce_flow_engine_module), 0);
	*flow_engine = mce_switch_engine;
	TAILQ_INSERT_TAIL(&vport->flow_engine_list, flow_engine, node);
	flow_engine->init(vport, &flow_engine->handle);
#endif
}

static void mcevf_init_flow_engine(struct mce_vport *vport)
{
	struct mce_flow_engine_module *flow_engine;

	TAILQ_INIT(&vport->flow_engine_list);
	TAILQ_INIT(&vport->flow_list);
	/* generic filter register */
	flow_engine = rte_zmalloc("mce_generic_filter",
				  sizeof(struct mce_flow_engine_module), 0);
	*flow_engine = mce_generic_engine;
	TAILQ_INSERT_TAIL(&vport->flow_engine_list, flow_engine, node);
	flow_engine->init(vport, &flow_engine->handle);
	/* rss configure register */
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	/* rss configure register */
	flow_engine = rte_zmalloc("mce_rss",
				  sizeof(struct mce_flow_engine_module), 0);
	*flow_engine = mce_rss_engine;
	TAILQ_INSERT_TAIL(&vport->flow_engine_list, flow_engine, node);
	flow_engine->init(vport, &flow_engine->handle);
#endif
}

/**
 * @brief Uninitialize all flow engines attached to a vport.
 *
 * Calls each engine's uinit callback to release resources.
 *
 * @param vport Pointer to vport
 */
static void mce_uinit_flow_engine(struct mce_vport *vport)
{
	struct mce_flow_engine_module *it;

	RTE_TAILQ_FOREACH(it, &vport->flow_engine_list, node) {
		it->uinit(vport, it->handle);
	}
}

 /**
 * @brief Reset VF configuration registers to default values.
 *
 * Clears per-vf RSS, etype tables and multicast entries for a VF
 * to bring it to a known default state.
 *
 * @param hw Hardware context for the VF
 */
static void mce_reset_config_vf(struct mce_hw *hw)
{
	u32 base;
	u32 off;
	int i = 0;

	MCE_E_REG_WRITE(hw, hw->vp_reg_base[MCE_VP_ATTR], 0);
	base = hw->vp_reg_base[MCE_VP_RSS_ACT];
	off = 0x4;
	for (i = 0; i < hw->nb_qpair_per_vf; i++)
		MCE_E_REG_WRITE(hw, base + 0x4 * i, MCE_Q_ATTR_RSS_Q_VALID);
	for (i = 0; i < MCE_MAX_ETYPE_NUM; i++) {
		MCE_E_REG_WRITE(hw, hw->vp_reg_base[MCE_VP_ETQF] + off * i, 0);
		MCE_E_REG_WRITE(hw, hw->vp_reg_base[MCE_VP_ETQS] + off * i, 0);
	}
	for (i = 0; i < MCE_MCAST_ADDR_PER_VF; i++) {
		u32 val_hi;
		u32 val_lo;
		int list;
		u32 addr;

		if (i < 8) {
			list = i % 2;
			addr = hw->vp_reg_base[MCE_VP_MULTICAST_LO_F];
		} else {
			list = (i - 8) % 2;
			addr = hw->vp_reg_base[MCE_VP_MULTICAST_HI_F];
		}
		val_lo = MCE_E_REG_READ(hw, addr);
		val_hi = MCE_E_REG_READ(hw, addr + 4);
		if (!list) {
			val_lo = 0;
			val_hi &= ~(GENMASK_U32(15, 0));
		} else {
			val_lo &= ~(GENMASK_U32(31, 16));
			val_hi = 0;
		}
		MCE_E_REG_WRITE(hw, addr, val_lo);
		MCE_E_REG_WRITE(hw, addr + 4, val_hi);
	}
	MCE_E_REG_WRITE(hw, hw->vp_reg_base[MCE_VP_SYNQF_F], 0);
	MCE_E_REG_WRITE(hw, hw->vp_reg_base[MCE_VP_SYNQF_PRI], 0);
}


 /**
 * @brief Initialize resource limits for a VF vport.
 *
 * Populate vport attribute limits (queues, mac addrs, reta size, etc.)
 * based on hardware capabilities for VF contexts.
 *
 * @param vport Pointer to vport to initialize
 * @param hw Hardware context
 */
static void mcevf_init_resource_parameter(struct mce_vport *vport,
					  struct mce_hw *hw)
{
	int vfnum = hw->vfnum;

	vport->attr.max_rx_queues = hw->nb_qpair_per_vf;
	vport->attr.max_tx_queues = hw->nb_qpair_per_vf;
	vport->attr.vport_id = vfnum;
	vport->attr.is_vf = true;

	vport->attr.max_mcast_addrs = MCE_MCAST_ADDR_PER_VF;
	vport->attr.max_mac_addrs = hw->nb_mac_per_vf;
	vport->attr.max_reta_num = hw->max_reta_num;
	vport->attr.max_pkt_len = hw->max_pkt_len;
	vport->attr.trust_on = hw->trust_on;
	vport->attr.max_ntuple_num = 4;
	vport->attr.max_mac_addrs = 1;

	memcpy(vport->mac_addr, &hw->mac.assign_addr, RTE_ETHER_ADDR_LEN);
}

 /**
 * @brief Initialize generic resource parameters for a vport (PF case).
 *
 * Sets qpair ranges, hash table sizes and other defaults for PF vports.
 *
 * @param vport Pointer to vport
 * @param hw Hardware context
 */
static void mce_init_resource_parameter(struct mce_vport *vport,
					struct mce_hw *hw)
{
	uint16_t qpair_offset = 0;

	if (hw->max_vfs == 0) {
		vport->attr.max_rx_queues = hw->nb_qpair;
		vport->attr.max_tx_queues = hw->nb_qpair;
		vport->attr.max_mac_addrs = MCE_MAX_MAC_ADDRESS;
		vport->attr.qpair_offset = 0;
		vport->attr.speed = RTE_ETH_SPEED_NUM_100G;
		vport->attr.mc_hash_tb_size = MCE_MULTICAST_HASH_TABLE_SIZE;
		vport->attr.uc_hash_tb_size = MCE_UNICAST_HASH_TABLE_SIZE;
		vport->attr.qpair_base = 0;
		vport->attr.max_ntuple_num = MCE_MAX_NTUPLE_NUM;
	} else {
		vport->attr.max_rx_queues = hw->nb_qpair_per_vf;
		vport->attr.max_tx_queues = hw->nb_qpair_per_vf;
		vport->attr.max_mac_addrs = 4;
		vport->attr.max_ntuple_num = MCE_MAX_NTUPLE_NUM / hw->max_vfs;
		vport->attr.max_tx_queues = hw->vf_max_ring;
		vport->attr.max_rx_queues = hw->vf_max_ring;
		vport->attr.vport_id = 127;
		qpair_offset = vport->attr.vport_id * hw->vf_max_ring;
		vport->attr.qpair_offset = qpair_offset;
		vport->attr.qpair_base = qpair_offset;
	}
	vport->attr.hash_filter_type = 0;
	vport->attr.hash_table_shift = MCE_UTA_BIT_SHIFT;
	vport->attr.max_mc_mac_hash = vport->attr.mc_hash_tb_size * 32;
	vport->attr.max_uc_mac_hash = vport->attr.uc_hash_tb_size * 32;

	vport->attr.max_reta_num = hw->max_reta_num;
	vport->attr.max_pkt_len = hw->max_pkt_len;
	vport->min_dma_size = 64;
}

 /**
 * @brief Allocate and initialize a vport structure.
 *
 * Allocates a new `mce_vport`, initializes flow engines, resource
 * parameters and registers. For VF vports additional VF-specific
 * reset/config is applied.
 *
 * @param hw Hardware context
 * @param type Type of vport to allocate (PF or VF)
 * @return Pointer to allocated `mce_vport` or NULL on failure
 */
struct mce_vport *mce_alloc_vport(struct mce_hw *hw, enum mce_vport_type type)
{
	struct mce_adapter *adapter = hw->back;
	struct mce_vport *vport = NULL;

	vport = rte_zmalloc("vport", sizeof(*vport), 0);
	if (vport == NULL)
		return NULL;
	if (type == MCE_VPORT_IS_PF) {
		vport->attr.smid_force_en = adapter->pf.force_smid_en;
		vport->data = adapter->pf.dev->data;
		vport->dev = adapter->pf.dev;
		vport->hw = hw;
		mce_init_resource_parameter(vport, hw);
		mce_init_flow_engine(vport);
	}
	if (type == MCE_VPORT_IS_VF) {
		vport->data = adapter->vf.dev->data;
		vport->is_vf = MCE_VPORT_IS_VF;
		vport->dev = adapter->vf.dev;
		vport->hw = hw;
		mcevf_init_resource_parameter(vport, hw);
		mcevf_init_flow_engine(vport);
	}
	mce_vport_reg_setup(vport);
	if (type == MCE_VPORT_IS_VF)
		mce_reset_config_vf(hw);
	vport->lut = rte_zmalloc("vport_lut",
			vport->attr.max_reta_num * sizeof(uint32_t), 0);
	if (vport->lut == NULL)
		goto lut_failed;
	TAILQ_INIT(&vport->vlan_list);
	TAILQ_INIT(&vport->mac_list);

	return vport;
lut_failed:
	mce_uinit_flow_engine(vport);
	rte_free(vport);

	return NULL;
}

 /**
 * @brief Destroy and free a vport previously allocated.
 *
 * Unregisters flow engines, frees lookup memory and releases the
 * vport structure.
 *
 * @param vport Pointer to vport to destroy
 */
void mce_destory_vport(struct mce_vport *vport)
{
	struct mce_hw *hw = vport->hw;

	mce_uinit_flow_engine(vport);
	if (!vport->is_vf && hw->max_vfs)
		mce_pf_uinit(vport->dev);
	rte_free(vport->lut);
	rte_free(vport);
}

 /**
 * @brief Program RSS RETA table for a vport.
 *
 * Writes the provided LUT into per-vport RETA hardware registers.
 *
 * @param vport Pointer to vport
 * @param lut Lookup table entries to program
 */
void mce_setup_rss_reta(struct mce_vport *vport, u32 *lut)
{
	struct mce_hw *hw = vport->hw;
	u32 reta_base_ctrl = 0;
	u16 max_reta_num = 0;
	u16 reta_size = 0;
	u16 step = 0x4;
	int i = 0;

	max_reta_num = vport->attr.max_reta_num;
	reta_size = max_reta_num / 2;
	reta_base_ctrl = hw->vp_reg_base[MCE_VP_RSS_RETA];
	for (i = 0; i < reta_size; i++)
		MCE_E_REG_WRITE(hw, reta_base_ctrl + step * i, lut[i]);
}

 /**
 * @brief Read back the RSS RETA table for a vport.
 *
 * Reads the hardware RETA registers into the provided LUT buffer.
 *
 * @param vport Pointer to vport
 * @param lut Output buffer to fill with RETA entries
 */
void mce_get_rss_reta(struct mce_vport *vport, u32 *lut)
{
	u16 vport_id = vport->attr.vport_id;
	struct mce_hw *hw = vport->hw;
	u32 reta_base_ctrl = 0;
	u16 max_reta_num = 0;
	u16 reta_size = 0;
	u16 step = 0x4;
	int i = 0;

	max_reta_num = vport->attr.max_reta_num;
	reta_size = max_reta_num / 2;
	memset(vport->lut, 0, sizeof(*vport->lut) * reta_size);
	if (vport->is_vf || hw->max_vfs) {
		reta_base_ctrl = MCE_VF_ETH_RSS_RETA_BASE;
		reta_base_ctrl += (vport_id * reta_size * step);
	} else {
		reta_base_ctrl = MCE_PF_ETH_RSS_RETA_BASE;
	}

	for (i = 0; i < reta_size; i++)
		lut[i] = MCE_E_REG_READ(hw, reta_base_ctrl + step * i);
}
