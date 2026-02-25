/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef _MCE_HW_H_
#define _MCE_HW_H_

#include <rte_version.h>
#include "../mce_compat.h"
#include <rte_spinlock.h>
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_io.h>
#else
static inline uint32_t __attribute__((always_inline))
rte_read32_relaxed(const volatile void *addr)
{
	return *(const volatile uint32_t *)addr;
}
static inline void __attribute__((always_inline))
rte_write32_relaxed(uint32_t value, volatile void *addr)
{
	*(volatile uint32_t *)addr = value;
}
static inline uint32_t __attribute__((always_inline))
rte_read32(const volatile void *addr)
{
	uint32_t val;
	val = rte_read32_relaxed(addr);
	rte_io_rmb();
	return val;
}
static inline void __attribute__((always_inline))
rte_write32(uint32_t value, volatile void *addr)
{
	rte_io_wmb();
	rte_write32_relaxed(value, addr);
}
#endif
#include <rte_log.h>

#include "mce_osdep.h"
#include "mce_vp_reg.h"

#ifndef BIT
#define BIT(n) (1UL << (n))
#endif

#ifndef BIT_ULL
#define BIT_ULL(n) (1ULL << (n))
#endif

static inline u32 prd32(volatile void *addr)
{
	unsigned int v = rte_read32(((volatile u8 *)addr));

	printf("addr: 0x%04lx_%04lx -> 0x%08x\n", ((unsigned long)addr >> 16),
	       ((unsigned long)addr) & 0xffff, v);
	return v;
}

static inline void pwr32(volatile void *addr, int val)
{
	printf("addr: 0x%04lx_%04lx <- 0x%08x\n", ((unsigned long)addr >> 16),
	       ((unsigned long)addr) & 0xffff, val);
	rte_write32_relaxed((val), ((volatile u8 *)addr));
}
#define mbx_rd32(reg)	   rte_read32((reg))
#define mbx_wr32(reg, val) rte_write32_relaxed((val), (reg))
#if 0
static inline
u32 mce_rd_reg(volatile void *addr, size_t offset)
{
	unsigned int v = rte_read32(((volatile u8 *)addr + offset));
	MCE_PMD_REG_LOG(DEBUG, "offset=0x%08lx val=0x%04x",
			(unsigned long) offset, v);
	return v;
}

static inline void
mce_wr_reg(volatile void *addr, size_t offset, s32 val)
{
	MCE_PMD_REG_LOG(DEBUG, "offset=0x%08lx val=0x%08x",
			(unsigned long)(offset), (val));
	rte_write32_relaxed((val), ((volatile u8 *)(addr) + (offset)));
}
#else
#define mce_rd_reg(addr, off) rte_read32(((volatile u8 *)(addr) + (off)))
#define mce_wr_reg(addr, offset, val) \
	rte_write32_relaxed((val), ((volatile u8 *)(addr) + (offset)));
#endif

#define MCE_E_REG_READ(_hw, _off) mce_rd_reg((u8 *)((_hw)->nic_base), (_off))
#define MCE_E_REG_WRITE(_hw, _off, _val) \
	mce_wr_reg((u8 *)((_hw)->nic_base), (_off), (_val))
#define MCE_REG_ADDR_WRITE(reg, _off, val) \
	mce_wr_reg((u8 *)(reg), (_off), (val))
#define MCE_REG_ADDR_READ(reg, _off) mce_rd_reg((u8 *)(reg), (_off))

#define rd32			     MCE_E_REG_READ
#define wr32			     MCE_E_REG_WRITE

#if 1
#define _rd32(reg)	rte_read32(reg)
#define _wr32(reg, val) rte_write32_relaxed((val), (reg))
#else
#define _rd32(reg)	prd32((reg))
#define _wr32(reg, val) pwr32((reg), (val))
#endif

#define MCE_E_REG_SET_VAL(hw, off, _prefix, val)         \
	do {                                             \
		u32 reg_val = MCE_E_REG_READ(hw, off);   \
		reg_val &= ~_prefix##_##MASK;            \
		reg_val |= ((val) << _prefix##_##SHIFT); \
		MCE_E_REG_WRITE(hw, off, reg_val);       \
	} while (0)

#define MCE_E_REG_SET_BITS(hw, off, mask, val)         \
	do {                                           \
		u32 reg_val = MCE_E_REG_READ(hw, off); \
		if (mask)                              \
			reg_val &= ~mask;              \
		reg_val |= val;                        \
		MCE_E_REG_WRITE(hw, off, reg_val);     \
	} while (0)

#define modify32 MCE_E_REG_SET_BITS

#define MCE_FIELD_GET_VAL(data, _prefix) \
	((data & _prefix##_##MASK) >> _prefix##_##SHIFT)

#define MCE_E_REG_GET_VAL(hw, off, _prefix) \
	MCE_FIELD_GET_VAL(MCE_E_REG_READ(hw, off), _prefix)

#define MCE_FIELD_SET_VAL(data, _prefix, val)         \
	do {                                          \
		data &= ~_prefix##_##MASK;            \
		data |= ((val) << _prefix##_##SHIFT); \
	} while (0)

#define MCE_FIELD_SET_BITS(data, mask, val) \
	do {                                \
		if (mask)                   \
			data &= ~mask;      \
		data |= (val);              \
	} while (0)

#define MCE_MAX_TC_NUM	  (8)
#define MCE_MAX_PG	  (8)
#define MCE_MAX_USER_PRIO (8)
struct mce_adapter;

/**
 * @brief Traffic Class queue options
 *
 * Describes queue allocation and mapping for a traffic class (TC).
 */
struct mce_tc_qopt {
	u16 tqp_offset; /* TQP offset from base TQP */
	u16 tqp_count; /* Total TQPs */
	u8 tc; /* TC index */
	u8 prio_tc_map; /* TC prio */
	bool enable; /* If this TC is enable or not */
};

/**
 * @brief Traffic class options
 *
 * Per-TC configuration such as priority group and bandwidth limit.
 */
struct mce_tc_opt {
	u8 pg_id; /* tc belone to pg */
	u8 tc_id; /* traffic class id */
	u32 bw_limit; /* bandwth limit */
	u8 pri_tc_map; /* user priority mapping on the TC */
};

/**
 * @brief Priority group options
 *
 * Groups multiple TCs together and configures group bandwidth and members.
 */
struct mce_pg_opt {
	u8 pg_id; /* Priority Group ID*/
	struct mce_tc_opt tc_opt[MCE_MAX_TC_NUM];
	u8 tc_bit_map; /* the member tc of group */
	u32 bw_limit; /* bandwth limit */
	bool pg_en;
};

/**
 * @brief DCB (Data Center Bridging) options
 *
 * Encapsulates number of traffic classes, priority mapping and PFC/PG flags.
 */
struct mce_dcb_opt {
	u8 num_tc; /* traffic class num */
	u8 num_pg; /* poriority group */
	u8 hw_tc_map[MCE_MAX_USER_PRIO]; /* TC priority <=> TCs */
	bool pfc_en;
	bool pg_en;
};

/**
 * @brief DCB scheduling modes
 */
enum mce_dcb_sched_mode {
	MCE_DCB_TX_SCHD_NONE,
	MCE_DCB_TX_SCHD_DWRR,
	MCE_DCB_TC_SCHD_SP,
	MCE_DCB_TC_SCHD_ETS,
};

/**
 * @brief Common hardware capabilities exposed to software
 */
struct mcevf_hw_common_caps {
	/* Tx/Rx queues */
	u32 num_rxq; /* Number/Total Rx queues */
	u32 num_txq; /* Number/Total Tx queues */

	/* RSS related capabilities */
	u32 rss_table_size; /* 512 for PFs*/
	u32 rss_key_size;

	/* IRQs */
	u32 num_mbox_irqs;
	u32 num_rdma_irqs;
};

/**
 * @brief Function-specific hardware capabilities
 */
struct mcevf_hw_func_caps {
	struct mcevf_hw_common_caps common_cap;
	u32 num_allocd_vfs; /* Number of allocated VFs */
	u32 guar_num_vsi;
	u32 fd_fltr_guar;
};

struct mce_hw;
struct mce_vport;

/**
 * @brief Mailbox statistics counters
 */
struct mce_mbx_stats {
	u32 tx_event_cnt;
	u32 tx_event_err_cnt;

	u32 tx_req_cnt;
	u32 tx_shm_lock_timeout;

	u32 rx_resp_cnt;
	u32 rx_req_shm_lock_timeout;
	u32 rx_resp_shm_lock_timeout;
};

/**
 * @brief Simple mailbox sync counters
 *
 * Contains request/ack counters used for mailbox synchronization.
 */
struct mce_mbx_sync {
	u16 req;
	u16 ack;
};
/**
 * @brief Mailbox VF identifier types
 */
enum mce_mbx_vfid {
	MCE_VFID_VF,
	MCE_VFID_PF = 127,
	MCE_VFID_FW = 128,
};

/**
 * @brief Mailbox destination types
 */
enum MBX_DST {
	MBX_PF2FW,
	MBX_PF2VF,
	MBX_VF2PF,
};

/**
 * @brief Mailbox information and shared memory descriptors
 *
 * Holds mailbox related buffers, locks, and state used for PF/VF/FW
 * communication.
 */
struct mce_mbx_info {
	struct mce_mbx_stats stats;
	struct mce_hw *hw;

	char name[64];

	struct mce_vf_info *vfinfo;

	rte_spinlock_t req_lock;
	rte_spinlock_t thiz_req_shm_lock;
	rte_spinlock_t peer_shm_lock;

	bool irq_enabled;
	bool setup_done;
	int nr_vf;
	int nr_pf;
	enum MBX_DST dst;

	int thiz_req_shm_size; /* PF2FW shm size */
	int peer_req_shm_size; /* FW2PF shm size */

	u8 __iomem *thiz2peer_shm; /* peer = fw or vf */
	u8 __iomem *thiz2peer_shm_lock;
	u8 __iomem *thiz2peer_ctrl;
	u32 thiz2peer_shm_lock_msk;

	u8 __iomem *peer2thiz_shm;
	u8 __iomem *peer2thiz_shm_lock;
	u8 __iomem *peer2thiz_ctrl;
	u32 peer2thiz_shm_lock_msk;

	u8 __iomem *vf2pf_irq_stat;

	u8 __iomem *mbx_vec_base;
};

/**
 * @brief Bitmap allocation entry
 */
struct mce_bitmap_entry {
	char name[128];
	void *bitmap_mem;
	struct rte_bitmap *bitmap;
	u16 max_bit;
	u32 *mem_store;
};

/**
 * @brief MAC operations interface
 *
 * Function pointers implemented by MAC-specific code to perform
 * initialization, reset and address/filter operations.
 */
struct mce_mac_ops {
	void (*init_offset)(struct mce_hw *hw);
	/* Rest Hardware Status */
	s32 (*reset_hw)(struct mce_hw *hw);
	s32 (*init_hw)(struct mce_hw *hw);
	/* Rest nic Status */
	s32 (*reset_nic)(struct mce_hw *hw);
	/* Get Reg */
	s32 (*get_reg)(struct mce_hw *hw, u32 addr, u32 *val);
	/* MAC Address */
	s32 (*get_mac_addr)(struct mce_hw *hw, u8 *addr);
	s32 (*set_default_mac)(struct mce_hw *vport, u8 *addr);
	/* MTU */
	s32 (*get_mtu)(struct mce_vport *vport, u16 *mtu);
	s32 (*set_mtu)(struct mce_vport *vport, u16 mtu);
	/* Setup Receive Unicast Address Filter Table */
	s32 (*set_rafb)(struct mce_hw *hw, u8 *addr);
	/* Clear Unicast Mac Address Filter */
	s32 (*clear_rafb)(struct mce_vport *vport, u8 vm_pool, u8 index);
	/* Update Unicast Address Table */
	s32 (*update_uta)(struct mce_vport *vport, u8 *addr, u8 add);
	s32 (*enable_uta)(struct mce_vport *vport, bool en);
	/* Enable Multicast Filter */
	s32 (*enable_mta)(struct mce_hw *hw, bool en);
	s32 (*clear_mc_filter)(struct mce_hw *hw);
	/* Update Multicast Address Table */
	s32 (*update_mta)(struct mce_hw *hw, u8 *addr, u16 loc);
	/* Enable Vlan Filter */
	s32 (*en_vlan_f)(struct mce_hw *hw, bool en);
	/* Vlan Filter Add Rule */
	s32 (*add_vlan_f)(struct mce_hw *hw, u16 vlan, bool add);
	/* Vlan/QinQ strip Rule */
	s32 (*en_strip_f)(struct mce_hw *hw, u16 strip_layers, u16 loc,
			  bool en);
	s32 (*update_mc_filte)(struct mce_hw *hw, u16 index, u8 *mac);
	/* Mac Enable Receive */
	s32 (*mac_rx_start)(struct mce_hw *hw, u8 p_id, bool start);

	/* Mac Enable Transmit */
	s32 (*mac_tx_start)(struct mce_hw *hw, u8 p_id, bool start);
	/* Get Link Status */
	/* Set Link Status */
	/* Enable Jumbo Frame Support */
	s32 (*rx_jumbo_en)(struct mce_hw *hw, bool en);
};

struct mce_mac_info {
	uint8_t assign_addr[RTE_ETHER_ADDR_LEN];
	uint8_t set_addr[RTE_ETHER_ADDR_LEN];
	const struct mce_mac_ops *ops;
};

struct mce_ptp_ops {
  /* ptp ops */
        void (*ptp_get_systime)(struct mce_hw *, u64 *);
        int (*ptp_init_systime)(struct mce_hw *, u32, u32);
        int (*ptp_adjust_systime)(struct mce_hw *, u32, u32, int);
        int (*ptp_adjfine)(struct mce_hw *, long);
        int (*ptp_tx_stamp)(struct mce_hw *, u64 *sec, u64 *nsec);
};

struct mce_ptp_info {
	u64 ptp_default_int;
	u64 clk_ptp_rate;
	bool ptp_enable;

	const struct mce_ptp_ops *ops;
};

struct mce_fw_info {
	u32 fw_version;
};

enum mce_mpf_modes {
	MCE_MPF_MODE_NONE = 0,
	MCE_MPF_MODE_ALLMULTI, /* Multitle Promisc */
	MCE_MPF_MODE_PROMISC, /* Promisc */
};

union __rte_packed_begin dm_stat {
	struct {
		u32 linkup : 1;
		u32 sfp_mod_abs : 1;
		u32 s_speed : 3;
#define UNKOWN_SPEED 0
#define Z_SPEED_10M  1
#define Z_SPEED_100M 2
#define Z_SPEED_1G   3
#define Z_SPEED_10G  4
#define Z_SPEED_25G  5
#define Z_SPEED_40G  6
#define Z_SPEED_100G 7
		u32 duplex : 1;
		u32 is_sgmii : 1;
		u32 is_backplane : 1;
		u32 active_fec : 2;
#define ST_FEC_OFF  0
#define ST_FEC_BASER 1
#define ST_FEC_RS    2
#define ST_FEC_AUTO  3
		u32 autoneg : 1;
		u32 link_traing : 1;
		u32 lldp_tx_en : 1;
		u32 sfp_fault : 1;
		u32 sfp_tx_dis : 1;
		u32 sfp_los : 1;
		u32 force_link_cap : 1;
#define FOCE_LINK_DOWN_ON_CLOSE_CAP 0
#define FOCE_LINK_UP_ON_CLOSE_CAP   1
		u32 force_link_status : 1;
#define NO_FORCE_LINK_SET 0
#define FOCE_LINK_SETTED  1
		u32 configed_fec:3;
		u32 pxe_ablity : 1;
		u32 pxe_enabled	: 1;
		u32 pxe_fw_availble : 1;
		u32 rev2: 4;
		u32 magic : 4;
#define DM_STAT0_IMAGE 0xA
	} __rte_packed_end;
	u32 v;
} __rte_packed_end;

union __rte_packed_begin nic_stat {
	struct {
		u32 vf_isolate_disabled : 1;
		u32 pf0_vf_max_queue_cnt_3bit : 3;
		u32 pf1_vf_isolate : 1;
		u32 pf1_vf_max_queue_cnt_3bit : 3;
		u32 temp : 8;
		u32 phy_id_idx : 4;
		u32 sgmii_addr : 4;
		u32 phy_type : 5;
		u32 magic : 3;
#define NIC_STAT0_IMAGE 0b101
	};
	u32 v;
} __rte_packed_end;

struct phy_speed_ablity {
	/* sfp_mod_abs == 1 then
	 * speed_1g/10/25g/40g/100g is sfp module supported speed
	 * or speed_1g/10/25g/40g/100g is card supported speed
	 */
	u8 speed_1g : 1;
	u8 speed_10g : 1;
	u8 speed_25g : 1;
	u8 speed_40g : 1;
	u8 speed_100g : 1;
	u8 force_speed_by_user : 3; /* 0: no force 1:1G 2:10G 3:25G 4:40G 5:100G */

	u8 acc : 1;
	u8 dac : 1;
	u8 unsupported_sfp : 1;
	u8 sfp_rj45_or_t : 1; /*10G-T 1G-T 100G-T */
	u8 is_sgmii : 1;
	u8 is_backplane : 1;
	u8 sfp_c0_c1_valid : 1;
	u8 sfp_mod_abs : 1;

	/* 2:8bit */
	union {
		struct { /* 40G/100G */
			u8 c0 : 4;
#define QSFP_C_CR4   1
#define QSFP_C_SR4   2
#define QSFP_C_LR4   3
#define QSFP_C_PSM4  4
#define QSFP_C_ER4   5
#define QSFP_C_CWDM4 6
#define QSFP_C_CLR4  7
#define QSFP_C_SWDM4 8

			u8 c0_10g : 2;
#define QSFP_C_10G_SR  1
#define QSFP_C_10G_LR  2
#define QSFP_C_10G_LRM 3

			u8 c0_1g : 2;
#define QSFP_C_1G_SX 1
#define QSFP_C_1G_LX 2
#define QSFP_C_1G_CX 3
		};

		struct { /* 1G/10G/25G */
			u8 c1 : 4;
#define SFP_C_SR  1
#define SFP_C_LR  2
#define SFP_C_LRM 3
#define SFP_C_CR  4
#define SFP_C_ER  5
#define SFP_C_KR  6

			u8 c1_1g : 2;
#define SFP_C_1G_SX 1
#define SFP_C_1G_LX 2
#define SFP_C_1G_CX 3
		};
		struct { /* sgmii */
			u8 phy_addr : 2;
			u8 phy_id_idx : 4;
			u8 a;
		};
	};
} __rte_packed_end;

struct __rte_packed_begin ext_stat {
	union {
		struct {
			u32 mac_addr_hi;
			u32 mac_addr_lo; /* lo16 */
		};
		u8 mac_addr[6];
	};
	u32 fw_version;
	u32 pxe_version;
	union {
		struct {
			u32 phy_speed_ablity : 24; /* struct phy_speed_ablity */
			u32 rdma_disable : 1;
			u32 have_rdma : 1;
			u32 wol_supported : 1;
			u32 wol_enabled : 1;
			u32 rev : 1;
			u32 magic : 3;
#define ext_ABLITY_IMAGE 0b101
		};
		u32 v;
	} ext;
} __rte_packed_end;

struct fw_stat {
	u32 fw_linkup : 1;
	u32 fw_nic_reset_done : 1;
	union dm_stat stat0;
	union nic_stat stat1;
	struct ext_stat stat2;
};

struct pf_stat {
	u32 pf_link_status : 1;
	u32 nr_pf : 1;
	int pf_link_speed;
};

struct mce_hw {
	struct mce_adapter *back;
	u8 __iomem *nic_base;
	u8 *npu_base;
	u32 vp_reg_base[MCE_VP_REG_MAX];
	/* === dma == */
	u16 min_dma_size;
	u64 max_tm_rate;
	u16 tm_sample_unit;
	u16 clock_mhz;

	bool fw_sfp_pluginout_notify_en;
	bool fw_link_change_notify_en;

	u8 saved_force_speed;

	struct rte_pci_device *pci_dev;
	struct fw_stat fw_stat; /* for pf */
	struct pf_stat pf_stat; /* for vf */

	rte_spinlock_t link_lock;
	rte_spinlock_t ptp_lock;
	bool ifup_status;
	bool reset_done;
	bool is_vf_isolated_enabled;
	bool is_sgmii;
	bool pf_rxfcs_en;
	bool trust_on;
	bool is_ocp_card;

	int vf_min_ring_cnt;
	int port_id;
	u32 total_irq_req_num;

	int link_duplex;
	int link_speed;
	int link_autoneg;
	int link_status;

	u8 pfc_en;
	u8 num_tc; /* total number of enabled TCs */
	u8 tc_prior_map[MCE_MAX_USER_PRIO]; /* TC <=> TC priority*/
	u16 nb_txq_per_tc;
	u16 nb_rxq_per_tc;
	u16 max_vfs;
	u16 nb_qpair_per_vf;
	u16 nb_qpair;
	u16 nb_mac_per_vf;
	u16 nb_mulcast_per_vf;
	u16 nb_vid_per_vf;
	u16 nb_irq_per_vf;
	u16 max_reta_num;
	u16 max_pkt_len;
	enum mce_dcb_sched_mode tc_sched_mode[MCE_MAX_TC_NUM];
	struct mce_tc_qopt tx_tc_q[MCE_MAX_TC_NUM];
	struct mce_tc_qopt rx_tc_q[MCE_MAX_TC_NUM];
	struct mce_pg_opt pg_opt[MCE_MAX_PG];
	struct mce_dcb_opt dcb_opt;

	struct mce_switch_handle *switch_handle;
	u16 device_id;
	u16 vendor_id;
	u16 function;
	uint16_t connect_type;
	struct mcevf_hw_func_caps func_caps; /* function capabilities */
	struct mce_mac_info mac;
	struct mce_ptp_info ptp;

	union {
		struct mce_mbx_info vf2pf_mbx;
		struct {
			struct mce_mbx_info pf2fw_mbx;
			struct mce_mbx_info pf2vf_mbx[128];
		};
	};
	u8 perm_mac_addr[6];

	u32 fw_version;
	u8 pcie_speed;
	u8 pcie_width;
	bool vf_bar_isolate_on;
	u32 vf_max_ring;
	u32 max_speed;

	int vfnum;
	int sriov;
	bool is_vf;
	int nr_pf;

	u8 __iomem *dm_stat;
	u8 __iomem *nic_stat;
	u8 __iomem *ext_stat;
	char device_name[128];
};

#define mbx_info_reg_bar_off(mbx, reg) \
	((char *)(reg) - (char *)((mbx)->hw->nic_base))

struct mce_hw_stats {
	uint64_t rx_bad_pkts;
	uint64_t rx_all_pkts;
	uint64_t rx_invalid_len;
	uint64_t rx_invalid_tun_len;
	uint64_t rx_vlan_hdr_num_err;
	uint64_t rx_sctp_cksum_err;
	uint64_t rx_l4_cksum_err;
	uint64_t rx_ipv4_cksum_err;
	uint64_t rx_ipv4_len_err;
	uint64_t rx_ipv4_hdr_err;
	uint64_t rx_802_3_pkts;
	uint64_t rx_ptp_pkts;
	uint64_t rx_rdma_pkts;
	uint64_t rx_gtp_u_pkts;
	uint64_t rx_gtp_c_pkts;
	uint64_t rx_geneve_pkts;
	uint64_t rx_vxlan_pkts;
	uint64_t rx_gre_pkts;
	uint64_t rx_esp_pkts;
	uint64_t rx_sctp_pkts;
	uint64_t rx_tcp_sync_pkts;
	uint64_t rx_tcp_pkts;
	uint64_t rx_udp_pkts;
	uint64_t rx_icmpv6_pkts;
	uint64_t rx_icmpv4_pkts;
	uint64_t rx_frag_pkts;
	uint64_t rx_arp_pkts;
	uint64_t rx_ipv6_ext_pkts;
	uint64_t rx_ipv6_pkts;
	uint64_t rx_ipv4_pkts;
	uint64_t rx_3_layer_vlan_pkts;
	uint64_t rx_2_layer_vlan_pkts;
	uint64_t rx_1_layer_vlan_pkts;

	uint64_t rx_tun_in_sctp_pkts;
	uint64_t rx_tun_in_tcp_sync_pkts;
	uint64_t rx_tun_in_tcp_pkts;
	uint64_t rx_tun_in_udp_pkts;
	uint64_t rx_tun_in_icmp6_pkts;
	uint64_t rx_tun_in_icmp4_pkts;
	uint64_t rx_tun_in_frag_pkts;
	uint64_t rx_tun_in_arp_pkts;
	uint64_t rx_tun_in_ipv6_ext_pkts;
	uint64_t rx_tun_in_ipv6_pkts;
	uint64_t rx_tun_in_ipv4_pkts;
	uint64_t rx_tun_in_3lay_vlan_pkts;
	uint64_t rx_tun_in_2lay_vlan_pkts;
	uint64_t rx_tun_in_1lay_vlan_pkts;

	uint64_t rx_strip_vlan_num;
	uint64_t rx_strip_1vlan_num;
	uint64_t rx_strip_2vlan_num;
	uint64_t rx_strip_3vlan_num;

	uint64_t rx_l2filter_drop_pkts;
	uint64_t rx_reta_f_drop_pkts;
	uint64_t attr_rx_egress_pkt_drop_num;

	uint64_t rx_dmac_f_drop;
	uint64_t rx_vlan_f_drop;

	uint64_t rx_mtu_drop;
	uint64_t rx_fd_drop;
	uint64_t rx_tuple_drop;
	uint64_t rx_policy_drop;

	uint64_t rx_trans_in;
	uint64_t rx_trans_out;
	uint64_t rx_other_err;
	uint64_t rx_trans_drop;
	uint64_t rx_crc_err;
	uint64_t rx_nosym_err;
	uint64_t rx_usize_err;
	uint64_t rx_osize_err;
	uint64_t rx_len_err;
	uint64_t rx_wpi_err;
	uint64_t rx_magic_err;
	uint64_t rx_mdmac_err;
	uint64_t rx_slen_err;
	uint64_t rx_glen_err;
	uint64_t rx_frag_num;
	uint64_t rx_len_exp_num;
	uint64_t rx_pkt_sop_num;
	uint64_t rx_pkt_eop_num;
	uint64_t rx_sop_num;
	uint64_t rx_eop_num;
	uint64_t rx_wpi_state;
	uint64_t rx_pfc_pri0_drop;
	uint64_t rx_pfc_pri1_drop;
	uint64_t rx_pfc_pri2_drop;
	uint64_t rx_pfc_pri3_drop;
	uint64_t rx_pfc_pri4_drop;
	uint64_t rx_pfc_pri5_drop;
	uint64_t rx_pfc_pri7_drop;
	uint64_t rx_pfc_pri6_drop;

	uint64_t rx_miss_drop;

	uint64_t tx_anti_dmac_drop;
	uint64_t tx_anti_smac_drop;
	uint64_t tx_anti_vlan_drop;

	uint64_t tx_tso_pkts;

	uint64_t tx_prio0_send_pkts;
	uint64_t tx_prio1_send_pkts;
	uint64_t tx_prio2_send_pkts;
	uint64_t tx_prio3_send_pkts;
	uint64_t tx_prio4_send_pkts;
	uint64_t tx_prio5_send_pkts;
	uint64_t tx_prio6_send_pkts;
	uint64_t tx_prio7_send_pkts;

	uint64_t tx_trans_send_sop;
	uint64_t tx_trans_send_eop;
	uint64_t tx_trans_recv_sop;
	uint64_t tx_trans_recv_eop;
	uint64_t tx_non_sop_len_err;
	uint64_t tx_max_len_lock;
	uint64_t tx_max_len_lock_cnt;
	uint64_t tx_length_is_zero;
	uint64_t tx_pause_xon2xof;
	uint64_t tx_pfc_pri0_xon2xoff;
	uint64_t tx_pfc_pri1_xon2xoff;
	uint64_t tx_pfc_pri2_xon2xoff;
	uint64_t tx_pfc_pri3_xon2xoff;
	uint64_t tx_pfc_pri4_xon2xoff;
	uint64_t tx_pfc_pri5_xon2xoff;
	uint64_t tx_pfc_pri6_xon2xoff;
	uint64_t tx_pfc_pri7_xon2xoff;
};

struct mce_hw_basic_stats {
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t rx_unicast_pkts;
	uint64_t rx_multicast_pkts;
	uint64_t rx_broadcast_pkts;
	uint64_t rx_miss_drop;

	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t tx_unicast_pkts;
	uint64_t tx_multicast_pkts;
	uint64_t tx_broadcast_pkts;
};

struct mce_hw_mac_stats {
	uint64_t rx_good_bad_pkts;
	uint64_t rx_good_bad_bytes;
	uint64_t rx_good_pkts;
	uint64_t rx_good_bytes;
	uint64_t rx_bad_pkts;

	uint64_t rx_fcs_err; /* rx fcs err pkts */
	uint64_t rx_runt_err; /* Frame Less-than-64-byte with a CRC error*/
	uint64_t rx_jabber_err; /* Jumbo Frame Crc Error */
	uint64_t rx_undersize_err; /* Frame Less Than 64 bytes Error */
	uint64_t rx_oversize_err; /* Bigger Than Max Support Length Frame */
	uint64_t rx_len_err; /* Bigger Or Less Than Len Support */
	uint64_t rx_len_invaild; /* Frame Len Isn't equal real Len */
	uint64_t rx_discard_pkts;

	uint64_t rx_64octes_pkts;
	uint64_t rx_65to127_octes_pkts;
	uint64_t rx_128to255_octes_pkts;
	uint64_t rx_256to511_octes_pkts;
	uint64_t rx_512to1023_octes_pkts;
	uint64_t rx_1024to1518_octes_pkts;
	uint64_t rx_1519tomax_octes_pkts;
	uint64_t rx_unicast_pkts;
	uint64_t rx_multicase_pkts;
	uint64_t rx_broadcast_pkts;
	uint64_t rx_vlan_pkts; /* Rx Vlan Frame Num */
	uint64_t rx_pause_pkts; /* Rx Pause Frame Num */
	uint64_t rx_pfc_pri0_pkts;
	uint64_t rx_pfc_pri1_pkts;
	uint64_t rx_pfc_pri2_pkts;
	uint64_t rx_pfc_pri3_pkts;
	uint64_t rx_pfc_pri4_pkts;
	uint64_t rx_pfc_pri5_pkts;
	uint64_t rx_pfc_pri6_pkts;
	uint64_t rx_pfc_pri7_pkts;

	uint64_t tx_good_bad_pkts;
	uint64_t tx_good_bad_bytes;
	uint64_t tx_good_pkts;
	uint64_t tx_good_bytes;
	uint64_t tx_bad_pkts;

	uint64_t tx_oversize_err; /* Bigger Than Max Support Length Frame */
	uint64_t tx_jabber_err; /* Jumbo Frame Crc Error */

	uint64_t tx_64octes_pkts;
	uint64_t tx_65to127_octes_pkts;
	uint64_t tx_128to255_octes_pkts;
	uint64_t tx_256to511_octes_pkts;
	uint64_t tx_512to1023_octes_pkts;
	uint64_t tx_1024to1518_octes_pkts;
	uint64_t tx_1519tomax_octes_pkts;
	uint64_t tx_unicast_pkts;
	uint64_t tx_multicase_pkts;
	uint64_t tx_broadcast_pkts;
	uint64_t tx_vlan_pkts;
	uint64_t tx_pause_pkts;
	uint64_t tx_pfc_pri0_pkts;
	uint64_t tx_pfc_pri1_pkts;
	uint64_t tx_pfc_pri2_pkts;
	uint64_t tx_pfc_pri3_pkts;
	uint64_t tx_pfc_pri4_pkts;
	uint64_t tx_pfc_pri5_pkts;
	uint64_t tx_pfc_pri6_pkts;
	uint64_t tx_pfc_pri7_pkts;
};

#endif /* _MCE_H_ */
