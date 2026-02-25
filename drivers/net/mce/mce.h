/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef _MCE_H_
#define _MCE_H_

#include <limits.h> /* PATH_MAX */
#include <stdio.h>

#include <rte_version.h>

#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#include <rte_pci.h>
#else
#if RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
#include <rte_ethdev_pci.h>
#else
#include <ethdev_pci.h>
#endif
#endif
#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
#include <rte_tm.h>
#endif

#include "mce_compat.h"
#include "mce_vf_representor.h"
#include "mce_fdir_flow.h"

#include "base/mce_hw.h"
#include "base/mce_common.h"
#include "base/mce_dma_regs.h"
#include "base/mce_vp_reg.h"

#define PCI_VENDOR_ID_MUCSE	      (0x8848)
#define MCE_DEV_ID_N20		      (0x9000)
#define MCE_DEV_ID_N20_VF	      (0x8503)

#define MCE_PF_INFO_BAR		      (0)
#define MCE_NIC_CTRL_BAR              (4)
#define MCE_BAR_DIS_SIZE              (1024)
#define MCE_MCAST_ADDR_PER_VF	      (16)
#define MCE_MAX_VLAN_PER_VF           (16)

#define MCE_BUFF_SIZE_MIN	      (1024)
#define MCE_MAX_FRAME_SIZE	      (16383 - 64)
#define MCE_DEFAULT_RX_FREE_THRESH    (32)
#define MCE_DEFAULT_TX_FREE_THRESH    (32)
#define MCE_DEFAULT_TX_RS_THRESH      (32)
#define MCE_MAX_HASH_KEY_SIZE	      (13)
#define MCE_MAX_RX_BD		      (4096)
#define MCE_MAX_TX_BD		      (4096)
#define MCE_MAX_RX_QUEUE	      (512)
#define MCE_MAX_TX_QUEUE	      (512)
#define MCE_UNICAST_HASH_TABLE_SIZE   (128)
#define MCE_MAX_MAC_ADDRESS	      (512)

#define MCE_M_MAX_JUMBO               (16383 - 64)
#define MCE_MAX_NO_TSO_SEG_LEN        (64960)
#define MCE_MAX_SEG_LEN               (16 * 1024)
#define MCE_MAX_TSO_PKT               (64 * 1024)
#define MCE_MULTICAST_HASH_TABLE_SIZE (128)
#define MCE_MAX_RETA_LOC_SIZE (512)
#define MCE_MAX_NTUPLE_NUM    (512)
#define MCE_MAX_ETYPE_NUM     (16)
#define MCE_MAX_LEGEND_RULE   (384)
#define MCE_MAX_ESWITCH_RULE  (128)

#define MCE_MAC_HASH_SIZE      (MCE_MULTICAST_HASH_TABLE_SIZE * 32)

#define MCE_VLAN_TAG_SIZE      (4)
#define MCE_ETH_OVERHEAD       (RTE_ETHER_HDR_LEN + MCE_VLAN_TAG_SIZE * 2)

#define MCE_VF_MULCAST_MAX_NUM 16

#define MCE_RX_CHECKSUM_SUPPORT                                         \
	(RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM | \
	 RTE_ETH_RX_OFFLOAD_TCP_CKSUM | RTE_ETH_RX_OFFLOAD_SCTP_CKSUM | \
	 RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |                          \
	 RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM)
#define MCE_COMMIT_QUEUE

struct mce_vlan_entry {
	uint16_t vid;
	uint16_t hash_entry;
	uint32_t hash_bit;
};

/* VLAN filter list structure */
struct mce_vlan_filter {
	TAILQ_ENTRY(mce_vlan_filter) next;
	struct mce_vlan_entry vlan;
};

TAILQ_HEAD(mce_vlan_filter_list, mce_vlan_filter);

struct mce_mac_entry {
	struct rte_ether_addr mac_addr;
	uint16_t loc;
};

struct mce_mac_filter {
	TAILQ_ENTRY(mce_mac_filter) next;
	struct mce_mac_entry mac;
};

TAILQ_HEAD(mce_mac_filter_list, mce_mac_filter);

TAILQ_HEAD(mce_sw_macvlan_filter_list, mce_sw_macvlan_filter);
struct mce_select_func_attr {
	bool simple_allowed;
	bool cpu_support;
	bool vec_options;
	bool simd_en;
	bool scatter;
};
struct mce_port_attr {
	uint16_t hash_filter_type;
	uint16_t max_mac_addrs; /* Max Support Mac Address */
	uint16_t max_mcast_addrs; /* max support mcast address */
	uint16_t uc_hash_tb_size; /* Unicast Hash Table Size */
	uint16_t max_uc_mac_hash; /* Max Num of hash MAC addr for UC */
	uint16_t mc_hash_tb_size; /* Multicast Hash Table Size */
	uint16_t max_mc_mac_hash; /* Max Num Of Hash Mac addr For MC */
	uint16_t hash_table_shift;
	uint16_t max_reta_num;
	uint16_t max_vlan_hash; /* Max Num Of Hash For Vlan ID*/
	uint16_t rte_pid; /* Dpdk Manage Port Sequence Id */
	uint16_t max_rx_queues; /* Belong To This Port Rxq Resource */
	uint16_t max_tx_queues; /* Belong To This Port Rxq Resource */
	uint16_t max_ntuple_num;
	uint16_t qpair_offset;
	uint16_t qpair_base;
	union {
		uint8_t nr_lane; /* phy lane of This PF:0~3 */
		uint8_t nr_port; /* phy lane of This PF:0~3 */
	};
	uint16_t vport_id;
	bool link_ready;
	bool pre_link;
	bool strip_crc;
	bool trust_on;
	uint32_t speed;
	uint16_t max_pkt_len;
	bool is_vf;

	bool inner_rss_en;
	bool smid_force_en;
	struct mce_select_func_attr rx;
	struct mce_select_func_attr tx;
};

struct rte_flow;
struct mce_flow_engine_module;
TAILQ_HEAD(mce_flow_list, rte_flow);
TAILQ_HEAD(mce_flow_engine_list, mce_flow_engine_module);

#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
struct mce_tm_shaper_profile {
	TAILQ_ENTRY(mce_tm_shaper_profile) node;
	uint32_t shaper_profile_id;
	uint32_t reference_count;
	struct rte_tm_shaper_params *profile;
};

TAILQ_HEAD(mce_tm_node_list, mce_tm_node);

struct mce_tm_node {
	TAILQ_ENTRY(mce_tm_node) node;
	uint32_t id;
	uint32_t priority;
	uint32_t level;
	uint32_t weight;
	uint32_t reference_count;
	struct mce_tm_node *parent;
	struct mce_tm_shaper_profile *shaper_profile;
	struct rte_tm_node_params params;

	bool has_child;
	struct mce_tm_node_list child;
};

TAILQ_HEAD(mce_shaper_profile_list, mce_tm_shaper_profile);

struct mce_tm_shaper_conf {
	uint16_t profile_user_set;
	uint16_t profile_max;
	uint16_t profile_load_cnt;
	uint16_t sample_unit;

	struct mce_tm_node *root;
	bool committed;
	struct mce_tm_node_list queue_list;
	struct mce_tm_node_list vport_list;
	struct mce_tm_node_list qgroup_list;
	struct mce_tm_node_list tc_list;
	struct mce_shaper_profile_list shaper_profile_list;

	uint32_t nb_qgroup_node;
	uint32_t nb_queue_node;
};
#endif /* RTE_VERSION >= 17.08 */

#pragma pack(push)
#pragma pack(1)
struct mce_fdir_prog_cmd {
	u8 data[60];
	u16 loc;
	u8 resv;
	u8 cmd_type;
};
#pragma pack(pop)

struct mce_fdir_fifo_commit {
	struct mce_tx_queue *txq;
	void *prg_pkt;
	uint64_t dma_addr;
	const struct rte_memzone *mz;
	struct mce_fdir_prog_cmd cmd_buf[4];
	u16 cmd_block;
};

enum mce_evb_mode {
	MCE_VEB_MODE,
	MCE_VEPA_MODE,
};

struct mce_veb {
	/* struct mce_switch_handle *switch_handle;

	 struct mce_mulcast_list bd_list;
	 struct mce_uc_list uc_list;
	 struct mce_vlan_list vlan_list;
	*/
	int dummy;
};

struct mce_veb_res {
	int dummy;
};

struct mce_vport {
	struct rte_eth_dev *dev;
	struct rte_eth_dev_data *data;
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];
	struct mce_hw_mac_stats hw_mac_stats;
	struct mce_hw_basic_stats basic_stats;
	struct mce_hw_stats hw_stats;
	struct mce_hw_stats hw_stats_old;
	struct mce_port_attr attr;
	uint16_t min_dma_size;
	struct mce_hw *hw;

	/* l2 filter */
	uint32_t mc_hash_table[MCE_MULTICAST_HASH_TABLE_SIZE];
	struct mce_vlan_filter_list vlan_list; /* vlan filter list */
	struct mce_mac_filter_list mac_list;
	struct mce_flow_engine_list flow_engine_list;
	struct mce_flow_list flow_list;
	struct mce_sw_macvlan_filter_list macvlan_list;
	struct mce_veb *veb_handle;
#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
	struct mce_tm_shaper_conf tm_conf;
#endif
	uint8_t num_tc;

	uint16_t reta_q_size;
	uint32_t *lut;
	bool rss_en;
	uint64_t rss_hf;
	bool is_vf;
	bool combined_tx;
};

#define MCE_MAX_VF_NUM 128

struct mce_vf_info {
	struct mce_pf *pf;
	u8 pf_set_mac : 1;
	u8 trusted : 1;
	u8 spoofchk : 1;
	u8 link_forced : 1;
	u8 rscv : 4;
	struct mce_mac_filter_list mac_list;
	struct rte_ether_addr mac_addr; /* Default MAC address */
	struct rte_ether_addr set_addr; /* user MAC address */
	uint16_t max_qps;
	uint16_t max_ntuple;
	uint16_t cur_ntuple_cnt;
	uint16_t vf_idx;
	bool init_done;
	bool clear_to_send;
};
enum mce_eswitch_mode {
	MCE_ESWITCH_LEGACY,
	MCE_ESWITCH_SWITCHDEV,
};

#define MAX_UDP_PORTS_PER_TUNNEL 8

struct mce_tunnel_udp_port {
	uint16_t udp_ports[MAX_UDP_PORTS_PER_TUNNEL];
	bool port_used[MAX_UDP_PORTS_PER_TUNNEL];
	uint8_t port_count;
};
struct mce_pf {
	struct mce_vport *pf_vport;
	struct rte_eth_dev *dev;
	struct rte_eth_dev_data *dev_data; /* Pointer to the device data */

	struct mce_fdir_fifo_commit commit;
	enum mce_fdir_mode_type fdir_mode;
	enum mce_eswitch_mode eswitch_mode;
	bool fdir_flush_en;
	bool is_switchdev;
	char link_down_on_close;
	char fw_path[PATH_MAX];
	int axi_mhz;

	struct mce_tunnel_udp_port tunnel_port[MCE_TUNNEL_TYPE_MAX];
	struct mce_vf_representor *vf_reprs[MCE_MAX_VF_NUM];
	struct mce_proxy_route_adapter *proxy_route;
	uint8_t nr_repr_ports;
	/* Sriov vf info */
	struct mce_vf_info *vfinfos;
	uint16_t switch_domain_id;
	uint16_t vf_nb_qp_max;
	uint16_t en_max_vf;
	bool force_smid_en;
	uint16_t max_vfs;
};

struct mce_vf {
	struct mce_vport *vf_vport;
	struct rte_eth_dev *dev;
	struct rte_eth_dev_data *dev_data; /* Pointer to the device data */
	struct mce_vlan_filter_list vlan_list;
	struct mce_mac_filter_list mac_list;
	struct mce_flow_engine_list flow_engine_list;
	struct mce_flow_list flow_list;
};

struct mce_adapter {
	union {
		struct mce_vf vf;
		struct mce_pf pf;
	};
	struct mce_hw hw;
	RTE_ATOMIC(unsigned int) nb_secondary;
};
/**
 * @brief Check whether the given device is supported by the MCE driver.
 *
 * @param dev Pointer to the rte_eth_dev to check.
 * @param drv Pointer to the rte_pci_driver probing the device.
 *
 * @return true if supported, false otherwise.
 */
bool mce_is_device_supported(struct rte_eth_dev *dev,
				 struct rte_pci_driver *drv);

/**
 * @brief Check whether the given device is a supported MCE device (PF or VF).
 *
 * @param dev Pointer to the rte_eth_dev to check.
 *
 * @return true if MCE is supported, false otherwise.
 */
bool is_mce_supported(struct rte_eth_dev *dev);

/**
 * @brief Check whether the given device is a supported MCE VF.
 *
 * @param dev Pointer to the rte_eth_dev to check.
 *
 * @return true if the device is a supported MCE VF, false otherwise.
 */
bool is_mcevf_supported(struct rte_eth_dev *dev);

/**
 * @enum mce_vport_type
 * @brief Identify whether a vport belongs to PF or VF.
 */
enum mce_vport_type {
	MCE_VPORT_IS_PF,
	MCE_VPORT_IS_VF,
};
#define MCE_DEV_TO_ADAPTER(eth_dev) \
	(((struct mce_adapter *)((eth_dev)->data->dev_private)))
#define MCE_DEV_TO_VPORT(eth_dev)                             \
	((MCE_DEV_TO_ADAPTER(eth_dev)->hw.is_vf) ?            \
		 (MCE_DEV_TO_ADAPTER(eth_dev)->vf.vf_vport) : \
		 (MCE_DEV_TO_ADAPTER(eth_dev)->pf.pf_vport))
#define MCE_DEV_TO_PF(eth_dev) \
	(&((struct mce_adapter *)((eth_dev)->data->dev_private))->pf)
#define MCE_DEV_TO_VF(eth_dev) \
	(&((struct mce_adapter *)((eth_dev)->data->dev_private))->vf)
#define MCE_DEV_TO_HW(eth_dev) \
	(&((struct mce_adapter *)((eth_dev)->data->dev_private))->hw)
#define MCE_HW_T0_DEV(hw)    ((hw)->back->pf.dev)
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
static inline int mce_get_pcie_link_state(struct rte_pci_device *pci_dev,
					  struct mce_hw *hw)
{
#define PCI_EXP_LNKSTA_SPEED RTE_GENMASK32(12, 10) /* Current Link Speed (Gen1/2/3/4) */
#define PCI_EXP_LNKSTA_WIDTH RTE_GENMASK32(9, 4)
#define PCI_EXP_LNKSTA       0x12
	u16 lnksta = 0;
	off_t pos = 0;

	pos = rte_pci_find_capability(pci_dev, RTE_PCI_CAP_ID_EXP);
	if (rte_pci_read_config(pci_dev, &lnksta, sizeof(lnksta),
				pos + PCI_EXP_LNKSTA) < 0) {
		return -1;
	}
	hw->pcie_speed = (lnksta & PCI_EXP_LNKSTA_SPEED) >> 10;
	hw->pcie_width = (lnksta & PCI_EXP_LNKSTA_WIDTH) >> 4;

	return 0;
}
#endif
/**
 * @brief Configure receive paths to support scattered RX (multi-segment packets).
 *
 * @param dev Pointer to the Ethernet device.
 */
void mce_rx_scattered_setup(struct rte_eth_dev *dev);

/**
 * @brief Set the MTU for the device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param mtu New MTU value.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

/**
 * @brief Lookup a MAC entry in a MAC filter list.
 *
 * @param mac_list Pointer to the MAC filter list.
 * @param entry Pointer to the MAC entry to lookup (MAC address and loc).
 *
 * @return Pointer to the matching `mce_mac_filter` if found, NULL otherwise.
 */
struct mce_mac_filter *
mce_mac_filter_lookup(struct mce_mac_filter_list *mac_list,
			  struct mce_mac_entry *entry);
static inline bool mce_is_vf_device(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	uint16_t device_id = 0;

	device_id = pci_dev->id.device_id;
	return (device_id == MCE_DEV_ID_N20_VF);
}
/**
 * @brief Get device statistics.
 *
 * @note Signature depends on DPDK version; see implementation.
 */
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(25, 11, 0, 0) > RTE_VERSION
int mce_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);
#elif RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
int mce_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
			  struct eth_queue_stats *qstats);
#else
void mce_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);
#endif

/**
 * @brief Reset device statistics to zero.
 *
 * @param dev Pointer to the Ethernet device.
 *
 * @return 0 on success, negative errno on failure (when applicable by DPDK).
 */
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
int mce_dev_stats_reset(struct rte_eth_dev *dev);
#else
void mce_dev_stats_reset(struct rte_eth_dev *dev);
#endif /* RTE_VERSION >= 19.11 */
int mce_dev_txq_rate_limit(struct rte_eth_dev *dev,
#if RTE_VERSION_NUM(22, 11, 0, 0) <= RTE_VERSION
			   uint16_t queue_idx, uint32_t tx_rate
#else
			   uint16_t queue_idx, uint16_t tx_rate
#endif
);

#endif /* _MCE_H_ */
