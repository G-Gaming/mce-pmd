/**
 * @file mce_ethdev.c
 * @brief MCE Ethernet Device Operations and Management
 *
 * This module implements the core Ethernet device operations for the MCE
 * (DPDK MCE Poll Mode Driver), including device initialization, configuration,
 * link management, statistics collection, VLAN operations, MAC filtering,
 * and various offload capabilities.
 *
 * @details
 * The MCE ethdev module provides:
 * - Device lifecycle management (probe, init, configure, start, stop, uninit)
 * - Link state detection and monitoring
 * - MAC address and VLAN filtering
 * - Statistics and extended statistics collection
 * - RX/TX offload configuration
 * - Module EEPROM and temperature monitoring
 * - Debug and telemetry features
 * - Interrupt handling and mailbox communication
 *
 * The module supports multiple hardware versions through conditional compilation
 * and version-specific device operations registration.
 *
 * @note Supports DPDK 17.2 and later with version-specific adaptations
 * @see mce.h for main MCE driver definitions
 * @see mce_rxtx.h for Rx/Tx operations
 * @see mce_rss.h for RSS configuration
 */

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <rte_version.h>
#ifdef MCE_DEBUG_PCAP
#include <rte_pcapng.h>
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#include <rte_pci.h>
#include <rte_ethdev.h>
#else
#if RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
#include <rte_ethdev_pci.h>
#else
#include <ethdev_pci.h>
#endif /* RTE_VERSION > 21.2 */
#endif /* RTE_VERSION < 17.5 */
#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_time.h>

#include "mce.h"
#include "mce_fdir_flow.h"
#include "mce_flow.h"
#include "mce_intr.h"
#include "mce_logs.h"
#include "mce_pf.h"
#include "mce_route_proxy.h"
#include "mce_rss.h"
#include "mce_rxtx.h"
#include "mce_tm.h"
#include "mce_mp.h"

#include "base/mce_common.h"
#include "base/mce_dma_regs.h"
#include "base/mce_fwchnl.h"
#include "base/mce_hw.h"
#include "base/mce_irq.h"
#include "base/mce_l2_filter.h"
#include "base/mce_mac_regs.h"
#include "base/mce_mbx.h"
#include "base/mce_pf2vfchnl.h"
#include "base/mce_fwchnl.h"
#include "base/mce_sched.h"
#include "base/mce_switch.h"
#include "base/mce_pfvf.h"
#include "base/mce_ptp.h"

#ifdef MCE_DEBUG_PCAP
#include <rte_pcapng.h>
rte_pcapng_t *n20_pcapng_fd;
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#define MCE_FDIR_FILTER_MODE "fdir_mode"
#define MCE_FDIR_FLUSH_MODE  "fdir_flush_mode"
#define MCE_FW_PATH	     "fw_path"
#define MCE_AXI_MHZ	     "axi_mhz"
#define MCE_LINK_DOWN_ON_CLOSE "link_down_on_close"
#define MCE_SMID_VECTOR_ENA  "smid_vector_en"
#define MCE_ESWITCH_MODE     "eswitch_mode"
#endif /* RTE_VERSION >= 17.02 */
#if 0
static const char * const mce_valid_args_key[] = {
	MCE_FDIR_FILTER_MODE,
	MCE_FDIR_FLUSH_MODE,
	NULL
};
#endif

unsigned int mce_loglevel;
int mce_logtype_init;
int mce_logtype_driver;
static int mce_link_update(struct rte_eth_dev *dev,
			   int wait_to_complete __rte_unused);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
mce_dev_xstats_reset(struct rte_eth_dev *dev);
static int
mce_fw_version_get(struct rte_eth_dev *dev, char *fw_version, size_t fw_size);

static void mce_mailbox_incomming_event_irq_handler(struct mce_mbx_info *mbx,
						    int event_id)
{
	/* event request */
	if (mbx->dst == MBX_PF2VF) /* VF2PF */
		mce_mbx_vf2pf_event_req_isr(mbx, event_id);
	else /* FW2PF*/
		mce_mbx_fw2pf_event_req_isr(mbx, event_id);
}

static void mce_mailbox_incomming_req_irq_handler(struct mce_mbx_info *mbx,
						  struct mbx_req *req)
{
	/* req with data*/
	if (mbx->dst == MBX_PF2VF) /* VF2PF*/
		mce_mbx_vf2pf_req_isr(mbx, req);
	else /* FW2PF*/
		mce_mbx_fw2pf_req_isr(mbx, req);
}
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void
mce_dev_interrupt_handler(struct rte_intr_handle *handle __rte_unused,
			  void *param)
#else
static void mce_dev_interrupt_handler(void *param)
#endif
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct mce_adapter *adapter = MCE_DEV_TO_ADAPTER(dev);
	uint32_t total_irq_req_num = 0;
	struct mce_hw *hw = &adapter->hw;

	mce_pf_irq0_disable(hw);
	total_irq_req_num = rd32(hw, MCE_TITAL_IRQ_REQ_NUM);
	if (total_irq_req_num != hw->total_irq_req_num) {
		mce_mbx_clean_all_incomming_req(
				hw, mce_mailbox_incomming_event_irq_handler,
				mce_mailbox_incomming_req_irq_handler);
		hw->total_irq_req_num = total_irq_req_num;
	}
	mce_pf_irq0_enable(hw);

	return;
}

#ifdef RNPCE_FD_DEBUG
static int mce_debug_switch(struct rte_eth_dev *dev);
#endif
static void mce_get_hw_stats(struct mce_vport *vport);
/**
 * @brief Enable receive checksum offloading.
 *
 * Configures the hardware to perform checksum validation on received packets
 * for IPv4, UDP, TCP, SCTP, and tunneled protocols.
 *
 * @param dev Pointer to the Ethernet device
 *
 * @note Modifies hardware register MCE_ETH_RQA_CTRL
 * @see mce_disable_rx_cksum()
 */
static void mce_enable_rx_cksum(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint64_t offloads;
	bool tunnel_set = false;
	uint32_t cksum_ctrl;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	offloads = dev->data->dev_conf.rxmode.offloads;
#else
	if (dev->data->dev_conf.rxmode.hw_ip_checksum) {
		offloads = RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
			   RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
			   RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
			   RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
			   RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
			   RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM;
	}
#endif
	offloads = RTE_ETH_RX_OFFLOAD_UDP_CKSUM | RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
		   RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
		   RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
		   RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		   RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM;
	cksum_ctrl = MCE_E_REG_READ(hw, MCE_ETH_RQA_CTRL);
	cksum_ctrl |= MCE_RQA_RX_ERR_MASK;
#define MCE_OUT_CKSUM_MASK                     \
	(RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM | \
	 RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM)
	if (offloads & MCE_OUT_CKSUM_MASK)
		tunnel_set = true;
	if (tunnel_set) {
		/* Tunnel Option Cksum L4_Option */
		if (offloads & (RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
				RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
				RTE_ETH_RX_OFFLOAD_SCTP_CKSUM)) {
			cksum_ctrl &= ~MCE_RQA_RX_I_L4_ERR;
		}
		if (offloads & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
			cksum_ctrl &= ~MCE_RQA_RX_I_L3_ERR;
		if (offloads & RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM)
			cksum_ctrl &= ~MCE_RQA_RX_O_L4_ERR;
		if (offloads & RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM) {
			cksum_ctrl &= ~MCE_RQA_RX_O_L3_ERR;
			cksum_ctrl &= ~MCE_RQA_RX_O_L4_ERR;
		}
	} else {
		/* No Tunnel Option Cksum L4_Option */
		if (offloads & (RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
				RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
				RTE_ETH_RX_OFFLOAD_SCTP_CKSUM)) {
			cksum_ctrl &= ~MCE_RQA_RX_O_L4_ERR;
		}
		if (offloads & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
			cksum_ctrl &= ~MCE_RQA_RX_O_L3_ERR;
	}
	MCE_E_REG_WRITE(hw, MCE_ETH_RQA_CTRL, cksum_ctrl);
}

/**
 * @brief Disable receive checksum offloading.
 *
 * Clears the RX checksum validation bits in hardware,  disabling
 * all checksum offload features.
 *
 * @param dev Pointer to the Ethernet device
 *
 * @see mce_enable_rx_cksum()
 */
static void mce_disable_rx_cksum(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t cksum_ctrl;

	cksum_ctrl = MCE_E_REG_READ(hw, MCE_ETH_RQA_CTRL);
	cksum_ctrl |= MCE_RQA_RX_ERR_MASK;
	MCE_E_REG_WRITE(hw, MCE_ETH_RQA_CTRL, cksum_ctrl);
}

/**
 * @brief Configure or disable CRC stripping on received packets.
 *
 * Controls whether the hardware automatically removes the CRC (Cyclic Redundancy
 * Check) trailer from received packets before passing to the driver.
 *
 * @param dev Pointer to the Ethernet device
 * @param dis Set to true to disable CRC stripping, false to enable it
 *
 * @note Updates hardware register MCE_M_MAC_CTRL
 */
static void
mce_disable_crc_strip(struct rte_eth_dev *dev, bool dis)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = vport->hw;
	uint32_t ctrl = 0;

	ctrl = MCE_E_REG_READ(hw, MCE_M_MAC_CTRL);

	if (dis)
		ctrl &= ~MCE_M_CRC_STRIP_EN;
	else
		ctrl |= MCE_M_CRC_STRIP_EN;
	MCE_E_REG_WRITE(hw, MCE_M_MAC_CTRL, ctrl);
	hw->pf_rxfcs_en = dis;
}

/**
 * @brief Configure the MCE Ethernet device.
 *
 * Applies the device configuration parameters including RX/TX modes,
 * offloads, RSS settings, and hardware initialization based on the
 * configuration provided in dev->data->dev_conf.
 *
 * @param dev Pointer to the Ethernet device
 *
 * @return 0 on successful configuration
 * @return Negative error code on failure
 *
 * @note Must be called before device start
 * @see mce_dev_start()
 */
static int mce_dev_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	struct rte_eth_rxmode *rxmode = &dev_conf->rxmode;
	struct rte_eth_txmode *txmode = &dev_conf->txmode;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	struct rte_eth_dcb_tx_conf *dcb_tx_conf =
		&dev_conf->tx_adv_conf.dcb_tx_conf;
#endif
	uint16_t i = 0, j = 0;

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rxmode->offloads & MCE_RX_CHECKSUM_SUPPORT)
#else
	if (rxmode->hw_ip_checksum)
#endif
		mce_enable_rx_cksum(dev);
	else
		mce_disable_rx_cksum(dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC)
#else
	if (rxmode->hw_strip_crc)
#endif
		mce_disable_crc_strip(dev, true);
	else
		mce_disable_crc_strip(dev, false);
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	if (txmode->mq_mode == RTE_ETH_MQ_TX_DCB && dcb_tx_conf->nb_tcs) {
		hw->dcb_opt.num_tc = dcb_tx_conf->nb_tcs;
		for (j = 0; j < MCE_MAX_USER_PRIO; j++) {
			for (i = 0; i < dcb_tx_conf->nb_tcs; i++) {
				if (i != dcb_tx_conf->dcb_tc[j])
					continue;

				hw->tc_prior_map[i] |= dcb_tx_conf->dcb_tc[j];
			}
			hw->dcb_opt.hw_tc_map[j] = dcb_tx_conf->dcb_tc[j];
		}
		if (dev_conf->dcb_capability_en & RTE_ETH_DCB_PFC_SUPPORT)
			hw->dcb_opt.pfc_en = 1;

		if (dev_conf->dcb_capability_en & RTE_ETH_DCB_PG_SUPPORT)
			hw->dcb_opt.pg_en = 1;
	}
#else
	RTE_SET_USED(hw);
	RTE_SET_USED(txmode);
#endif

	return 0;
}

static uint64_t
mce_get_speed_support(struct mce_hw *hw)
{
	struct phy_speed_ablity sfp_ablity = {};
	uint64_t speeds = 0;

	mce_get_fw_supported_speed(hw, &sfp_ablity);

	if (sfp_ablity.speed_100g)
		speeds |= RTE_ETH_LINK_SPEED_100G;
	if (sfp_ablity.speed_40g)
		speeds |= RTE_ETH_LINK_SPEED_40G;
	if (sfp_ablity.speed_25g)
		speeds |= RTE_ETH_LINK_SPEED_25G;
	if (sfp_ablity.speed_10g)
		speeds |= RTE_ETH_LINK_SPEED_10G;
	if (sfp_ablity.speed_1g)
		speeds |= RTE_ETH_LINK_SPEED_1G;
#if RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
	if (sfp_ablity.dac) {
		hw->connect_type = RTE_ETH_LINK_CONNECTOR_DAC;
	} else if (sfp_ablity.is_sgmii) {
		hw->connect_type = RTE_ETH_LINK_CONNECTOR_SGMII;
	} else {
		if (sfp_ablity.speed_100g)
			hw->connect_type = RTE_ETH_LINK_CONNECTOR_QSFP28;
		else if (sfp_ablity.speed_40g)
			hw->connect_type = RTE_ETH_LINK_CONNECTOR_QSFP_PLUS;
		else if (sfp_ablity.speed_25g || sfp_ablity.speed_10g)
			hw->connect_type = RTE_ETH_LINK_CONNECTOR_SFP28;
		else if (sfp_ablity.speed_1g)
			hw->connect_type = RTE_ETH_LINK_CONNECTOR_SFP;
		else
			hw->connect_type = RTE_ETH_LINK_CONNECTOR_NONE;
	}
#endif

	return speeds;
}

/**
 * @brief Get device information and capabilities.
 *
 * Retrieves and populates device information including supported offloads,
 * queue limits, capabilities, and default configurations.
 *
 * @param dev Pointer to the Ethernet device
 * @param dev_info Output structure to receive device information
 *
 * @return 0 on success (for DPDK >= 19.11)
 * @return void (for DPDK < 19.11)
 *
 * @note Capabilities include checksum, TSO, VLAN, and RSS offloads
 */
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_dev_infos_get(struct rte_eth_dev *dev,
			     struct rte_eth_dev_info *dev_info)
#else
static void mce_dev_infos_get(struct rte_eth_dev *dev,
			      struct rte_eth_dev_info *dev_info)
#endif
{
	struct mce_pf *pf = MCE_DEV_TO_PF(dev);
	struct mce_hw *hw = pf->pf_vport->hw;

#if RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	dev_info->pci_dev = pci_dev;
#endif
	if (pf->max_vfs) {
		dev_info->max_rx_queues = hw->nb_qpair_per_vf;
		dev_info->max_tx_queues = hw->nb_qpair_per_vf;
	} else {
		dev_info->max_rx_queues = hw->nb_qpair;
		dev_info->max_tx_queues = hw->nb_qpair;
	}
	dev_info->min_rx_bufsize = 60;
	dev_info->max_rx_pktlen = MCE_MAX_FRAME_SIZE;
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	dev_info->rx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = 4096,
		.nb_min = 64,
		.nb_align = 2,
	};
#endif
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	dev_info->tx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = 4096,
		.nb_min = 128,
		.nb_align = 2,
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
		.nb_seg_max = 32,
		.nb_mtu_seg_max = 4096,
#endif
	};
#endif
	if (!hw->max_vfs)
		dev_info->max_hash_mac_addrs = MCE_MAC_HASH_SIZE;
	dev_info->max_mac_addrs = pf->pf_vport->attr.max_mac_addrs;
	dev_info->rx_offload_capa =
		RTE_ETH_RX_OFFLOAD_VLAN_FILTER | RTE_ETH_RX_OFFLOAD_QINQ_STRIP |
		RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
		RTE_ETH_RX_OFFLOAD_VLAN_EXTEND | RTE_ETH_RX_OFFLOAD_RSS_HASH |
		RTE_ETH_RX_OFFLOAD_TIMESTAMP |
		RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM |
		RTE_ETH_RX_OFFLOAD_KEEP_CRC |
		RTE_ETH_RX_OFFLOAD_SCATTER;
#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
	dev_info->rx_offload_capa |= RTE_ETH_RX_OFFLOAD_JUMBO_FRAME;
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	dev_info->rx_queue_offload_capa = RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	dev_info->rx_offload_capa |= dev_info->rx_queue_offload_capa;
#endif
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
	dev_info->rss_algo_capa = RTE_ETH_HASH_ALGO_CAPA_MASK(DEFAULT) |
				  RTE_ETH_HASH_ALGO_CAPA_MASK(TOEPLITZ) |
				  RTE_ETH_HASH_ALGO_CAPA_MASK(SYMMETRIC_TOEPLITZ) |
				  RTE_ETH_HASH_ALGO_CAPA_MASK(SYMMETRIC_TOEPLITZ_SORT);
#endif
	dev_info->reta_size = MCE_MAX_RETA_LOC_SIZE;
	dev_info->hash_key_size = MCE_MAX_HASH_KEY_SIZE * sizeof(uint32_t);
	dev_info->flow_type_rss_offloads = MCE_SUPPORT_RSS_OFFLOAD_ALL;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	dev_info->tx_queue_offload_capa = RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
#endif
	dev_info->tx_offload_capa =
		RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
		RTE_ETH_TX_OFFLOAD_TCP_CKSUM | RTE_ETH_TX_OFFLOAD_SCTP_CKSUM |
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM |
		RTE_ETH_TX_OFFLOAD_TCP_TSO | RTE_ETH_TX_OFFLOAD_UDP_TSO |
		RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_QINQ_INSERT |
		RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		dev_info->tx_queue_offload_capa |
#endif
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
#if RTE_VERSION_NUM(19, 5, 0, 0) <= RTE_VERSION
	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->max_mtu = dev_info->max_rx_pktlen - MCE_ETH_OVERHEAD;
#endif
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	dev_info->speed_capa = mce_get_speed_support(hw);
#endif
	/* clang-format off */
	dev_info->default_rxconf = (struct rte_eth_rxconf){
		.rx_thresh = {
				.pthresh = MCE_RX_DESC_HIGH_WATER_TH,
				.hthresh = MCE_RX_DEFAULT_BURST,
				.wthresh = MCE_RX_DEFAULT_WTHRESH,
			},

		.rx_free_thresh = MCE_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		.offloads = 0,
#endif
	};

	dev_info->default_txconf = (struct rte_eth_txconf){
		.tx_thresh = {
				.pthresh = MCE_TX_DESC_HIGH_WATER_TH,
				.hthresh = MCE_TX_DEFAULT_BURST,
				.wthresh = MCE_TX_DEFAULT_WTHRESH,
			},
		.tx_free_thresh = MCE_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = MCE_DEFAULT_TX_RS_THRESH,
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
		.txq_flags =
			ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
#else
		.offloads = 0,
#endif
	};
	/* clang-format on */
	/* Default Ring configure */
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	dev_info->default_rxportconf.burst_size = 32;
	dev_info->default_txportconf.burst_size = 32;
	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = 512;
	dev_info->default_txportconf.ring_size = 512;
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif /* RTE_VERSION >= 19.11 */
}

void mce_rx_scattered_setup(struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	uint16_t max_pkt_size =
		dev->data->dev_conf.rxmode.mtu + MCE_ETH_OVERHEAD;
#else
	uint16_t max_pkt_size = dev->data->dev_conf.rxmode.max_rx_pkt_len;
#endif
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_rx_queue *rxq;
	uint16_t dma_buf_size;
	uint16_t queue_id;

	if (dev->data->rx_queues == NULL)
		return;

	for (queue_id = 0; queue_id < dev->data->nb_rx_queues; queue_id++) {
		rxq = dev->data->rx_queues[queue_id];
		if (!rxq)
			continue;

		if (hw->min_dma_size == 0)
			hw->min_dma_size = rxq->rx_buf_len;
		else
			hw->min_dma_size =
				RTE_MIN(hw->min_dma_size, rxq->rx_buf_len);
	}
	dma_buf_size = hw->min_dma_size;
#if RTE_VERSION_NUM(17, 11, 0, 16) < RTE_VERSION
	if (dev_conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_SCATTER ||
#else
	if (dev_conf->rxmode.enable_scatter ||
#endif
	    max_pkt_size > dma_buf_size ||
	    dev->data->mtu + MCE_ETH_OVERHEAD > dma_buf_size)
		dev->data->scattered_rx = 1;
	else
		dev->data->scattered_rx = 0;
}

static uint32_t eth_conf_speed(struct rte_eth_conf *conf)
{
	uint32_t cfg_link_speed = 0;

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	cfg_link_speed = conf->link_speeds;

	if (cfg_link_speed == RTE_ETH_LINK_SPEED_AUTONEG)
		cfg_link_speed = RTE_ETH_LINK_SPEED_AUTONEG;
	else if(cfg_link_speed & RTE_ETH_LINK_SPEED_100G)
		cfg_link_speed = RTE_ETH_LINK_SPEED_100G;
	else if(cfg_link_speed & RTE_ETH_LINK_SPEED_40G)
		cfg_link_speed = RTE_ETH_LINK_SPEED_40G;
	else if(cfg_link_speed & RTE_ETH_LINK_SPEED_25G)
		cfg_link_speed = RTE_ETH_LINK_SPEED_25G;
	else if(cfg_link_speed & RTE_ETH_LINK_SPEED_10G)
		cfg_link_speed = RTE_ETH_LINK_SPEED_10G;
	else if(cfg_link_speed & RTE_ETH_LINK_SPEED_1G)
		cfg_link_speed = RTE_ETH_LINK_SPEED_1G;
	else if((cfg_link_speed & RTE_ETH_LINK_SPEED_100M) || (cfg_link_speed & RTE_ETH_LINK_SPEED_100M_HD))
		cfg_link_speed = RTE_ETH_LINK_SPEED_100M;
	else if((cfg_link_speed & RTE_ETH_LINK_SPEED_10M) || cfg_link_speed & RTE_ETH_LINK_SPEED_10M_HD)
		cfg_link_speed = RTE_ETH_LINK_SPEED_10M;
#else
	cfg_link_speed  = conf->link_speeds;
#endif
	return cfg_link_speed;
}

static int mce_speed_duplex_setup(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	enum FORCE_SPEED speed_type = NO_FORCE_SPEED;
	bool is_backplane = false, autoneg = true;
	bool is_sgmii = false, duplex = true;
	uint32_t cfg_link_speed;

	mce_update_fw_stat(hw);

	is_sgmii = hw->fw_stat.stat0.is_sgmii;
	is_backplane = hw->fw_stat.stat0.is_backplane ? true:false;

	cfg_link_speed = eth_conf_speed(conf);
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	if (is_backplane || is_sgmii) {
		if (cfg_link_speed != RTE_ETH_LINK_SPEED_AUTONEG)
			autoneg = false;
	}
#else
	if (is_sgmii) {
		if (conf->link_duplex != RTE_ETH_LINK_FULL_DUPLEX)
			duplex = false;
		if (conf->link_duplex != ETH_LINK_AUTONEG_DUPLEX)
			autoneg = false;
	}
#endif

	if (is_sgmii) {
		switch (cfg_link_speed) {
		case RTE_ETH_LINK_SPEED_1G:
			speed_type = FORCE_1G;
			break;
		case RTE_ETH_LINK_SPEED_100M:
			speed_type = FORCE_100M;
			break;
		case  RTE_ETH_LINK_SPEED_10M:
			speed_type = FORCE_10M;
			break;
		default:
			return -EINVAL;
		}
	} else {
		/* force speed must set autoneg to disable */
		switch (cfg_link_speed) {
		case RTE_ETH_LINK_SPEED_1G:
			speed_type = FORCE_1G;
			break;
		case RTE_ETH_LINK_SPEED_10G:
			if (hw->max_speed < RTE_ETH_SPEED_NUM_10G)
				return -EINVAL;
			speed_type = FORCE_10G;
			break;
		case RTE_ETH_LINK_SPEED_25G:
			if (hw->max_speed < RTE_ETH_SPEED_NUM_25G)
				return -EINVAL;
			speed_type = FORCE_25G;
			break;
		case RTE_ETH_LINK_SPEED_40G:
			if (hw->max_speed < RTE_ETH_SPEED_NUM_40G)
				return -EINVAL;
			speed_type = FORCE_40G;
			break;
		case RTE_ETH_LINK_SPEED_100G:
			if (hw->max_speed < RTE_ETH_SPEED_NUM_100G)
				return -EINVAL;
			speed_type = FORCE_100G;
			break;
		case RTE_ETH_LINK_SPEED_AUTONEG :
			speed_type = NO_FORCE_SPEED;
			break;
		default:
			return -EINVAL;
		}
	}
	if (is_sgmii || is_backplane)
		mce_mbx_set_autoneg(hw, autoneg);
	return mce_mbx_set_force_speed(hw, speed_type, duplex);
}

/**
 * @brief Start the device: enable queues, RSS, and bring link up notifications.
 *
 * This prepares RX/TX queues, configures RSS, enables interrupts and notifies
 * firmware that the interface is up.
 *
 * @param dev Pointer to the Ethernet device.
 * @return 0 on success, negative errno on failure.
 */
static int mce_dev_start(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t vport_id = vport->attr.vport_id;
	char str[128] = "";

	mce_fw_version_get(dev, str, 128);
	printf("firmware_version %s\n", str);
	if (mce_rxq_intr_enable(dev) < 0)
		return -EINVAL;
	mce_speed_duplex_setup(dev);
	mce_enable_all_rx_queue(dev);
	mce_enable_all_tx_queue(dev);
	mce_dev_rss_configure(dev);
	MCE_E_REG_SET_BITS(hw, MCE_ETH_RX_ES_DROP_CTRL, RTE_BIT32(0), 0);
	MCE_E_REG_SET_BITS(hw, MCE_ETH_TX_ES_DROP_CTRL, RTE_BIT32(0),
			   RTE_BIT32(4));
	/* max packet len limit setup */
	mce_dev_mtu_set(dev, dev->data->mtu);
	mce_rx_scattered_setup(dev);
	mce_setup_rx_function(dev);
	mce_setup_tx_function(dev);
	if (vport->attr.rx.vec_options && vport->attr.rx.simd_en)
		mce_rx_vec_cksum_db_init(dev);
	mce_mbx_fw_ifup(hw, true);
	mce_mbx_set_pf_stat_reg(hw);

	mce_mbx_link_state_change_notify_en(hw, true);
	mce_dev_xstats_reset(dev);
	mce_link_update(dev, 0);
	MCE_E_REG_SET_BITS(hw, MCE_ETH_FWD_ATTR(vport_id), MCE_FWD_DROP, 0);
	/* enable datapath on secondary process. */
	mce_mp_req_start_rxtx(dev);

	return 0;
}

/**
 * @brief Stop the device: disable queues and notify firmware the interface is down.
 *
 * Disables RX/TX queues, stops firmware notifications and clears relevant HW
 * forwarding/drop controls.
 *
 * @param dev Pointer to the Ethernet device.
 * @return 0 on success when DPDK expects int, otherwise void.
 */
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
static int mce_dev_stop(struct rte_eth_dev *dev)
#else
static void mce_dev_stop(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t vport_id = vport->attr.vport_id;

	PMD_INIT_FUNC_TRACE();

	/* disable fw send linkStatus irq to pf */
	mce_mbx_link_state_change_notify_en(hw, false);
	/* Disable datapath on secondary process. */
	mce_mp_req_stop_rxtx(dev);
	MCE_E_REG_SET_BITS(hw, MCE_ETH_RX_ES_DROP_CTRL, 0, RTE_BIT32(0));
	MCE_E_REG_SET_BITS(hw, MCE_ETH_TX_ES_DROP_CTRL, 0, RTE_BIT32(0));

	MCE_E_REG_SET_BITS(hw, MCE_ETH_FWD_ATTR(vport_id), 0, MCE_FWD_DROP);
	mce_disable_all_rx_queue(dev);
	mce_disable_all_tx_queue(dev);

	mce_mbx_fw_ifup(hw, false);
	mce_mbx_set_pf_stat_reg(hw);
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
static int mce_dev_close(struct rte_eth_dev *eth_dev)
#else
static void mce_dev_close(struct rte_eth_dev *eth_dev)
#endif
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct mce_vport *vport = MCE_DEV_TO_VPORT(eth_dev);
	int i = 0;

	PMD_INIT_FUNC_TRACE();
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		mce_mp_req_secondry_removed(eth_dev);
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
		free(eth_dev->process_private);
#endif
		return 0;
	} else {
		mce_mp_req_removed(eth_dev);
	}
	mce_dev_stop(eth_dev);
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		mce_rx_queue_release(eth_dev->data->rx_queues[i]);
		eth_dev->data->rx_queues[i] = NULL;
	}
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		mce_tx_queue_release(eth_dev->data->tx_queues[i]);
		eth_dev->data->tx_queues[i] = NULL;
	}
	eth_dev->data->nb_rx_queues = 0;
	eth_dev->data->nb_tx_queues = 0;
	rte_intr_callback_unregister(intr_handle,
			mce_dev_interrupt_handler, eth_dev);
	mce_mbx_drv_send_uninstall_notify_fw(vport->hw);
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	free(eth_dev->process_private);
#endif
	mce_destory_vport(vport);

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
static int mce_dev_flow_ops_get(struct rte_eth_dev *dev,
				const struct rte_flow_ops **ops)
{
	if (!dev)
		return -EINVAL;

	*ops = &mce_flow_ops;
	return 0;
}
#else
static int mce_filter_ctrl(struct rte_eth_dev *dev,
			   enum rte_filter_type filter_type,
			   enum rte_filter_op filter_op, void *arg)
{
	int ret = 0;

	RTE_SET_USED(filter_op);
	RTE_SET_USED(arg);
	RTE_SET_USED(dev);
	switch (filter_type) {
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	case RTE_ETH_FILTER_GENERIC:
		if (filter_op != RTE_ETH_FILTER_GET)
			return -EINVAL;
		*(const void **)arg = &mce_flow_ops;
		break;
#endif
	default:
		PMD_DRV_LOG(WARNING,
			    "Filter type (%d) not "
			    "supported",
			    filter_type);
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}
#endif

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_promisc_enable(struct rte_eth_dev *dev)
#else
static void mce_promisc_enable(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_rxmode *rxmode = NULL;
#endif
	bool vlan_filter_en = 0;

	PMD_INIT_FUNC_TRACE();
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	rxmode = &dev->data->dev_conf.rxmode;
	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
#else
	if (dev->data->dev_conf.rxmode.hw_vlan_filter)
#endif
		vlan_filter_en = 1;
	mce_update_mpfm(vport, MCE_MPF_MODE_PROMISC, vlan_filter_en, 1);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_promisc_disable(struct rte_eth_dev *dev)
#else
static void mce_promisc_disable(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_rxmode *rxmode = NULL;
#endif
	bool vlan_filter_en = 0;

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	rxmode = &dev->data->dev_conf.rxmode;
	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
#else
	if (dev->data->dev_conf.rxmode.hw_vlan_filter)
#endif
		vlan_filter_en = 1;
	mce_update_mpfm(vport, MCE_MPF_MODE_PROMISC, vlan_filter_en, 0);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#else
	return;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_allmulticast_enable(struct rte_eth_dev *dev)
#else
static void mce_allmulticast_enable(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);

	mce_update_mpfm(vport, MCE_MPF_MODE_ALLMULTI, 0, 1);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#else
	return;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_allmulticast_disable(struct rte_eth_dev *dev)
#else
static void mce_allmulticast_disable(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);

	PMD_INIT_FUNC_TRACE();
	if (dev->data->promiscuous == 1)
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
		return 0;
#else
		return; /* must remain in all_multicast mode */
#endif
	mce_update_mpfm(vport, MCE_MPF_MODE_ALLMULTI, 0, 0);

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#else
	return;
#endif
}

static uint64_t mce_get_eth_stats_64bit(struct mce_hw *hw, uint32_t reg_off)
{
	uint64_t val_hi;
	uint64_t val_lo;

	val_lo = MCE_E_REG_READ(hw, reg_off);
	val_hi = MCE_E_REG_READ(hw, reg_off + 4);

	return (val_lo + (val_hi << 32));
}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION && \
    RTE_VERSION_NUM(25, 11, 0, 0) > RTE_VERSION
int mce_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
#elif RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
int mce_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
		      struct eth_queue_stats *qstats)
#else
void mce_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
#endif /* RTE_VERSION >= 17.11 */
{
	uint64_t rx_bytes, rx_unicast, rx_multicast, rx_broadcast;
	uint64_t tx_bytes, tx_unicast, tx_multicast, tx_broadcast;
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct rte_eth_dev_data *data = dev->data;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_rx_queue *rxq = NULL;
	struct mce_tx_queue *txq = NULL;
	uint64_t tx_tso_pkts = 0;
	uint64_t rx_miss_drop;
	uint64_t ipackets;
	uint64_t opackets;
	uint16_t idx = 0;
	uint16_t base;
	int i = 0;

	PMD_INIT_FUNC_TRACE();
	if (!hw->is_vf)
		mce_get_hw_stats(vport);
	base = vport->attr.qpair_base;
	memset(&vport->basic_stats, 0, sizeof(vport->basic_stats));
	for (i = 0; i < data->nb_rx_queues; i++) {
		if (!data->rx_queues[i])
			continue;
		idx = base + i;
		rxq = data->rx_queues[i];
		rx_bytes = mce_get_eth_stats_64bit(
				hw, MCE_DMA_RX_BYTES_LO(idx));
		rx_unicast = mce_get_eth_stats_64bit(
				hw, MCE_DMA_RX_UNICAST_PKT_LO(idx));
		rx_multicast = mce_get_eth_stats_64bit(
				hw, MCE_DMA_RX_MULCAST_PKT_LO(idx));
		rx_broadcast = mce_get_eth_stats_64bit(
				hw, MCE_DMA_RX_BROADCAST_PKT_LO(idx));
		rx_miss_drop = MCE_E_REG_READ(
				hw, MCE_DMA_RXQ_NODESC_DROP(idx));
		ipackets = rx_unicast + rx_multicast + rx_broadcast;
		ipackets -= rxq->rep_stats.ipackets;
		rx_bytes -= rxq->rep_stats.ibytes;

		vport->basic_stats.rx_multicast_pkts += rx_multicast;
		vport->basic_stats.rx_broadcast_pkts += rx_broadcast;
		vport->basic_stats.rx_unicast_pkts += rx_unicast;
		vport->basic_stats.rx_miss_drop += rx_miss_drop;
		vport->basic_stats.rx_packets += ipackets;
		vport->basic_stats.rx_bytes += rx_bytes;
#if RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
		if (qstats != NULL && i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			qstats->q_ipackets[i] = ipackets;
			qstats->q_ibytes[i] = rx_bytes;
		}
#else
		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = ipackets;
			stats->q_ibytes[i] = rx_bytes;
		}
#endif
	}
	for (i = 0; i < data->nb_tx_queues; i++) {
		if (!data->tx_queues[i])
			continue;
		txq = data->tx_queues[i];
		idx = base + i;
		tx_bytes = mce_get_eth_stats_64bit(
				hw, MCE_DMA_TX_BYTES_LO(idx));
		tx_unicast = mce_get_eth_stats_64bit(
				hw, MCE_DMA_TX_UNICAST_PKT_LO(idx));
		tx_multicast = mce_get_eth_stats_64bit(
				hw, MCE_DMA_TX_MULCAST_PKT_LO(idx));
		tx_broadcast = mce_get_eth_stats_64bit(
				hw, MCE_DMA_TX_BROADCAST_PKT_LO(idx));
		opackets = tx_unicast + tx_multicast + tx_broadcast;
		opackets -= txq->rep_stats.opackets;
		tx_bytes -= txq->rep_stats.obytes;
		tx_tso_pkts += txq->stats.tx_tso_pkts;
		vport->basic_stats.tx_multicast_pkts += tx_multicast;
		vport->basic_stats.tx_broadcast_pkts += tx_broadcast;
		vport->basic_stats.tx_unicast_pkts += tx_unicast;
		vport->basic_stats.tx_packets += opackets;
		vport->basic_stats.tx_bytes += tx_bytes;
#if RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
		if (qstats != NULL && i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			qstats->q_opackets[i] = opackets;
			qstats->q_obytes[i] = tx_bytes;
		}
#else
		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = opackets;
			stats->q_obytes[i] = tx_bytes;
		}
#endif
	}
	vport->hw_stats.tx_tso_pkts = tx_tso_pkts;

	stats->imissed = vport->basic_stats.rx_miss_drop;
	stats->imissed += vport->hw_stats.rx_trans_drop;
	stats->ipackets = vport->basic_stats.rx_packets;
	stats->ibytes = vport->basic_stats.rx_bytes;
	stats->opackets = vport->basic_stats.tx_packets;
	stats->obytes = vport->basic_stats.tx_bytes;

	if (!vport->is_vf)
		stats->ierrors = vport->hw_stats.rx_bad_pkts;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
int
#else
void
#endif
mce_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = vport->hw;
	uint16_t max_queues = 0;
	uint16_t base = 0;
	uint16_t idx = 0;
	int i = 0;
	PMD_INIT_FUNC_TRACE();

	max_queues = RTE_MAX(dev->data->nb_rx_queues, dev->data->nb_tx_queues);
	base = vport->attr.vport_id * 4;
	for (i = 0; i < max_queues; i++) {
		idx = base + i;
		/* read on clear */
		MCE_E_REG_WRITE(hw, MCE_DMA_Q_STATS_CLR(idx), 1);
		MCE_E_REG_READ(hw, MCE_DMA_RXQ_NODESC_DROP(idx));
		mce_get_eth_stats_64bit(hw, MCE_DMA_RX_BYTES_LO(idx));
		mce_get_eth_stats_64bit(hw, MCE_DMA_RX_UNICAST_PKT_LO(idx));
		mce_get_eth_stats_64bit(hw, MCE_DMA_RX_MULCAST_PKT_LO(idx));
		mce_get_eth_stats_64bit(hw, MCE_DMA_RX_BROADCAST_PKT_LO(idx));
		/* clear tx counter */
		mce_get_eth_stats_64bit(hw, MCE_DMA_TX_BYTES_LO(idx));
		mce_get_eth_stats_64bit(hw, MCE_DMA_TX_UNICAST_PKT_LO(idx));
		mce_get_eth_stats_64bit(hw, MCE_DMA_TX_MULCAST_PKT_LO(idx));
		mce_get_eth_stats_64bit(hw, MCE_DMA_TX_BROADCAST_PKT_LO(idx));
		MCE_E_REG_WRITE(hw, MCE_DMA_Q_STATS_CLR(idx), 0);
	}
#if 0
	struct mce_rx_queue *rxq;
	struct mce_tx_queue *txq;
	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = ((struct mce_rx_queue **)
				(dev->data->rx_queues))[idx];
		if (!rxq)
			continue;
		memset(&rxq->stats, 0, sizeof(struct xstats));
	}
	for (idx = 0; idx < dev->data->nb_tx_queues; idx++) {
		txq = ((struct mce_tx_queue **)
				(dev->data->tx_queues))[idx];
		if (!txq)
			continue;
		memset(&txq->stats, 0, sizeof(struct xstats));
	}
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

/**
 * @brief Reset MAC hardware statistics counters (MMC) and read updated values.
 *
 * This triggers a hardware MMC counter reset on read, reads the hardware
 * statistics into the driver's structures, and clears the reset flag.
 *
 * @param dev Pointer to the Ethernet device.
 */
static void
mce_dev_mac_stats_reset(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = vport->hw;
	uint32_t reg = 0;

	/* Set MMC Reset HW Counter When Read Event */
	reg = MCE_E_REG_READ(hw, MCE_M_MAC_CTRL);
	reg |= MCE_M_MMC_RCLRC;
	MCE_E_REG_WRITE(hw, MCE_M_MAC_CTRL, reg);
	mce_get_hw_stats(vport);
	reg = MCE_E_REG_READ(hw, MCE_M_MAC_CTRL);
	reg &= ~MCE_M_MMC_RCLRC;
	MCE_E_REG_WRITE(hw, MCE_M_MAC_CTRL, reg);
}

/**
 * @brief Reset extended device statistics (xstats) and refresh hardware counters.
 *
 * Performs a top-level device stats reset, triggers MMC counter clear/read,
 * updates the driver's `mce_hw_stats` snapshot and zeroes the running counters.
 *
 * @param dev Pointer to the Ethernet device.
 * @return 0 on success when DPDK requires an int return, otherwise void.
 */
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
mce_dev_xstats_reset(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw_stats *stats = &vport->hw_stats;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t reg = 0;

	mce_dev_stats_reset(dev);
	/* Set MMC Reset HW Counter When Read Event */
	reg = MCE_E_REG_READ(hw, MCE_M_MAC_CTRL);
	reg |= MCE_M_MMC_RCLRC;
	MCE_E_REG_WRITE(hw, MCE_M_MAC_CTRL, reg);
	mce_get_hw_stats(vport);
	reg = MCE_E_REG_READ(hw, MCE_M_MAC_CTRL);
	reg &= ~MCE_M_MMC_RCLRC;
	MCE_E_REG_WRITE(hw, MCE_M_MAC_CTRL, reg);

	memset(stats, 0, sizeof(*stats));
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

struct rte_mce_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t offset;
	uint32_t reg_base;
	uint32_t cmd_sel;
	bool hi_addr_en;
	int32_t hi_off;
};
struct mce_bus_count_reg {
	uint32_t ctrl_reg;
	uint32_t read_addr;
	uint32_t val_mask;

	const struct rte_mce_xstats_name_off *str_list;
	uint16_t list_num;
};
#define XSTAT_M_ENTRY(NAME, STRUCT_FIELD, REG, HI_EN, HI_OFF) \
    { .name = NAME, .offset = offsetof(struct mce_hw_mac_stats, STRUCT_FIELD), \
      .reg_base = REG, .hi_addr_en = HI_EN, .hi_off = HI_OFF }
#define XSTAT_E_ENTRY(NAME, STRUCT_FIELD, REG, HI_EN, HI_OFF) \
    { .name = NAME, .offset = offsetof(struct mce_hw_stats, STRUCT_FIELD), \
      .reg_base = REG, .hi_addr_en = HI_EN, .hi_off = HI_OFF }
#define XSTATS_EX_ENTRY(NAME, STRUCT_FIELD, CMD_SEL) \
    { .name = NAME, .offset = offsetof(struct mce_hw_stats, STRUCT_FIELD), \
      .cmd_sel = CMD_SEL, .hi_addr_en = false, .hi_off = 0 }
static const struct rte_mce_xstats_name_off rte_mce_rx_ex_stats_str[] = {
	XSTATS_EX_ENTRY("rxtrans_pkt_drop_num", rx_trans_drop, 0 << 24),
#if 0
	XSTATS_EX_ENTRY("rxtrans_pkt_in_num", rx_trans_in, 1 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_out_num", rx_trans_out, 2 << 24),
#endif
	XSTATS_EX_ENTRY("rxtrans_other_err_num",  rx_other_err, 3 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_crc_err_num", rx_crc_err, 4 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_nosym_err_num", rx_nosym_err, 5 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_undersize_err_num", rx_usize_err, 6 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_oversize_err_num", rx_osize_err, 7 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_len_err_num", rx_len_err, 8 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_wpi_err_num", rx_wpi_err, 9 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_magic_err_num", rx_magic_err, 10 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_unmatch_da_err_num", rx_mdmac_err, 11 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_slen_err_num", rx_slen_err, 12 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_glen_err_num", rx_glen_err, 13 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_frag_num", rx_frag_pkts, 14 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_len_except_num", rx_len_exp_num, 15 << 24),
#if 0
	XSTATS_EX_ENTRY("rxtrans_pkt_sop_num", rx_pkt_sop_num, 16 << 24),
	XSTATS_EX_ENTRY("rxtrans_pkt_eop_num", rx_pkt_eop_num, 17 << 24),
	XSTATS_EX_ENTRY("rxtrans_sop_num", rx_sop_num, 18 << 24),
	XSTATS_EX_ENTRY("rxtrans_eop_num", rx_eop_num, 19 << 24),
	XSTATS_EX_ENTRY("rxtrans_wpi_status", rx_wpi_state, 20 << 24),
#endif
	XSTATS_EX_ENTRY("rxtrans_pri0_pkt_drop_num", rx_pfc_pri0_drop, 24 << 24),
	XSTATS_EX_ENTRY("rxtrans_pri1_pkt_drop_num", rx_pfc_pri1_drop, 25 << 24),
	XSTATS_EX_ENTRY("rxtrans_pri2_pkt_drop_num", rx_pfc_pri2_drop, 26 << 24),
	XSTATS_EX_ENTRY("rxtrans_pri3_pkt_drop_num", rx_pfc_pri3_drop, 27 << 24),
	XSTATS_EX_ENTRY("rxtrans_pri4_pkt_drop_num", rx_pfc_pri4_drop, 28 << 24),
	XSTATS_EX_ENTRY("rxtrans_pri5_pkt_drop_num", rx_pfc_pri5_drop, 29 << 24),
	XSTATS_EX_ENTRY("rxtrans_pri6_pkt_drop_num", rx_pfc_pri6_drop, 30 << 24),
	XSTATS_EX_ENTRY("rxtrans_pri7_pkt_drop_num", rx_pfc_pri7_drop, 31 << 24),
};

static const struct rte_mce_xstats_name_off rte_mce_tx_ex_stats_str[] = {
#if 0
	XSTATS_EX_ENTRY("tx_trans_send_sop", tx_trans_send_sop, 0 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_eop", tx_trans_send_eop, 1 << 24),
	XSTATS_EX_ENTRY("tx_trans_recv_sop", tx_trans_recv_sop, 2 << 24),
	XSTATS_EX_ENTRY("tx_trans_recv_eop", tx_trans_send_eop, 3 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num0", tx_prio0_send_pkts, 4 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num1", tx_prio1_send_pkts, 5 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num2", tx_prio2_send_pkts, 6 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num3", tx_prio3_send_pkts, 7 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num4", tx_prio4_send_pkts, 8 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num5", tx_prio5_send_pkts, 9 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num6", tx_prio6_send_pkts, 10 << 24),
	XSTATS_EX_ENTRY("tx_trans_send_pkt_num7", tx_prio7_send_pkts, 11 << 24),
	XSTATS_EX_ENTRY("tx_trans_port_tx_status_reg_num", , 12 << 24),
	XSTATS_EX_ENTRY("tx_trans_port_tx_timestamp_hreg", tx_timestap_hreg, 13 << 24),
	XSTATS_EX_ENTRY("tx_trans_port_tx_timestamp_lreg", tx_timestap_lreg, 14 << 24),
	XSTATS_EX_ENTRY("tx_trans_port_tx_timestamp_val",  tx_timestap_val, 15 << 24),
	XSTATS_EX_ENTRY("tx_trans_len_mon", len_mon_expect, 17 << 24),
	XSTATS_EX_ENTRY("tx_trans_lerr_pkt_num,无sop导致的长度错误", tx_non_sop_len_err, 18 << 24),
	XSTATS_EX_ENTRY("tx_trans_pkt_len_max,锁存最大包长度", tx_max_lock_len, 19 << 24),
	XSTATS_EX_ENTRY("tx_trans_fsm_cnt_max,锁存读操作最大次数", tx_max_len_lock_cnt, 20 << 24),
	XSTATS_EX_ENTRY("tx_trans_len_is_zero", tx_length_is_zero, 21 << 24),
#endif
	XSTATS_EX_ENTRY("pause xon2xoff", tx_pause_xon2xof, 23 << 24),
	XSTATS_EX_ENTRY("pfc-pri0 xon2xoff", tx_pfc_pri0_xon2xoff, 24 << 24),
	XSTATS_EX_ENTRY("pfc-pri1 xon2xoff", tx_pfc_pri1_xon2xoff, 25 << 24),
	XSTATS_EX_ENTRY("pfc-pri2 xon2xoff", tx_pfc_pri2_xon2xoff, 26 << 24),
	XSTATS_EX_ENTRY("pfc-pri3 xon2xoff", tx_pfc_pri3_xon2xoff, 27 << 24),
	XSTATS_EX_ENTRY("pfc-pri4 xon2xoff", tx_pfc_pri4_xon2xoff, 28 << 24),
	XSTATS_EX_ENTRY("pfc-pri5 xon2xoff", tx_pfc_pri5_xon2xoff, 29 << 24),
	XSTATS_EX_ENTRY("pfc-pri6 xon2xoff", tx_pfc_pri6_xon2xoff, 30 << 24),
	XSTATS_EX_ENTRY("pfc-pri7 xon2xoff", tx_pfc_pri7_xon2xoff, 31 << 24),
};

static const struct mce_bus_count_reg mce_bus_info[] = {
	{ MCE_RX_TRANS_BUS, MCE_RX_TRANS_READ, GENMASK_U32(31, 24), rte_mce_rx_ex_stats_str, RTE_DIM(rte_mce_rx_ex_stats_str) },
	{ MCE_TX_TRANS_BUS, MCE_TX_TRANS_READ, GENMASK_U32(31, 24), rte_mce_tx_ex_stats_str, RTE_DIM(rte_mce_tx_ex_stats_str) },
};
#define MCE_BUS_INFO_CNT                  RTE_DIM(mce_bus_info)
static const struct rte_mce_xstats_name_off rte_mce_rx_stats_str[] = {
	XSTAT_E_ENTRY("Inval packet len pkts", rx_invalid_len, MCE_ETH_LIP_E_N, false, 0),
	XSTAT_E_ENTRY("invalid tunnel packet len pkts", rx_invalid_tun_len, MCE_ETH_TUN_LIP_E_N, false, 0),
	XSTAT_E_ENTRY("invalid vlan pkts", rx_vlan_hdr_num_err, MCE_ETH_IVLAN_E_N, false, 0),
	XSTAT_E_ENTRY("rx sctp_cksum_err", rx_sctp_cksum_err, MCE_ETH_RX_SCTP_CKSUM_E_N, false, 0),
	XSTAT_E_ENTRY("rx l4_cksum err", rx_l4_cksum_err, MCE_ETH_RX_L4_CKSUM_E_N, false, 0),
	XSTAT_E_ENTRY("rx ipv4 len err", rx_ipv4_len_err, MCE_ETH_IP_LEN_E_N, false, 0),
	XSTAT_E_ENTRY("rx ipv4 hdr err", rx_ipv4_hdr_err, MCE_ETH_IP_HDR_L_E_N, false, 0),
	XSTAT_E_ENTRY("rx 802.3 pkts", rx_802_3_pkts, MCE_ETH_802_3_N, false, 0),
	XSTAT_E_ENTRY("rx ptp pkts", rx_ptp_pkts, MCE_ETH_PTP_N, false, 0),
	XSTAT_E_ENTRY("rx rdma pkts", rx_rdma_pkts, MCE_ETH_RDMA_N, false, 0),
	XSTAT_E_ENTRY("rx gtpu pkts", rx_gtp_u_pkts, MCE_ETH_GTPU_N, false, 0),
	XSTAT_E_ENTRY("rx gtpc pkts", rx_gtp_c_pkts, MCE_ETH_GTPC_N, false, 0),
	XSTAT_E_ENTRY("rx geneve pkts", rx_geneve_pkts, MCE_ETH_GENEVE_N, false, 0),
	XSTAT_E_ENTRY("rx vxlan pkts", rx_vxlan_pkts, MCE_ETH_VXLAN_N, false, 0),
	XSTAT_E_ENTRY("rx gre pkts", rx_gre_pkts, MCE_ETH_GRE_N, false, 0),
	XSTAT_E_ENTRY("rx esp pkts", rx_esp_pkts, MCE_ETH_ESP_N, false, 0),
	XSTAT_E_ENTRY("rx sctp pkts", rx_sctp_pkts, MCE_ETH_SCTP_N, false, 0),
	XSTAT_E_ENTRY("rx tcp sync pkts", rx_tcp_sync_pkts, MCE_ETH_TCPSYNC_N, false, 0),
	XSTAT_E_ENTRY("rx tcp pkts", rx_tcp_pkts, MCE_ETH_TCP_N, false, 0),
	XSTAT_E_ENTRY("rx udp pkts", rx_udp_pkts, MCE_ETH_UDP_N, false, 0),
	XSTAT_E_ENTRY("rx icmpv6 pkts", rx_icmpv6_pkts, MCE_ETH_ICMP6_N, false, 0),
	XSTAT_E_ENTRY("rx icmp pkts", rx_icmpv4_pkts, MCE_ETH_ICMP_N, false, 0),
	XSTAT_E_ENTRY("rx frag pkts", rx_frag_pkts, MCE_ETH_FRAG_N, false, 0),
	XSTAT_E_ENTRY("rx arp pkts", rx_arp_pkts, MCE_ETH_ARP_N, false, 0),
	XSTAT_E_ENTRY("rx ipv6 ext pkts", rx_ipv6_ext_pkts, MCE_ETH_IPV6_EXT_N, false, 0),
	XSTAT_E_ENTRY("rx ipv6 pkts", rx_ipv6_pkts, MCE_ETH_IPV6_N, false, 0),
	XSTAT_E_ENTRY("rx ipv4 pkts", rx_ipv4_pkts, MCE_ETH_IPV4_N, false, 0),
	XSTAT_E_ENTRY("rx 3 layer vlan pkts", rx_3_layer_vlan_pkts, MCE_ETH_LAY3_VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx 2 layer vlan pkts", rx_2_layer_vlan_pkts, MCE_ETH_LAY2_VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx 1 layer vlan pkts", rx_1_layer_vlan_pkts, MCE_ETH_LAY1_VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner sctp pkts", rx_tun_in_sctp_pkts, MCE_ETH_IN_SCTP_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner tcpsync pkts", rx_tun_in_tcp_sync_pkts, MCE_ETH_IN_TCPSYNC_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner tcp pkts", rx_tun_in_tcp_pkts, MCE_ETH_IN_TCP_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner udp pkts", rx_tun_in_udp_pkts, MCE_ETH_IN_UDP_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner icmp6 pkts", rx_tun_in_icmp6_pkts, MCE_ETH_IN_ICMP6_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner icmp pkts", rx_tun_in_icmp4_pkts, MCE_ETH_IN_ICMP_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner frag pkts", rx_tun_in_frag_pkts, MCE_ETH_IN_FRAG_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner arp pkts", rx_tun_in_arp_pkts, MCE_ETH_IN_ARP_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner ipv6 ext pkts", rx_tun_in_ipv6_ext_pkts, MCE_ETH_IN_IPV6_EXT_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner ipv6 pkts", rx_tun_in_ipv6_pkts, MCE_ETH_IN_IPV6_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner ipv4 pkts", rx_tun_in_ipv4_pkts, MCE_ETH_IN_IPV4_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner 3lay vlan pkts", rx_tun_in_3lay_vlan_pkts, MCE_ETH_IN_LAY3_VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner 2lay vlan pkts", rx_tun_in_2lay_vlan_pkts, MCE_ETH_IN_LAY2_VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx tun inner 1lay vlan pkts", rx_tun_in_1lay_vlan_pkts, MCE_ETH_IN_LAY1_VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx l2filter drop pkts", rx_l2filter_drop_pkts, MCE_ETH_L2_FILTER_DROP_N, false, 0),
	XSTAT_E_ENTRY("rx flow direct drop pkts", rx_reta_f_drop_pkts, MCE_ETH_FLOW_DIR_DROP_N, false, 0),
	XSTAT_E_ENTRY("vf_switch_invail_pkts", attr_rx_egress_pkt_drop_num, MCE_ETH_FWD_VEB_DROP, false, 0),
	XSTAT_E_ENTRY("rx bigger than mtu drop", rx_mtu_drop, MCE_ETH_RX_MTU_LIMIT_DROP_N, false, 0),
	XSTAT_E_ENTRY("rx strip vlan pkts", rx_strip_vlan_num, MCE_ETH_STRIP_VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx_strip_3vlan_num", rx_strip_3vlan_num, MCE_ETH_STRIP_3VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx_strip_2vlan_num", rx_strip_2vlan_num, MCE_ETH_STRIP_2VLAN_N, false, 0),
	XSTAT_E_ENTRY("rx_strip_1vlan_num", rx_strip_1vlan_num, MCE_ETH_STRIP_1VLAN_N, false, 0),
	XSTAT_E_ENTRY("tx_anti_smac_drop", tx_anti_smac_drop, MCE_ANTISPOOF_SMAC_DROP_LO, true, -0x20),
	XSTAT_E_ENTRY("tx_anti_dmac_drop", tx_anti_dmac_drop, MCE_ANTISPOOF_DMAC_DROP_LO, true, -0x20),
	XSTAT_E_ENTRY("tx antispoof dmac_drop", tx_anti_vlan_drop, MCE_ANTISPOOF_DMAC_DROP_LO, true, -0x20),
	XSTAT_E_ENTRY("rx dmac_filter drop", rx_dmac_f_drop, MCE_L2_DMAC_F_DROP_CNT, true, -0x20),
	XSTAT_E_ENTRY("rx vlan filter drop", rx_vlan_f_drop, MCE_L2_VLAN_F_DROP_CNT, true, -0x20),
	XSTAT_E_ENTRY("tx_tso_pkts", tx_tso_pkts, 0, false, 0),
};
static const struct rte_mce_xstats_name_off rte_mce_mac_xstats[] = {
	XSTAT_M_ENTRY("rx_crc_errors", rx_fcs_err, MCE_M_RX_FCS_ERR, false, 0),
	XSTAT_M_ENTRY("rx_bad_pkts", rx_bad_pkts, MCE_M_RX_BFRMB, true, 0x4c),
	XSTAT_M_ENTRY("rx_bytes", rx_good_bad_bytes, MCE_M_RX_GBOCTGB, true, 0x48),
	XSTAT_M_ENTRY("rx_packets", rx_good_bad_pkts, MCE_M_RX_GBFRMB, true, 0x48),
	XSTAT_M_ENTRY("rx_undersize_pkts", rx_undersize_err, MCE_M_RX_USIZECB, false, 0),
	XSTAT_M_ENTRY("rx_oversize_pkts", rx_oversize_err, MCE_M_RX_OSIZE_FRMB, false, 0),
	XSTAT_M_ENTRY("rx_jabber_errors", rx_jabber_err, MCE_M_RX_JABBER_FRMB, false, 0),
	XSTAT_M_ENTRY("rx_crc_errors_small_packets", rx_runt_err, MCE_M_RX_RUNTERB, false, 0),
	XSTAT_M_ENTRY("rx_mac_discard", rx_discard_pkts, MCE_M_RX_DISCARD, false, 0),
	XSTAT_M_ENTRY("rx_pause_packets", rx_pause_pkts, MCE_M_RX_PAUSE_FRAMS, false, 0),
	XSTAT_M_ENTRY("rx_vlan_packets", rx_vlan_pkts, MCE_M_RX_VLAN_FRAMB, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio0_pkt", rx_pfc_pri0_pkts, MCE_M_RX_PFC_PRI0_NUM, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio1_pkt", rx_pfc_pri1_pkts, MCE_M_RX_PFC_PRI1_NUM, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio2_pkt", rx_pfc_pri2_pkts, MCE_M_RX_PFC_PRI2_NUM, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio3_pkt", rx_pfc_pri3_pkts, MCE_M_RX_PFC_PRI3_NUM, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio4_pkt", rx_pfc_pri4_pkts, MCE_M_RX_PFC_PRI4_NUM, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio5_pkt", rx_pfc_pri5_pkts, MCE_M_RX_PFC_PRI5_NUM, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio6_pkt", rx_pfc_pri6_pkts, MCE_M_RX_PFC_PRI6_NUM, false, 0),
	XSTAT_M_ENTRY("rx_pfc_prio7_pkt", rx_pfc_pri7_pkts, MCE_M_RX_PFC_PRI7_NUM, false, 0),
	XSTAT_M_ENTRY("rx_unicast_packets", rx_unicast_pkts, MCE_M_RX_GUCASTB, true, 0x4c),
	XSTAT_M_ENTRY("rx_multicast_packets", rx_multicase_pkts, MCE_M_RX_GMCASTB, true, 0x4c),
	XSTAT_M_ENTRY("rx_broadcast_packets", rx_broadcast_pkts, MCE_M_RX_GBCASTB, true, 0x4c),
	XSTAT_M_ENTRY("rx_64_byte_packets", rx_64octes_pkts, MCE_M_RX_64_BYTESB, true, 0x44),
	XSTAT_M_ENTRY("rx_65_to_127_byte_packets", rx_65to127_octes_pkts, MCE_M_RX_65TO127_BYTESB, true, 0x44),
	XSTAT_M_ENTRY("rx_128_to_255_byte_packets", rx_128to255_octes_pkts, MCE_M_RX_128TO255_BYTESB, true, 0x44),
	XSTAT_M_ENTRY("rx_256_to_511_byte_packets", rx_256to511_octes_pkts, MCE_M_RX_256TO511_BYTESB, true, 0x44),
	XSTAT_M_ENTRY("rx_512_to_1023_byte_packets", rx_512to1023_octes_pkts, MCE_M_RX_512TO1023_BYTESB, true, 0x44),
	XSTAT_M_ENTRY("rx_1024_to_1518_byte_packets", rx_1024to1518_octes_pkts, MCE_M_RX_1024TO1518_BYTESB, true, -0x40),
	XSTAT_M_ENTRY("rx_1519_to_max_byte_packets", rx_1519tomax_octes_pkts, MCE_M_RX_1519TOMAX_BYTESB, true, -0x40),
	XSTAT_M_ENTRY("tx_packets", tx_good_pkts, MCE_M_TX_GFRAMSB, true, 0x28),
	XSTAT_M_ENTRY("tx_bytes", tx_good_bytes, MCE_M_TX_GOCTGB, true, 0x40),
	XSTAT_M_ENTRY("tx_bad_pkts", tx_bad_pkts, MCE_M_TX_BFRMB, true, 0x40),
	XSTAT_M_ENTRY("tx_oversize_err", tx_oversize_err, MCE_M_TX_OSIZE_FRMB, false, 0),
	XSTAT_M_ENTRY("tx_jabber_err", tx_jabber_err, MCE_M_TX_JABBER_FRMB, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio0_pkt", tx_pfc_pri0_pkts, MCE_M_TX_PFC_PRI0_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio1_pkt", tx_pfc_pri1_pkts, MCE_M_TX_PFC_PRI1_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio2_pkt", tx_pfc_pri2_pkts, MCE_M_TX_PFC_PRI2_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio3_pkt", tx_pfc_pri3_pkts, MCE_M_TX_PFC_PRI3_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio4_pkt", tx_pfc_pri4_pkts, MCE_M_TX_PFC_PRI4_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio5_pkt", tx_pfc_pri5_pkts, MCE_M_TX_PFC_PRI5_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio6_pkt", tx_pfc_pri6_pkts, MCE_M_TX_PFC_PRI6_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pfc_prio7_pkt", tx_pfc_pri7_pkts, MCE_M_TX_PFC_PRI7_NUM, false, 0),
	XSTAT_M_ENTRY("tx_pause_packets", tx_pause_pkts, MCE_M_TX_PAUSE_FRAMS, false, 0),
	XSTAT_M_ENTRY("tx_vlan_packets", tx_vlan_pkts, MCE_M_TX_VLAN_FRAMB, false, 0),
	XSTAT_M_ENTRY("tx_unicast_packets", tx_unicast_pkts, MCE_M_TX_GUCASTB, true, 0x40),
	XSTAT_M_ENTRY("tx_multicast_packets", tx_multicase_pkts, MCE_M_TX_GMCASTB, true, 0x40),
	XSTAT_M_ENTRY("tx_broadcast_packets", tx_broadcast_pkts, MCE_M_TX_GBCASTB, true, 0x40),
	XSTAT_M_ENTRY("tx_64_byte_packets", tx_64octes_pkts, MCE_M_TX_64_BYTESB, true, 0x40),
	XSTAT_M_ENTRY("tx_65_to_127_byte_packets", tx_65to127_octes_pkts, MCE_M_TX_65TO127_BYTESB, true, 0x40),
	XSTAT_M_ENTRY("tx_128_to_255_byte_packets", tx_128to255_octes_pkts, MCE_M_TX_128TO255_BYTESB, true, 0x40),
	XSTAT_M_ENTRY("tx_256_to_511_byte_packets", tx_256to511_octes_pkts, MCE_M_TX_256TO511_BYTESB, true, 0x40),
	XSTAT_M_ENTRY("tx_512_to_1023_byte_packets", tx_512to1023_octes_pkts, MCE_M_TX_512TO1023_BYTESB, true, 0x40),
	XSTAT_M_ENTRY("tx_1024_to_1518_byte_packets", tx_1024to1518_octes_pkts, MCE_M_TX_1024TO1518_BYTESB, true, 0x40),
	XSTAT_M_ENTRY("tx_1519_to_max_byte_packets", tx_1519tomax_octes_pkts, MCE_M_TX_1519TOMAX_BYTESB, true, 0x40),
};
#define MCE_NB_RX_HW_STATS     (RTE_DIM(rte_mce_rx_stats_str))
#define MCE_NB_MAC_HW_STATS (RTE_DIM(rte_mce_mac_xstats))
#define MCE_NB_RX_EX_STATS     (RTE_DIM(rte_mce_rx_ex_stats_str))
#define MCE_NB_TX_EX_STATS     (RTE_DIM(rte_mce_tx_ex_stats_str))

static uint32_t mce_dev_cal_xstats_num(void)
{
	uint32_t cnt = MCE_NB_RX_HW_STATS + MCE_NB_MAC_HW_STATS;

	cnt += MCE_NB_RX_EX_STATS + MCE_NB_TX_EX_STATS;

	return cnt;
}

#if RTE_VERSION_NUM(16, 7, 0, 0) <= RTE_VERSION
static int mce_dev_xstats_get_names(__rte_unused struct rte_eth_dev *dev,
				    struct rte_eth_xstat_name *xstats_names,
				    __rte_unused unsigned int size)
{
	uint32_t xstats_cnt = mce_dev_cal_xstats_num();
	uint32_t i, count = 0;

	if (xstats_names != NULL) {
		for (i = 0; i < MCE_NB_RX_HW_STATS; i++) {
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
			strlcpy(xstats_names[count].name,
				rte_mce_rx_stats_str[i].name,
				sizeof(xstats_names[count].name));
#else
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name), "%s",
				 rte_mce_rx_stats_str[i].name);
#endif
			count++;
		}
		for (i = 0; i < MCE_NB_RX_EX_STATS; i++) {
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
			strlcpy(xstats_names[count].name,
					rte_mce_rx_ex_stats_str[i].name,
					sizeof(xstats_names[count].name));
#else
			snprintf(xstats_names[count].name,
					sizeof(xstats_names[count].name), "%s",
					rte_mce_rx_ex_stats_str[i].name);
#endif
			count++;
		}
		for (i = 0; i < MCE_NB_TX_EX_STATS; i++) {
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
			strlcpy(xstats_names[count].name,
					rte_mce_tx_ex_stats_str[i].name,
					sizeof(xstats_names[count].name));
#else
			snprintf(xstats_names[count].name,
					sizeof(xstats_names[count].name), "%s",
					rte_mce_tx_ex_stats_str[i].name);
#endif
			count++;
		}
		for (i = 0; i < MCE_NB_MAC_HW_STATS; i++) {
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
			strlcpy(xstats_names[count].name,
					rte_mce_mac_xstats[i].name,
					sizeof(xstats_names[count].name));
#else
			snprintf(xstats_names[count].name,
					sizeof(xstats_names[count].name), "%s",
					rte_mce_mac_xstats[i].name);
#endif
			count++;
		}
	}

	return xstats_cnt;
}
#endif

static inline void mce_store_hw_stats(void *stats, uint32_t offset,
				      uint64_t val)
{
	*(uint64_t *)(((char *)stats) + offset) = val;
}

#define MCE_GET_E_HW_COUNT(stats, offset) \
	((uint64_t *)(((char *)stats) + (offset)))
#define MCE_ADD_INCL_COUNT(stats, offset, val) \
	((*(MCE_GET_E_HW_COUNT(stats, (offset)))) += val)

static inline void mce_update_eth_stats_32bit(struct mce_hw_stats *new,
					      struct mce_hw_stats *old,
					      uint32_t offset, uint32_t val)
{
	uint64_t *last_count = NULL;

	last_count = MCE_GET_E_HW_COUNT(old, offset);
	if (val >= *last_count)
		MCE_ADD_INCL_COUNT(new, offset, val - (*last_count));
	else
		MCE_ADD_INCL_COUNT(new, offset, val + UINT32_MAX);

	*last_count = val;
}

static inline void mce_update_eth_stats_64bit(struct mce_hw_stats *new,
					      struct mce_hw_stats *old,
					      uint32_t offset, uint64_t val)
{
	uint64_t *last_count = NULL;

	last_count = MCE_GET_E_HW_COUNT(old, offset);
	if (val >= *last_count)
		MCE_ADD_INCL_COUNT(new, offset, val - (*last_count));
	else
		MCE_ADD_INCL_COUNT(new, offset, val + UINT64_MAX);

	*last_count = val;
}

static void mce_get_eth_info(struct mce_hw *hw, struct mce_hw_stats *new,
			     struct mce_hw_stats *old,
			     const struct rte_mce_xstats_name_off *ptr)
{
	uint64_t count = 0;
	uint32_t offset;
	uint64_t hi_reg;

	if (ptr->reg_base) {
		count = MCE_E_REG_READ(hw, ptr->reg_base);
		if (ptr->hi_addr_en) {
			offset = ptr->reg_base + ptr->hi_off;
			hi_reg = MCE_E_REG_READ(hw, offset);
			count += (hi_reg << 32);
			mce_update_eth_stats_64bit(new, old, ptr->offset,
						   count);
		} else
			mce_update_eth_stats_32bit(new, old, ptr->offset,
						   count);
	}
}

static void
mce_get_stats_bus_info(struct mce_hw *hw, const struct mce_bus_count_reg *reg,
		       struct mce_hw_stats *new, struct mce_hw_stats *old,
		       const struct rte_mce_xstats_name_off *ptr)
{
	uint64_t count = 0;

	modify32(hw, reg->ctrl_reg, reg->val_mask, ptr->cmd_sel);
	count = MCE_E_REG_READ(hw, reg->read_addr);
	mce_update_eth_stats_32bit(new, old, ptr->offset, count);
}

static void mce_get_mmc_info(struct mce_hw *hw, void *stats,
			     const struct rte_mce_xstats_name_off *ptr)
{
	uint64_t count = 0;
	uint32_t offset;
	uint64_t hi_reg;

	if (ptr->reg_base) {
		count = MCE_E_REG_READ(hw, ptr->reg_base);
		if (ptr->hi_addr_en) {
			offset = ptr->reg_base + ptr->hi_off;
			hi_reg = MCE_E_REG_READ(hw, offset);
			count += (hi_reg << 32);
		}
		mce_store_hw_stats((void *)stats, ptr->offset, count);
	}
}

#ifdef RNPCE_FD_DEBUG
struct mce_reg_info {
	uint8_t log_info[32];
	uint32_t cond;
	bool verbose_en;
	uint16_t offset;
};

struct mce_reg_info mce_tso_debug3[] = {
	{ "ip_len/in_ip_len", GENMASK_U32(8, 0), true, 0 },
	{ "ip_mac_len/in_mac_len", GENMASK_U32(15, 9), true, 9 },
	{ "out_ip_len", GENMASK_U32(24, 16), true, 16 },
	{ "out_mac_len", GENMASK_U32(31, 25), true, 25 }
};

struct mce_reg_info mce_tso_debug4[] = {
	{ "mdy_tunnel_len", GENMASK_U32(7, 0), true, 0 },
	{ "cmd_l4_len", GENMASK_U32(15, 8), true, 8 },
	{ "mss", GENMASK_U32(31, 16), true, 16 }
};

struct mce_reg_info mce_tso_debug2[] = {
	{ "cmd_l3_ver", GENMASK_U32(1, 0), true, 0 },
	{ "cmd_l4_type", GENMASK_U32(7, 4), true, 4 },
	{ "cmd_out_l3_ver", GENMASK_U32(9, 8), true, 8 },
	{ "cmd_out_l4_type", GENMASK_U32(15, 12), true, 12 },
	{ "tunnel_type", GENMASK_U32(19, 16), true, 16 },
};

struct mce_reg_info mce_edtn_debug[] = {
	{ "channel_num", RTE_BIT32(0), true, 0 },
	{ "pack modulus len", GENMASK_U32(6, 1), true, 1 },
	{ "in_edtn_num", GENMASK_U32(14, 7), true, 8 },
	{ "out_edtn_num", GENMASK_U32(23, 16), true, 16 },
};

struct mce_reg_info mce_fd_profileid_debug[] = {
	{ "fsm_cnt", GENMASK_U32(1, 0), true, 0 },
	{ "fsm_nt", GENMASK_U32(3, 2), true, 2 },
	{ "entry_match", GENMASK_U32(4, 4), true, 4 },
	{ "entry_end", GENMASK_U32(5, 5), true, 5 },
	{ "entry_timeout", GENMASK_U32(6, 6), true, 6 },
	{ "pkt_port_ena_r", GENMASK_U32(7, 7), true, 7 },
	{ "pkt_ipv6_ena_r", GENMASK_U32(8, 8), true, 8 },
	{ "pkt_port_r", GENMASK_U32(15, 9), true, 9 },
	{ "pkt_profile_r", GENMASK_U32(21, 16), true, 16 },
};

struct mce_reg_info mce_fd_match_debug[] = {
	{ "fd_match_cnt", GENMASK_U32(7, 0), true, 0 },
	{ "fd_match_loc", GENMASK_U32(20, 8), true, 8 },
};

static void mce_dump_logs(struct mce_hw *hw, struct mce_reg_info *data_base,
			  uint16_t item_num, uint32_t dump_reg)
{
	uint32_t value = 0;
	uint16_t i = 0;

	value = MCE_E_REG_READ(hw, dump_reg);
	for (i = 0; i < item_num; i++) {
		if (data_base[i].cond & value) {
			if (data_base[i].verbose_en)
				printf("%s %d\n", data_base[i].log_info,
				       (value & data_base[i].cond) >>
					       data_base[i].offset);
			else
				printf("%s\n", data_base[i].log_info);
		}
	}
}

static uint32_t mce_fd_debug_cmd(struct mce_hw *hw, uint32_t cmd)
{
	uint32_t ctrl = 0;

	ctrl = MCE_E_REG_READ(hw, 0xf0000);
	ctrl &= ~GENMASK_U32(31, 27);
	ctrl |= cmd << 27;
	rte_io_wmb();
	MCE_E_REG_WRITE(hw, 0xf0000, ctrl);

	return 0;
}

__maybe_unused static void mce_rx_fd_show(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	mce_fd_debug_cmd(hw, 0 << 1);
	mce_dump_logs(hw, mce_fd_profileid_debug,
		      RTE_DIM(mce_fd_profileid_debug), 0xf0004);
	mce_fd_debug_cmd(hw, 1 << 1);
	printf("debug fd status hash 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 2 << 1);
	printf("debug fd status sign_hash 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 3 << 1);
	printf("match 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_dump_logs(hw, mce_fd_match_debug, RTE_DIM(mce_fd_match_debug),
		      0xf0004);
	mce_fd_debug_cmd(hw, 6 << 1);
	printf("debug fd input_data0 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 7 << 1);
	printf("debug fd input_data1 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 8 << 1);
	printf("debug fd input_data2 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 9 << 1);
	printf("debug fd input_data3 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 10 << 1);
	printf("debug fd input_data4 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 11 << 1);
	printf("debug fd input_data5 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 12 << 1);
	printf("debug fd input_data6 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 13 << 1);
	printf("debug fd input_data7 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 14 << 1);
	printf("debug fd input_data8 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 15 << 1);
	printf("debug fd input_data9 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 16 << 1);
	printf("debug fd input_data10 0x%.2x\n", MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 6 << 1 | 1);
	printf("debug fd_mask input_data0 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 7 << 1 | 1);
	printf("debug fd_mask input_data1 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 8 << 1 | 1);
	printf("debug fd_mask input_data2 0x%.2x \n ",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 9 << 1 | 1);
	printf("debug fd_mask input_data3 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 10 << 1 | 1);
	printf("debug fd_mask input_data4 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 11 << 1 | 1);
	printf("debug fd_mask input_data5 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 12 << 1 | 1);
	printf("debug fd_mask input_data6 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 13 << 1 | 1);
	printf("debug fd_mask input_data7 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 14 << 1 | 1);
	printf("debug fd_mask input_data8 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 15 << 1 | 1);
	printf("debug fd_mask input_data9 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
	mce_fd_debug_cmd(hw, 16 << 1 | 1);
	printf("debug fd_mask input_data10 0x%.2x\n",
	       MCE_E_REG_READ(hw, 0xf0004));
}

static uint32_t mce_switch_debug_cmd(struct mce_hw *hw, uint32_t cmd)
{
	uint32_t ctrl = 0;

	ctrl = MCE_E_REG_READ(hw, 0x88038);
	ctrl &= ~GENMASK_U32(25, 16);
	ctrl |= cmd;
	MCE_E_REG_WRITE(hw, 0x88038, ctrl);

	return 0;
}

__maybe_unused static int mce_debug_switch(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	int i = 0;

	mce_switch_debug_cmd(hw, 0 << 24);
	printf("switch eswitch[0] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));
	mce_switch_debug_cmd(hw, 1 << 24);
	printf("switch eswitch[1] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));
	mce_switch_debug_cmd(hw, 2 << 24);
	printf("switch eswitch[2] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));
	mce_switch_debug_cmd(hw, 3 << 24);
	printf("switch eswitch[2] match 0x%.2x\n", MCE_E_REG_READ(hw, 0x93900));

	for (i = 0; i < 16; i++) {
		mce_switch_debug_cmd(hw, i << 20);
		printf("switch legdy[%d] up match 0x%.2x\n", i,
		       MCE_E_REG_READ(hw, 0x93904));
	}
	for (i = 0; i < 16; i++) {
		mce_switch_debug_cmd(hw, i << 16);
		printf("switch legdy[%d] down match 0x%.2x\n", i,
		       MCE_E_REG_READ(hw, 0x93908));
	}

	return 0;
}
#endif

/**
 * @brief Read hardware statistics counters into the driver's stat structures.
 *
 * Populates `mce_hw_stats` and related counters by reading multiple HW
 * registers and bus counters. Used for both periodic updates and xstats reads.
 *
 * @param vport Pointer to the virtual port whose hardware stats to read.
 */
static void mce_get_hw_stats(struct mce_vport *vport)
{
	struct mce_hw_mac_stats *mac_stats = &vport->hw_mac_stats;
	struct mce_hw_stats *old = &vport->hw_stats_old;
	struct mce_hw_stats *stats = &vport->hw_stats;
	struct mce_hw_stats *new = &vport->hw_stats;
	struct mce_hw *hw = vport->hw;
	const struct rte_mce_xstats_name_off *ptr;
	const struct mce_bus_count_reg *reg;
	uint16_t i, j;

	for (i = 0; i < MCE_NB_RX_HW_STATS; i++) {
		ptr = &rte_mce_rx_stats_str[i];
		mce_get_eth_info(hw, new, old, ptr);
	}
	for (j = 0; j < MCE_BUS_INFO_CNT; j++) {
		reg = &mce_bus_info[j];
		for (i = 0; i < reg->list_num; i++) {
			ptr = &reg->str_list[i];
			mce_get_stats_bus_info(hw, reg, new, old, ptr);
		}
	}
	stats->rx_bad_pkts = stats->rx_crc_err + stats->rx_invalid_len +
			     stats->rx_vlan_hdr_num_err +
			     stats->rx_invalid_tun_len +
			     stats->rx_ipv4_len_err + stats->rx_ipv4_hdr_err;
	for (i = 0; i < MCE_NB_MAC_HW_STATS; i++) {
		ptr = &rte_mce_mac_xstats[i];
		mce_get_mmc_info(hw, mac_stats, ptr);
	}
}

#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
static int mce_dev_xstats_get(struct rte_eth_dev *dev,
			      struct rte_eth_xstats *xstats,
			      unsigned int n __rte_unused)
#else
static int mce_dev_xstats_get(struct rte_eth_dev *dev,
			      struct rte_eth_xstat *xstats,
			      unsigned int n __rte_unused)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw_mac_stats *hw_mac_stats = &vport->hw_mac_stats;
	struct mce_hw_stats *hw_stats = &vport->hw_stats;
	uint32_t count = 0;
	uint8_t i;

#if RTE_VERSION_NUM(16, 4, 0, 0) < RTE_VERSION
	if (xstats != NULL) {
#else
	if (xstats != NULL && n) {
#endif
		mce_get_hw_stats(vport);
		for (i = 0; i < MCE_NB_RX_HW_STATS; i++) {
			xstats[count].value =
				*(uint64_t *)(((char *)hw_stats) +
					      rte_mce_rx_stats_str[i].offset);
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[count].id = count;
#endif
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[count].name, sizeof(xstats[count].name),
				 "%s", rte_mce_rx_stats_str[i].name);
#endif
			count++;
		}
		for (i = 0; i < MCE_NB_RX_EX_STATS; i++) {
			xstats[count].value =
				*(uint64_t *)(((char *)hw_stats) +
						rte_mce_rx_ex_stats_str[i]
						.offset);
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[count].id = count;
#endif
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[count].name,
					sizeof(xstats[count].name), "%s",
					rte_mce_rx_ex_stats_str[i].name);
#endif
			count++;
		}
		for (i = 0; i < MCE_NB_TX_EX_STATS; i++) {
			xstats[count].value =
				*(uint64_t *)(((char *)hw_stats) +
						rte_mce_tx_ex_stats_str[i]
						.offset);
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[count].id = count;
#endif
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[count].name,
					sizeof(xstats[count].name), "%s",
					rte_mce_tx_ex_stats_str[i].name);
#endif
			count++;
		}
		for (i = 0; i < MCE_NB_MAC_HW_STATS; i++) {
			xstats[count].value =
				*(uint64_t *)(((char *)hw_mac_stats) +
						rte_mce_mac_xstats[i]
						.offset);
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[count].id = count;
#endif
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[count].name,
					sizeof(xstats[count].name), "%s",
					rte_mce_mac_xstats[i].name);
#endif
			count++;
		}
	} else {
			return mce_dev_cal_xstats_num();
	}

	return count;
}

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
static const uint32_t *
#if RTE_VERSION_NUM(24, 3, 0, 0) <= RTE_VERSION
mce_dev_supported_ptypes_get(struct rte_eth_dev *dev __rte_unused,
			     size_t *no_of_elements __rte_unused)
#else
mce_dev_supported_ptypes_get(struct rte_eth_dev *dev __rte_unused)
#endif
{
	static const uint32_t ptypes[] = {
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L2_ETHER_TIMESYNC,
		RTE_PTYPE_L2_ETHER_ARP,
		RTE_PTYPE_L2_ETHER_MPLS,
		RTE_PTYPE_L2_ETHER_NSH,
		RTE_PTYPE_L2_ETHER_VLAN,
		RTE_PTYPE_L2_ETHER_QINQ,
		RTE_PTYPE_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_L4_FRAG,
		RTE_PTYPE_L4_ICMP,
		RTE_PTYPE_L4_NONFRAG,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_TUNNEL_VXLAN,
		RTE_PTYPE_TUNNEL_GENEVE,
		RTE_PTYPE_TUNNEL_NVGRE,
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		RTE_PTYPE_TUNNEL_GTPC,
		RTE_PTYPE_TUNNEL_GTPU,
		RTE_PTYPE_TUNNEL_ESP,
#endif
		RTE_PTYPE_INNER_L2_ETHER,
		RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN,
		RTE_PTYPE_INNER_L4_FRAG,
		RTE_PTYPE_INNER_L4_ICMP,
		RTE_PTYPE_INNER_L4_NONFRAG,
		RTE_PTYPE_INNER_L4_SCTP,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_UNKNOWN,

	};
#if RTE_VERSION_NUM(24, 3, 0, 0) <= RTE_VERSION
	*no_of_elements = RTE_DIM(ptypes);
#endif
	return ptypes;
}
#endif
struct mce_mac_filter *
mce_mac_filter_lookup(struct mce_mac_filter_list *mac_list,
		      struct mce_mac_entry *entry)
{
	struct mce_mac_filter *it;

	TAILQ_FOREACH(it, mac_list, next) {
		if (rte_is_same_ether_addr(&it->mac.mac_addr, &entry->mac_addr))
			return it;
	}

	return NULL;
}

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
static void mce_macaddr_set(struct rte_eth_dev *dev,
			    struct rte_ether_addr *mac_addr)
#else
static int mce_macaddr_set(struct rte_eth_dev *dev,
			   struct rte_ether_addr *mac_addr)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_pf *pf = MCE_DEV_TO_PF(dev);
	struct mce_mac_filter *old_filter;
	struct mce_mac_filter *new_filter;
	struct mce_hw *hw = vport->hw;
	struct mce_mac_entry entry;
	int ret = 0;

	memset(&entry, 0, sizeof(struct mce_mac_entry));
	/* check input mac_addr*/
	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		PMD_DRV_LOG(ERR, "input MAC is invalid unicast address.");
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
		return;
#else
		return -EINVAL;
#endif
	}
	/* default mac address loc is zero */
	rte_ether_addr_copy((struct rte_ether_addr *)&vport->mac_addr,
			    &entry.mac_addr);
	old_filter = mce_mac_filter_lookup(&vport->mac_list, &entry);
	if (old_filter != NULL) {
		if (hw->max_vfs && pf->is_switchdev == 0)
			ret = mce_sw_remove_pf_macaddr(vport, old_filter);
		mce_remove_mac_addr(vport, old_filter);
		rte_free(old_filter);
		if (ret < 0) {
			PMD_DRV_LOG(ERR,
				    "input mac can't find delate location");
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
			return;
#else
			return ret;
#endif
		}
	}
	rte_ether_addr_copy(mac_addr, &entry.mac_addr);
	new_filter =
		rte_zmalloc("mce_mac_filter", sizeof(struct mce_mac_filter), 0);
	if (new_filter == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate memory for MAC Set filter");
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		return -ENOMEM;
#endif /* RTE_VERSION >= 18.05 */
	}
	new_filter->mac = entry;
	if (hw->max_vfs) {
		if (pf->is_switchdev == 0)
			mce_sw_set_pf_macaddr(vport, new_filter);
		mce_set_mac_addr(vport, new_filter);
	} else {
		mce_set_mac_addr(vport, new_filter);
	}
	rte_ether_addr_copy(mac_addr,
			    (struct rte_ether_addr *)&vport->mac_addr);
	TAILQ_INSERT_TAIL(&vport->mac_list, new_filter, next);
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	return 0;
#endif
}
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void mce_macaddr_add(struct rte_eth_dev *dev,
			    struct rte_ether_addr *mac_addr, uint32_t index,
			    __rte_unused uint32_t pool)
#else
static int mce_macaddr_add(struct rte_eth_dev *dev,
			   struct rte_ether_addr *mac_addr, uint32_t index,
			   __rte_unused uint32_t pool)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_mac_filter *filter;
	struct mce_mac_entry entry;

	memset(&entry, 0, sizeof(struct mce_mac_entry));
	/* check input mac_addr */
	if (rte_is_zero_ether_addr(mac_addr)) {
		PMD_DRV_LOG(ERR, "input MAC is invalid MAC address.");
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
		return;
#else
		return -EINVAL;
#endif
	}
	entry.mac_addr = *mac_addr;
	entry.loc = index;
	filter = mce_mac_filter_lookup(&vport->mac_list, &entry);
	if (filter) {
		PMD_DRV_LOG(ERR, "This MAC address has been added.");
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
		return;
#else
		return -EINVAL;
#endif
	}
	filter =
		rte_zmalloc("mce_mac_filter", sizeof(struct mce_mac_filter), 0);
	if (filter == NULL) {
		PMD_DRV_LOG(ERR, "alloc add mac filter failed");
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
		return;
#endif
	}
	filter->mac = entry;
	mce_set_mac_addr(vport, filter);
	TAILQ_INSERT_TAIL(&vport->mac_list, filter, next);
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static void mce_macaddr_remove(struct rte_eth_dev *dev, uint32_t index)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct rte_eth_dev_data *data = dev->data;
	struct mce_mac_filter *filter;
	struct mce_mac_entry entry;

	memset(&entry, 0, sizeof(struct mce_mac_entry));
	entry.mac_addr = data->mac_addrs[index];
	entry.loc = index;
	filter = mce_mac_filter_lookup(&vport->mac_list, &entry);
	if (filter == NULL) {
		PMD_DRV_LOG(ERR, "This MAC address has been removed.");
		return;
	}
	mce_remove_mac_addr(vport, filter);
}

static int mce_dev_set_mc_addr_list(struct rte_eth_dev *dev,
				    struct rte_ether_addr *mc_addr_list,
				    uint32_t nb_mc_addr)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t idx;

	if (nb_mc_addr > vport->attr.max_mcast_addrs) {
		PMD_DRV_LOG(ERR, "set multicast address is over max.");
		return -ENOMEM;
	}
	for (idx = 0; idx < vport->attr.mc_hash_tb_size; idx++) {
		MCE_E_REG_WRITE(hw, MCE_ETH_MULTICAST_HASH(idx), 0);
		vport->mc_hash_table[idx] = 0;
	}

	for (idx = 0; idx < nb_mc_addr; idx++)
		mce_update_mc_hash(vport, &mc_addr_list[idx]);

	return 0;
}

static int mce_vlan_add(struct mce_vport *vport, uint16_t vlan)
{
	struct mce_vlan_filter *filter = NULL;
	struct mce_vlan_entry entry;

	memset(&entry, 0, sizeof(entry));
	entry.vid = vlan;

	filter = mce_vlan_filter_lookup(vport, &entry);
	if (filter) {
		PMD_DRV_LOG(INFO, "vlan already exists in filter table.");
		return 0;
	}
	filter = rte_zmalloc("mce_vlan_filter", sizeof(struct mce_vlan_filter),
			     0);
	if (filter == NULL) {
		PMD_DRV_LOG(ERR, "vlan filter memory alloc failed.");
		return -ENOMEM;
	}
	filter->vlan = entry;
	mce_add_vlan_filter(vport, filter);

	return 0;
}

static int mce_vlan_remove(struct mce_vport *vport, uint16_t vlan)
{
	struct mce_vlan_filter *filter = NULL;
	struct mce_vlan_entry entry;

	memset(&entry, 0, sizeof(entry));
	entry.vid = vlan;

	filter = mce_vlan_filter_lookup(vport, &entry);
	if (filter == NULL) {
		PMD_DRV_LOG(INFO, "vlan has been remove from filter table.");
		return 0;
	}
	mce_remove_vlan_filter(vport, filter);

	return 0;
}

static int mce_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id,
			       int on)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	if (on) {
		ret = mce_vlan_add(vport, vlan_id);
		if (ret < 0) {
			PMD_DRV_LOG(ERR, "Failed to add vlan filter");
			return -EINVAL;
		}
	} else {
		ret = mce_vlan_remove(vport, vlan_id);
		if (ret < 0) {
			PMD_DRV_LOG(ERR, "failed to remove vlan filter.");
			return -EINVAL;
		}
	}

	return 0;
}

static void mce_vlan_strip_setup(struct mce_vport *vport, uint32_t strip_layers)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	uint32_t strip_ctrl;
	int i = 0;

	for (i = 0; i < MCE_MAX_RX_QUEUE; i++) {
		strip_ctrl =
			MCE_E_REG_READ(hw, MCE_PF_QUEUE_VLAN_STRIP_CTRL(i));
		strip_ctrl &= ~MCE_QUEUE_STRIP_MASK;
		strip_ctrl |= strip_layers << MCE_QUEUE_STRIP_S;
		strip_ctrl |= MCE_QUEUE_STRIP_VLAN_EN;
		MCE_E_REG_WRITE(hw, MCE_PF_QUEUE_VLAN_STRIP_CTRL(i),
				strip_ctrl);
	}
}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int mce_vlan_offload_set(struct rte_eth_dev *dev, int mask)
#else
static void mce_vlan_offload_set(struct rte_eth_dev *dev, int mask)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = vport->hw;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_rxmode *rxmode;
#endif
	uint32_t strip_layers = 0;

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	rxmode = &dev->data->dev_conf.rxmode;
#endif
	if (mask & RTE_ETH_VLAN_FILTER_MASK) {
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
#else
		if (dev->data->dev_conf.rxmode.hw_vlan_filter)
#endif
			mce_set_vlan_filter(vport, true);
		else
			mce_set_vlan_filter(vport, false);
	}
	if (mask & RTE_ETH_VLAN_STRIP_MASK) {
		strip_layers = 1;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		if (!(rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP))
#else
		if (!dev->data->dev_conf.rxmode.hw_vlan_strip)
#endif
			strip_layers--;
	}
#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
	if (mask & RTE_ETH_QINQ_STRIP_MASK) {
		strip_layers = 2;
		if (!(rxmode->offloads & RTE_ETH_RX_OFFLOAD_QINQ_STRIP))
			strip_layers--;
	}
#endif
	if (mask & RTE_ETH_VLAN_EXTEND_MASK) {
		uint32_t ctrl = 0;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_EXTEND) {
#else
		if (dev->data->dev_conf.rxmode.hw_vlan_extend) {
#endif /* rte_version >= 17.11 */
			ctrl = MCE_E_REG_READ(hw, MCE_ETH_GLOBAL_L2_F_CTRL);
			ctrl &= ~MCE_G_VLAN_F_SEL_MASK;
			ctrl |= (2 << MCE_G_VLAN_F_SEL_S);
			MCE_E_REG_WRITE(hw, MCE_ETH_GLOBAL_L2_F_CTRL, ctrl);
		} else {
			ctrl = MCE_E_REG_READ(hw, MCE_ETH_GLOBAL_L2_F_CTRL);
			ctrl &= ~MCE_G_VLAN_F_SEL_MASK;
			MCE_E_REG_WRITE(hw, MCE_ETH_GLOBAL_L2_F_CTRL, ctrl);
		}
	}
	mce_vlan_strip_setup(vport, strip_layers);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif /* RTE_VERSION >= 17.11 */
}

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
static int mce_vlan_tpid_set(struct rte_eth_dev *dev,
			     enum rte_vlan_type vlan_type, uint16_t tpid)
#else
static void mce_vlan_tpid_set(struct rte_eth_dev *dev, uint16_t tpid)
#endif
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

#if RTE_VERSION_NUM(16, 4, 0, 0) > RTE_VERSION
	enum rte_vlan_type vlan_type;
	vlan_type = ETH_VLAN_TYPE_OUTER;
#endif
	if (vlan_type == RTE_ETH_VLAN_TYPE_OUTER) {
		/* insert vlan tpid */
		MCE_E_REG_WRITE(hw, MCE_ETH_I_OVLAN_TYPE(1), tpid);
		/* rx vlan strip filter tpid */
		MCE_E_REG_WRITE(hw, MCE_ETH_OUT_VLAN_TYPE(0), tpid);
	} else if (vlan_type == RTE_ETH_VLAN_TYPE_INNER) {
		/* insert vlan tpid */
		MCE_E_REG_WRITE(hw, MCE_ETH_I_OVLAN_TYPE(0), tpid);
		/* rx vlan strip filter tpid */
		MCE_E_REG_WRITE(hw, MCE_ETH_VLAN_TYPE(0), tpid);
	}
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if 0
/*
 * mce_dcb_pfc_enable - Enable priority flow control
 * @dev: pointer to ethernet device
 *
 * Configures the pfc settings for one priority.
 */
int
mce_dcb_pfc_enable(struct rte_eth_dev *dev, struct rte_eth_pfc_conf *pfc_conf)
{

	return 0;
}

static int
mce_dev_get_dcb_info(struct rte_eth_dev *dev,
		       struct rte_eth_dcb_info *dcb_info)
{

	return 0;
}
#endif

static int mce_link_update(struct rte_eth_dev *dev,
			   int wait_to_complete __rte_unused)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct rte_eth_link link = {};

	rte_spinlock_lock(&hw->link_lock);
	memset(&link, 0, sizeof(link));
	mce_update_fw_stat(hw);
	if (hw->fw_stat.stat0.linkup) {
		link.link_duplex = hw->fw_stat.stat0.duplex;
		link.link_speed = speed_unzip(hw->fw_stat.stat0.s_speed);
#if RTE_VERSION_NUM(17, 8, 0, 0) < RTE_VERSION
		link.link_autoneg = hw->fw_stat.stat0.autoneg;
#endif
		link.link_status = hw->fw_stat.stat0.linkup;
#if RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
		link.link_connector = hw->connect_type;
#endif
	}
	rte_spinlock_unlock(&hw->link_lock);

	*dst = link;

	return 0;
}

int mce_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	uint32_t frame_size = mtu + MCE_ETH_OVERHEAD;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t vport_id = vport->attr.vport_id;

	if (frame_size < 64 || frame_size > 16000)
		return -EINVAL;

	if (dev->data->dev_started && !dev->data->scattered_rx &&
	    frame_size + 2 * RTE_VLAN_HLEN >
		    dev->data->min_rx_buf_size - RTE_PKTMBUF_HEADROOM) {
		PMD_INIT_LOG(ERR, "Stop port first.");
		return -EINVAL;
	}
	/* setup mtu limit */
	MCE_E_REG_SET_VAL(hw, MCE_ETH_FWD_ATTR(vport_id), MCE_FWD_MAXLEN,
			  frame_size);
	MCE_E_REG_SET_BITS(hw, MCE_ETH_FWD_ATTR(vport_id), 0,
			   MCE_FWD_LIMIT_LEN_EN);
	return 0;
}

int mce_dev_txq_rate_limit(struct rte_eth_dev *dev,
#if RTE_VERSION_NUM(22, 11, 0, 0) <= RTE_VERSION
			   uint16_t queue_idx, uint32_t tx_rate
#else
			   uint16_t queue_idx, uint16_t tx_rate
#endif
)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint64_t real_rate = 0;
	uint64_t set_rate = 0;
	uint16_t hwrid;

	hwrid = queue_idx;

	if (!tx_rate) {
		mce_set_txq_rate(hw, hwrid, 0);
		return 0;
	}
	set_rate = tx_rate;
	/* we need turn it to bytes/s */
	real_rate = (set_rate * 1000 * 1000) / 8;
	mce_set_txq_rate(hw, hwrid, real_rate);

	return 0;
}

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
static int mce_get_module_info(struct rte_eth_dev *dev,
			       struct rte_eth_dev_module_info *modinfo)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	char diag_supported, rc;
	char module_id = 0;
	struct mce_hw *hw = vport->hw;

	rc = mce_read_sfp_module_eeprom(hw, 0xA0, SFF_MODULE_ID_OFFSET,
			&module_id, 1);
	if (rc || ((uint8_t)module_id) == 0xFF)
		return -EIO;
	rc = mce_read_sfp_module_eeprom(hw, 0xA0, SFF_DIAG_SUPPORT_OFFSET,
			&diag_supported, 1);
	if (!rc) {
		switch (module_id) {
		case SFF_MODULE_ID_SFP:
			modinfo->type = RTE_ETH_MODULE_SFF_8472;
			modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8472_LEN;
			if (!diag_supported)
				modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8436_LEN;
			break;
		case SFF_MODULE_ID_QSFP:
		case SFF_MODULE_ID_QSFP_PLUS:
			modinfo->type = RTE_ETH_MODULE_SFF_8436;
			modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8436_LEN;
			break;
		case SFF_MODULE_ID_QSFP28:
			modinfo->type = RTE_ETH_MODULE_SFF_8636;
			modinfo->eeprom_len = RTE_ETH_MODULE_SFF_8636_LEN;
			break;
		default:
			PMD_DRV_LOG(INFO, "%s: not supported: module_id:0x%x "
					"diag_supported:0x%x\n", __func__,
					module_id, diag_supported);
			return -EOPNOTSUPP;
		}
	}

        return 0;
}

static int mce_get_module_eeprom(struct rte_eth_dev *dev,
				 struct rte_dev_eeprom_info *info)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t datalen = info->length;
	uint32_t length = info->length;
	uint32_t start = info->offset;
	char *data = info->data;
	int rc;

	memset(data, 0, datalen);
	/* Read A0 portion of the EEPROM */
	if (start < RTE_ETH_MODULE_SFF_8436_LEN) {
		if (start + datalen > RTE_ETH_MODULE_SFF_8436_LEN)
			length = RTE_ETH_MODULE_SFF_8436_LEN - start;
		rc = mce_read_sfp_module_eeprom(hw, 0xA0, start, data, length);
		if (rc)
			return rc;
		start += length;
		data += length;
		length = datalen - length;
	}
	/* Read A2 portion of the EEPROM */
	if (length) {
		start -= RTE_ETH_MODULE_SFF_8436_LEN;
		rc = mce_read_sfp_module_eeprom(hw, 0xA2, start, data, length);
	}

	return 0;
}
#endif

#if RTE_VERSION_NUM(22, 3, 0, 0) <= RTE_VERSION
static void mce_sfp_supported_speed_dump(FILE*file,struct mce_hw *hw)
{
	struct phy_speed_ablity sfp_ablity;
	mce_update_fw_stat(hw);

	memset(&sfp_ablity, 0, sizeof(sfp_ablity));

	mce_get_fw_supported_speed(hw, &sfp_ablity);

	fprintf(file,"\tsfp mod-abs:%d tx-fault:%d tx-disable:%d rx-los:%d\n",
		       hw->fw_stat.stat0.sfp_mod_abs,
		       hw->fw_stat.stat0.sfp_fault,
		       hw->fw_stat.stat0.sfp_tx_dis, hw->fw_stat.stat0.sfp_los);
	if (sfp_ablity.sfp_mod_abs) {
		fprintf(file,"\tsfp supported-speed:");
		if (sfp_ablity.speed_100g) {
			fprintf(file,"100G ");
		}
		if (sfp_ablity.speed_40g) {
			fprintf(file,"40G ");
		}
		if (sfp_ablity.speed_25g) {
			fprintf(file,"25G ");
		}
		if (sfp_ablity.speed_10g) {
			fprintf(file,"10G ");
		}
		if (sfp_ablity.speed_1g) {
			fprintf(file,"1G ");
		}
	}
	fprintf(file,"\n");
	fflush(file);
}

static void mce_temp_dump(FILE *file,struct mce_hw *hw)
{
	int voltage = 0;
	signed char temp = 0;

	mce_update_fw_stat(hw);
	temp = (signed char)hw->fw_stat.stat1.temp;
	voltage = mce_soc_ioread32_noshm(hw, MCE_LG_SOC_VOLTAGE_REG);
	fprintf(file, "\ttemperature:%d oC  volatage:%d mV\n", temp, voltage);
}

static int
mce_eth_dev_priv_dump(struct rte_eth_dev *dev, FILE *file)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	if (file == NULL)
		file = stdout;

	mce_temp_dump(file,hw);
	mce_sfp_supported_speed_dump(file,hw);

	fflush(file);
	return 0;
}
#endif

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
static int
mce_fec_get_capa_speed_to_fec(struct mce_hw *hw,
		       struct rte_eth_fec_capa *speed_fec_capa)
{
	unsigned int capa_num = 0;
	struct phy_speed_ablity sfp_cap;

	if (mce_get_fw_supported_speed(hw, &sfp_cap))
		return 0;
	if (sfp_cap.sfp_mod_abs == 0)
		return 0;
	if (sfp_cap.speed_100g) {
		if (speed_fec_capa) {
			speed_fec_capa[capa_num].speed = RTE_ETH_SPEED_NUM_100G;
			speed_fec_capa[capa_num].capa =
				RTE_ETH_FEC_MODE_CAPA_MASK(NOFEC) |
				RTE_ETH_FEC_MODE_CAPA_MASK(AUTO) |
				RTE_ETH_FEC_MODE_CAPA_MASK(RS);
		}
		capa_num++;
	}
	if (sfp_cap.speed_40g) {
		if (speed_fec_capa) {
			speed_fec_capa[capa_num].speed = RTE_ETH_SPEED_NUM_40G;
			speed_fec_capa[capa_num].capa =
				RTE_ETH_FEC_MODE_CAPA_MASK(NOFEC) |
				RTE_ETH_FEC_MODE_CAPA_MASK(AUTO) |
				RTE_ETH_FEC_MODE_CAPA_MASK(BASER);
		}
		capa_num++;
	}
	if (sfp_cap.speed_25g) {
		if (speed_fec_capa) {
			speed_fec_capa[capa_num].speed = RTE_ETH_SPEED_NUM_25G;
			speed_fec_capa[capa_num].capa =
				RTE_ETH_FEC_MODE_CAPA_MASK(NOFEC) |
				RTE_ETH_FEC_MODE_CAPA_MASK(AUTO) |
				RTE_ETH_FEC_MODE_CAPA_MASK(BASER) |
				RTE_ETH_FEC_MODE_CAPA_MASK(RS);
		}
		capa_num++;
	}
	if (sfp_cap.speed_10g) {
		if (speed_fec_capa) {
			speed_fec_capa[capa_num].speed = RTE_ETH_SPEED_NUM_10G;
			speed_fec_capa[capa_num].capa =
				RTE_ETH_FEC_MODE_CAPA_MASK(NOFEC) |
				RTE_ETH_FEC_MODE_CAPA_MASK(AUTO) |
				RTE_ETH_FEC_MODE_CAPA_MASK(BASER);
		}
		capa_num++;
	}

	return capa_num;
}

static int
mce_fec_get_capability(struct rte_eth_dev *dev,
		       struct rte_eth_fec_capa *speed_fec_capa, unsigned int num )
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	unsigned int num_entries = 0;

	num_entries = mce_fec_get_capa_speed_to_fec(hw, NULL);

	if(!speed_fec_capa ||  num < num_entries)
		return num_entries;

	return mce_fec_get_capa_speed_to_fec(hw, speed_fec_capa);
}

static int
mce_fec_get(struct rte_eth_dev *dev, uint32_t *fec_capa)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	mce_update_fw_stat(hw);
	/* hw->fw_stat.stat0.configed_fec */
	switch (hw->fw_stat.stat0.active_fec) {
	case ST_FEC_OFF:
		*fec_capa = RTE_ETH_FEC_MODE_CAPA_MASK(NOFEC);
		break;
	case ST_FEC_BASER:
		*fec_capa = RTE_ETH_FEC_MODE_CAPA_MASK(BASER);
		break;
	case ST_FEC_RS:
		*fec_capa = RTE_ETH_FEC_MODE_CAPA_MASK(RS);
		break;
	case ST_FEC_AUTO:
		*fec_capa = RTE_ETH_FEC_MODE_CAPA_MASK(AUTO);
		break;
	}

	return 0;
}

static int
mce_fec_set(struct rte_eth_dev *dev, uint32_t fec_capa)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	enum FEC_TYPE type;

	switch (fec_capa) {
	case RTE_ETH_FEC_MODE_CAPA_MASK(NOFEC):
		type = FEC_NONE;
		break;
	case RTE_ETH_FEC_MODE_CAPA_MASK(BASER):
		type = FEC_BASER;
		break;
	case RTE_ETH_FEC_MODE_CAPA_MASK(RS):
		type = FEC_RS;
		break;
	case RTE_ETH_FEC_MODE_CAPA_MASK(AUTO):
		type = FEC_AUTO;
		break;
	default:
		return -EINVAL;
	}

	return mce_mbx_set_fec(hw, type);
}
#endif /* RTE_VERSION >= 20.11 */

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
static int
mce_fw_version_get(struct rte_eth_dev *dev, char *fw_version, size_t fw_size)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	char *ver = (char *)&hw->fw_version;
	int ret;

	ret = snprintf(fw_version, fw_size, "%d.%d.%d.%d",
			ver[3],
			ver[2],
			ver[1],
			ver[0]);
	if (ret < 0)
		return -EINVAL;
	/* add the size of '\0' */
	ret += 1;
	if (fw_size < (size_t)ret)
		return ret;
	return 0;
}
#endif

static int
mce_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	return mce_mbx_fw_ifup(hw, true);
}

static int
mce_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	return mce_mbx_fw_ifup(hw, false);
}

static int
mce_dev_led_on(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

        return mce_fw_set_led(hw, LED_IDENTIFY_ON);
}

static int
mce_dev_led_off(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

        return mce_fw_set_led(hw, LED_IDENTIFY_OFF);
}

#ifdef RTE_LIBRTE_IEEE1588
/**
 * @brief Read the TX hardware timestamp of the last transmitted packet
 *
 * @param dev Pointer to the Ethernet device
 * @param timestamp Output parameter to receive the timestamp (sec + nsec)
 *
 * @return 0 on success (timestamp written)
 * @return -EINVAL if @p timestamp is NULL
 * @return -1 if no TX timestamp is available
 */
static int mce_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
					  struct timespec *timestamp)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint64_t sec = 0, nsec = 0;
	int ret = 0;

	if (timestamp == NULL)
		return -EINVAL;
	ret = mce_ptp_tx_stamp(hw, &sec, &nsec);
	if (!ret) {
		timestamp->tv_sec = sec;
		timestamp->tv_nsec = nsec;
	}

	return ret;
}

/**
 * @brief Read RX hardware timestamp for a received packet from a queue
 *
 * @param dev Pointer to the Ethernet device
 * @param timestamp Output parameter to receive the timestamp (sec + nsec)
 * @param flags Queue index used to locate the RX queue timestamp
 *
 * @return 0 on success
 * @return -EINVAL if the RX queue or @p timestamp is NULL
 */
static int mce_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
					  struct timespec *timestamp,
					  uint32_t flags)
{
	struct mce_rx_queue *rxq = NULL;

	rxq = dev->data->rx_queues[flags];
	if (rxq == NULL || timestamp == NULL)
		return -EINVAL;
	timestamp->tv_sec = rxq->time_high;
	timestamp->tv_nsec = rxq->time_low;

	return 0;
}

/**
 * @brief Adjust the device PTP clock by delta nanoseconds
 *
 * @param dev Pointer to the Ethernet device
 * @param delta Time offset in nanoseconds (positive to advance, negative to retard)
 *
 * @return 0 on success or if no adjustment required
 * @return Negative error code on failure
 */
static int mce_timesync_adjust_time(struct rte_eth_dev *dev, int64_t delta)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	if (!delta)
		return 0;
	return mce_ptp_adjtime(hw, delta);
}

#if RTE_VERSION_NUM(24, 11, 0, 0) <= RTE_VERSION
/**
 * @brief Adjust the device PTP clock frequency
 *
 * @param dev Pointer to the Ethernet device
 * @param ppm Frequency adjustment in parts-per-billion (ppb)
 *
 * @return 0 on success
 * @return Negative error code on failure
 */
static int
mce_timesync_adjust_freq(struct rte_eth_dev *dev, int64_t ppm)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	return mce_ptp_adjfreq(hw, ppm);
}
#endif /* RTE_VERSION >= 24.11 */

/**
 * @brief Enable hardware timestamping (PTP) on the device
 *
 * Verifies device is started and RX timestamp offload is configured,
 * programs PTP control bits and calls hardware setup.
 *
 * @param dev Pointer to the Ethernet device
 *
 * @return 0 on success
 * @return -EINVAL if preconditions are not met
 */
static int mce_timesync_enable(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t cfg = 0;

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (dev->data->dev_started && !(dev->data->dev_conf.rxmode.offloads &
				RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
		PMD_DRV_LOG(ERR, "before dev_started isn't set offload RX_TIME");
		return -EINVAL;
	}
#else
	if (dev->data->dev_started) {
		PMD_DRV_LOG(ERR, "before dev_started isn't set offload RX_TIME");
		return -EINVAL;
	}
#endif
	cfg = MCE_PTP_TCR_TSENA | MCE_PTP_TCR_TSENALL;
	cfg |= MCE_PTP_TX_EN | MCE_PTP_RX_EN;
	cfg |= MCE_PTP_TCR_TSEVNTENA;

	return mce_ptp_setup_ptp(hw, cfg);
}

/**
 * @brief Read current PTP time from hardware
 *
 * @param dev Pointer to the Ethernet device
 * @param timestamp Output parameter to receive current time
 *
 * @return 0 on success
 * @return -EINVAL if @p timestamp is NULL
 */
static int mce_timesync_read_time(struct rte_eth_dev *dev,
				  struct timespec *timestamp)
{
        struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	if (timestamp == NULL)
		return -EINVAL;

	return mce_ptp_gettime(hw, timestamp);
}
/**
 * @brief Set the hardware PTP time
 *
 * @param dev Pointer to the Ethernet device
 * @param ts Input parameter specifying desired time (sec + nsec)
 *
 * @return 0 on success
 * @return -EINVAL if @p ts is NULL
 */
static int mce_timesync_write_time(struct rte_eth_dev *dev,
							   const struct timespec *ts)
{
        struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	if (ts == NULL)
		return -EINVAL;

        return mce_ptp_settime(hw, ts);
}

/**
 * @brief Disable hardware PTP/timestamping on the device
 *
 * @param dev Pointer to the Ethernet device
 *
 * @return 0 on success
 */
static int mce_timesync_disable(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	return mce_disable_ptp(hw);
}

#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
static int
mce_read_clock(__rte_unused struct rte_eth_dev *dev, uint64_t *clock)
{
	struct timespec system_time;

#ifdef RTE_EXEC_ENV_LINUX
	clock_gettime(CLOCK_MONOTONIC_RAW, &system_time);
#else
	clock_gettime(CLOCK_MONOTONIC, &system_time);
#endif
	*clock = system_time.tv_sec * NSEC_PER_SEC + system_time.tv_nsec;

	return 0;
}
#endif
#endif /* RTE_LIBRTE_IEEE1588 */

static int
mce_dev_udp_tunnel_port_add(struct rte_eth_dev *dev,
			    struct rte_eth_udp_tunnel *udp_tunnel)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(dev);
	int ret = 0;

	if (udp_tunnel == NULL)
		return -EINVAL;

	switch (udp_tunnel->prot_type) {
	case RTE_ETH_TUNNEL_TYPE_VXLAN:
		ret = mce_tunnel_udp_port_add(pf, udp_tunnel->udp_port,
				MCE_TUNNEL_TYPE_VXLAN);
		break;
	case RTE_ETH_TUNNEL_TYPE_VXLAN_GPE:
		ret = mce_tunnel_udp_port_add(pf, udp_tunnel->udp_port,
				MCE_TUNNEL_TYPE_VXLAN_GPE);
		break;
	case RTE_ETH_TUNNEL_TYPE_GENEVE:
		ret = mce_tunnel_udp_port_add(pf, udp_tunnel->udp_port,
				MCE_TUNNEL_TYPE_GENEVE);
		break;
	default:
		PMD_DRV_LOG(ERR, "Invalid tunnel type");
		ret = -1;
		break;
	}

	return ret;
}

static int
mce_dev_udp_tunnel_port_del(struct rte_eth_dev *dev,
			    struct rte_eth_udp_tunnel *udp_tunnel)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(dev);
	int ret = 0;

	if (udp_tunnel == NULL)
		return -EINVAL;

	switch (udp_tunnel->prot_type) {
	case RTE_ETH_TUNNEL_TYPE_VXLAN:
		ret = mce_tunnel_udp_port_remove(pf, udp_tunnel->udp_port,
				MCE_TUNNEL_TYPE_VXLAN);
		break;
	case RTE_ETH_TUNNEL_TYPE_VXLAN_GPE:
		ret = mce_tunnel_udp_port_remove(pf, udp_tunnel->udp_port,
				MCE_TUNNEL_TYPE_VXLAN_GPE);
		break;
	case RTE_ETH_TUNNEL_TYPE_GENEVE:
		ret = mce_tunnel_udp_port_remove(pf, udp_tunnel->udp_port,
				MCE_TUNNEL_TYPE_GENEVE);
		break;
	default:
		PMD_DRV_LOG(ERR, "Invalid tunnel type");
		ret = -1;
		break;
	}

	return ret;
}


static const struct eth_dev_ops mce_eth_dev_ops = {
	.dev_configure = mce_dev_configure,
	.dev_infos_get = mce_dev_infos_get,
	.dev_start = mce_dev_start,
	.dev_stop = mce_dev_stop,
	.dev_close = mce_dev_close,

	.link_update = mce_link_update,
	.dev_set_link_up = mce_dev_set_link_up,
	.dev_set_link_down = mce_dev_set_link_down,
	.dev_led_on = mce_dev_led_on,
	.dev_led_off = mce_dev_led_off,
	.rx_queue_start = mce_rx_queue_start,
	.rx_queue_stop = mce_rx_queue_stop,
	.tx_queue_start = mce_tx_queue_start,
	.tx_queue_stop = mce_tx_queue_stop,
	.rx_queue_setup = mce_rx_queue_setup,
	.tx_queue_setup = mce_tx_queue_setup,
	.rx_queue_intr_enable = mce_dev_rx_queue_intr_enable,
	.rx_queue_intr_disable = mce_dev_rx_queue_intr_disable,

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	.rx_queue_release = mce_dev_rx_queue_release,
	.tx_queue_release = mce_dev_tx_queue_release,
#else
	.tx_queue_release = mce_rx_queue_release,
	.rx_queue_release = mce_tx_queue_release,
#endif
	.set_queue_rate_limit = mce_dev_txq_rate_limit,
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.rxq_info_get = mce_rx_queue_info_get,
	.txq_info_get = mce_tx_queue_info_get,
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	.rx_queue_count = mce_dev_rx_queue_count,
	.rx_descriptor_done = mce_dev_rx_descriptor_done,
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
	.rx_descriptor_status = mce_dev_rx_descriptor_status,
	.tx_descriptor_status = mce_dev_tx_descriptor_status,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.rx_burst_mode_get = mce_rx_burst_mode_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.tx_burst_mode_get = mce_tx_burst_mode_get,
#endif
	.mtu_set = mce_dev_mtu_set,
	.mac_addr_set = mce_macaddr_set,
	.mac_addr_add = mce_macaddr_add,
	.mac_addr_remove = mce_macaddr_remove,
	.set_mc_addr_list = mce_dev_set_mc_addr_list,
	.vlan_filter_set = mce_vlan_filter_set,
	.vlan_offload_set = mce_vlan_offload_set,
	.vlan_tpid_set = mce_vlan_tpid_set,
	.reta_update = mce_rss_reta_update,
	.reta_query = mce_rss_reta_query,
	.rss_hash_update = mce_rss_hash_set,
	.rss_hash_conf_get = mce_rss_hash_conf_get,
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
	.flow_ops_get = mce_dev_flow_ops_get,
#else
	.filter_ctrl = mce_filter_ctrl,
#endif
	.promiscuous_enable = mce_promisc_enable,
	.promiscuous_disable = mce_promisc_disable,
	.allmulticast_enable = mce_allmulticast_enable,
	.allmulticast_disable = mce_allmulticast_disable,

	.stats_get = mce_dev_stats_get,
	.stats_reset = mce_dev_stats_reset,
	.xstats_get = mce_dev_xstats_get,
#if RTE_VERSION_NUM(16, 7, 0, 0) <= RTE_VERSION
	.xstats_get_names = mce_dev_xstats_get_names,
#endif
	.xstats_reset = mce_dev_xstats_reset,
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	.dev_supported_ptypes_get = mce_dev_supported_ptypes_get,
#endif
#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
	.tm_ops_get = mce_tm_ops_get,
#endif /* RTE_VERSION >= 17.8 */
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	.get_module_info        = mce_get_module_info,
	.get_module_eeprom      = mce_get_module_eeprom,
#endif

#if RTE_VERSION_NUM(22, 3, 0, 0) <= RTE_VERSION
	.eth_dev_priv_dump  = mce_eth_dev_priv_dump,
#endif /* RTE_VERSION >= 22.03 */
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
	.fec_get_capability     = mce_fec_get_capability,
	.fec_set	        = mce_fec_set,
	.fec_get	        = mce_fec_get,
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	.fw_version_get         = mce_fw_version_get,
#endif
#ifdef RTE_LIBRTE_IEEE1588
	.timesync_enable              = mce_timesync_enable,
	.timesync_read_rx_timestamp   = mce_timesync_read_rx_timestamp,
	.timesync_read_tx_timestamp   = mce_timesync_read_tx_timestamp,
	.timesync_adjust_time         = mce_timesync_adjust_time,
#if RTE_VERSION_NUM(24, 11, 0, 0) <= RTE_VERSION
	.timesync_adjust_freq         = mce_timesync_adjust_freq,
#endif /* RTE_VERSION >= 24.11 */
	.timesync_read_time           = mce_timesync_read_time,
	.timesync_write_time          = mce_timesync_write_time,
	.timesync_disable             = mce_timesync_disable,
#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
	.read_clock                   = mce_read_clock,
#endif /* RTE_VERSION >= 19.08 */
#endif /* RTE_LIBRTE_IEEE1588 */

	.udp_tunnel_port_add          = mce_dev_udp_tunnel_port_add,
	.udp_tunnel_port_del          = mce_dev_udp_tunnel_port_del,
};

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
static int mce_parse_string_arg(const __rte_unused char *key, const char *value,
				void *args)
{
	char *cur;
	char *tmp;
	int str_len;
	int valid_len;

	int ret = 0;
	uint64_t *flags = args;
	char *str2 = strdup(value);
	if (str2 == NULL)
		return -1;

	str_len = strlen(str2);
	if (str_len == 0) {
		ret = -1;
		goto err_end;
	}

	/* Try stripping the outer square brackets of the parameter string. */
	str_len = strlen(str2);
	if (str2[0] == '[' && str2[str_len - 1] == ']') {
		if (str_len < 3) {
			ret = -1;
			goto err_end;
		}
		valid_len = str_len - 2;
		memmove(str2, str2 + 1, valid_len);
		memset(str2 + valid_len, '\0', 2);
	}

	cur = strtok_r(str2, ",", &tmp);
	while (cur != NULL) {
		if (!strcmp(cur, "sign"))
			*flags |= MCE_FDIR_SIGN_M_MODE;
		else if (!strcmp(cur, "exact"))
			*flags |= MCE_FDIR_EXACT_M_MODE;
		else if (!strcmp(cur, "macvlan"))
			*flags |= MCE_FDIR_MACVLAN_MODE;
		else if (!strcmp(cur, "switchdev"))
			*flags |= MCE_ESWITCH_SWITCHDEV;
		else if (!strcmp(cur, "legacy"))
			*flags |= MCE_ESWITCH_LEGACY;
		else
			PMD_DRV_LOG(ERR, "Unsupported fdir type: %s", cur);
		cur = strtok_r(NULL, ",", &tmp);
	}
	free(str2);
err_end:
	return ret;
}

static int mce_parse_fw_path_arg(const char *key __rte_unused,
				 const char *value, void *extra_args)
{
	char *fw_path = (char *)extra_args;

	strcpy(fw_path, value);
	return 0;
}

static int mce_parse_axi_mhz(const char *key __rte_unused,
			     const char *value, void *extra_args)
{
	int *axi_mhz = (int *)extra_args;

	*axi_mhz = strtol(value, NULL,0);

	return 0;
}

static int mce_parse_bool_arg(const char *key, const char *value, void *args)
{
	int *i = (int *)args;
	char *end;
	int num;

	num = strtoul(value, &end, 10);

	if (num != 0 && num != 1) {
		PMD_DRV_LOG(WARNING,
			    "invalid value:\"%s\" for key:\"%s\", "
			    "value must be 0 or 1",
			    value, key);
		return -1;
	}

	*i = num;
	return 0;
}
#endif

static int mce_parse_devargs(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
#if RTE_VERSION_NUM(16, 11, 0, 0) >= RTE_VERSION
	struct rte_devargs *devargs = pci_dev->devargs;
#else
	struct rte_devargs *devargs = pci_dev->device.devargs;
#endif
	struct mce_pf *pf = MCE_DEV_TO_PF(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	struct rte_kvargs *kvlist;
#endif
	int ret = 0;

	pf->link_down_on_close = -1;
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
	rte_eal_pci_device_name(&pci_dev->addr, hw->device_name,
				sizeof(hw->device_name));
#else
	strlcpy(hw->device_name, pci_dev->device.name,
		strlen(pci_dev->device.name) + 1);
#endif
	if (devargs == NULL)
		return 0;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL) {
		PMD_INIT_LOG(ERR, "Invalid kvargs key\n");
		return -EINVAL;
	}
	ret = rte_kvargs_process(kvlist, MCE_FDIR_FILTER_MODE,
				 &mce_parse_string_arg, &pf->fdir_mode);
	if (ret)
		goto fail;
	ret = rte_kvargs_process(kvlist, MCE_ESWITCH_MODE,
				 &mce_parse_string_arg, &pf->eswitch_mode);
	if (ret)
		goto fail;
	ret = rte_kvargs_process(kvlist, MCE_FDIR_FLUSH_MODE,
				 &mce_parse_bool_arg, &pf->fdir_flush_en);
	if (ret)
		goto fail;

	ret = rte_kvargs_process(kvlist, MCE_AXI_MHZ, &mce_parse_axi_mhz,
				 &pf->axi_mhz);
	if (ret)
		goto fail;

	ret = rte_kvargs_process(kvlist, MCE_FW_PATH, &mce_parse_fw_path_arg,
				 pf->fw_path);
	if (ret)
		goto fail;
	ret = rte_kvargs_process(kvlist, MCE_LINK_DOWN_ON_CLOSE,
				&mce_parse_bool_arg, &pf->link_down_on_close);
	if (ret)
		goto fail;
	ret = rte_kvargs_process(kvlist, MCE_SMID_VECTOR_ENA,
				&mce_parse_bool_arg, &pf->force_smid_en);
	if (ret)
		goto fail;
fail:
	rte_kvargs_free(kvlist);
#endif

	return ret;
}
#ifdef MCE_DEBUG_PCAP
#define RTE_GRAPH_PCAP_FILE_SZ 64
#define GRAPH_PCAP_FILE_NAME   "dpdk_graph_pcap_capture_XXXXXX.pcapng"
#define GRAPH_PCAP_PKT_POOL    "graph_pcap_pkt_pool"
/* rte_graph defines */
#define RTE_GRAPH_BURST_SIZE   256
struct rte_mempool *n20_pkt_mp;
#if 1
static int
mce_pcap_default_path_get(char **dir_path)
{
	struct passwd *pwd;
	char *home_dir;

	/* First check for shell environment variable */
	home_dir = getenv("HOME");
	if (home_dir == NULL) {
	/* Fallback to password file entry */
		pwd = getpwuid(getuid());
		if (pwd == NULL)
			return -EINVAL;

			home_dir = pwd->pw_dir;
	}

	/* Append default pcap file to directory */
	if (asprintf(dir_path, "%s/%s", home_dir, GRAPH_PCAP_FILE_NAME) == -1)
		return -ENOMEM;

	return 0;
}
#endif
static int mce_pcap_mp_init(void)
{
	n20_pkt_mp = rte_mempool_lookup(GRAPH_PCAP_PKT_POOL);
	if (n20_pkt_mp)
		goto done;

	/* Make a pool for cloned packets */
	n20_pkt_mp = rte_pktmbuf_pool_create_by_ops(
		GRAPH_PCAP_PKT_POOL, IOV_MAX + RTE_GRAPH_BURST_SIZE, 0, 0,
		rte_pcapng_mbuf_size(RTE_MBUF_DEFAULT_BUF_SIZE), SOCKET_ID_ANY,
		"ring_mp_mc");
	if (n20_pkt_mp == NULL)
		return -1;

done:
	return 0;
}
#endif

static int mce_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct mce_adapter *adapter = MCE_DEV_TO_ADAPTER(eth_dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct mce_vport *vport = MCE_DEV_TO_VPORT(eth_dev);
	struct mce_pf *pf = MCE_DEV_TO_PF(eth_dev);
	struct mce_hw *hw = &adapter->hw;
	uint32_t qgnum = 0;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();
	eth_dev->dev_ops = &mce_eth_dev_ops;
	eth_dev->rx_pkt_burst = mce_rx_recv_pkts;
	eth_dev->tx_pkt_burst = mce_xmit_simple;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	eth_dev->tx_pkt_prepare = mce_prep_pkts;
#endif
	ret = mce_mp_init(eth_dev);
	if (ret < 0) {
		PMD_INIT_LOG(ERR, "pf mp process sync init failed");
		return ret;
	}
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		mce_setup_rx_function(eth_dev);
		mce_setup_tx_function(eth_dev);
		mce_mp_req_secondry_probed(eth_dev);

		return 0;
	}
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
	if (mce_get_pcie_link_state(pci_dev, hw) < 0) {
		PMD_INIT_LOG(ERR, "Failed to read pcie config");
		return -EINVAL;
	}
#endif
	hw->nic_base = pci_dev->mem_resource[MCE_NIC_CTRL_BAR].addr;
	hw->dm_stat = (u8 *)hw->nic_base + 0x4000c;
	hw->nic_stat = (u8 *)hw->nic_base + 0x7000c;
	hw->ext_stat = (u8 *)hw->nic_base + 0x33000;
	if (pci_dev->mem_resource[0].len == MCE_BAR_DIS_SIZE)
		hw->npu_base = NULL;
	else
		hw->npu_base = pci_dev->mem_resource[0].addr;
	hw->pci_dev = pci_dev;
	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->function = pci_dev->addr.function;
	hw->port_id = eth_dev->data->port_id;
	hw->vf_min_ring_cnt = 4;
	hw->back = adapter;
	hw->max_vfs = pci_dev->max_vfs;
	hw->is_vf = 0;
#ifdef RTE_LIBRTE_IEEE1588
	mce_ptp_init(hw);
#endif
	rte_spinlock_init(&hw->link_lock);
	rte_spinlock_init(&hw->ptp_lock);
	adapter->pf.dev_data = eth_dev->data;
	adapter->pf.dev = eth_dev;
	ret = mce_parse_devargs(eth_dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to parse devargs");
		return -EINVAL;
	}
	/* init hw */
	if (mce_init_hw(hw)) {
		PMD_INIT_LOG(ERR, "Failed to Init Hw");
		return -EIO;
	}
	/* alloc a vport */
	pf->pf_vport = mce_alloc_vport(hw, MCE_VPORT_IS_PF);
	/* get from hwinfo to sw init */
	vport = pf->pf_vport;
#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
	mce_tm_conf_init(eth_dev);
#endif
	if (!rte_is_unicast_ether_addr(
		    (struct rte_ether_addr *)hw->perm_mac_addr))
		rte_eth_random_addr(hw->perm_mac_addr);
	memcpy(&vport->mac_addr, hw->perm_mac_addr, 6);
	/* setup default mac address */
	eth_dev->data->mac_addrs = rte_zmalloc("mce_mac_addr",
		sizeof(struct rte_ether_addr) * vport->attr.max_mac_addrs, 0);
	if (!eth_dev->data->mac_addrs) {
		PMD_DRV_LOG(ERR,
			    "memory allocation for MAC addrs failed");
		ret = -ENOMEM;
		goto cleanup;
	}
	memset(eth_dev->data->mac_addrs, 0,
	       sizeof(struct rte_ether_addr) * vport->attr.max_mac_addrs);
	rte_ether_addr_copy((const struct rte_ether_addr *)vport->mac_addr,
			    eth_dev->data->mac_addrs);
	/* Allocate  memory for storing hash filter MAC addresses */
	if (vport->attr.max_mc_mac_hash) {
		eth_dev->data->hash_mac_addrs = rte_zmalloc("mce_hash_mac_addr",
				RTE_ETHER_ADDR_LEN * vport->attr.max_mc_mac_hash, 0);
		if (eth_dev->data->hash_mac_addrs == NULL) {
			PMD_INIT_LOG(ERR,
					"Memory allocation for hash MAC addrs failed");
			ret = -ENOMEM;
			goto cleanup;
		}
	}
	if (hw->max_vfs) {
		if (hw->max_vfs >= 128) {
			return -EINVAL;
		}
		u32 sriov_ctrl = 0;
		u32 ctrl = 0;
		u32 qp_vf;

		pf->max_vfs = pci_dev->max_vfs;
		/* #endif*/
		sriov_ctrl = MCE_E_REG_READ(hw, MCE_DMA_CTRL);
#define MCE_QUEUE_PER_GROUP   (4)
#define MCE_SRIOV_QUEUE_MASK  GENMASK_U32(11, 9)
#define MCE_SRIOV_QUEUE_SHIFT (9)
#define MCE_SRIOV_EN	      RTE_BIT32(25)
#define MCE_FPGA_PF_QUEUE_NUM (4)
		/* setup dma perf vf max queue num */
		/* setup sriov default vport id */
		qp_vf = rte_log2_u32(hw->nb_qpair_per_vf);
		MCE_FIELD_SET_VAL(sriov_ctrl, MCE_SRIOV_QUEUE, qp_vf);
		MCE_FIELD_SET_BITS(sriov_ctrl, 0, MCE_SRIOV_EN);
		sriov_ctrl |= vport->attr.vport_id << MCE_DMA_PF_DEF_VPORT_S;
		MCE_E_REG_WRITE(hw, MCE_DMA_CTRL, sriov_ctrl);
		/* setup per vf queue group limit rate range */
		qgnum = rte_log2_u32(hw->nb_qpair / MCE_QUEUE_PER_GROUP);
		MCE_E_REG_WRITE(hw, MCE_VF_QG_CTRL_REG, MCE_VF_QG_EN | qgnum);
		MCE_E_REG_SET_BITS(hw, MCE_NIC_CTRL, 0, MCE_ESWITCH_EN);
		/* setup eth per vf max queue num */
		ctrl = MCE_E_REG_READ(hw, MCE_ETH_RQA_CTRL);
		ctrl &= ~MCE_RQA_VF_RING_MASK;
		ctrl |= qgnum << MCE_RQA_VF_RING_SHIFT;
		MCE_E_REG_WRITE(hw, MCE_ETH_RQA_CTRL, ctrl);
		mce_pf_init(eth_dev);
	}
	/* register callback func to eal lib */
	rte_intr_callback_register(intr_handle, mce_dev_interrupt_handler,
				   eth_dev);
	rte_intr_enable(intr_handle);
	/* enable mbx irq*/
	mce_mbx_vector_set(&hw->pf2fw_mbx, 0, true);
	mce_pf_set_all_vf2pf_mbx_vector(hw, 0, true);
	mce_dev_mac_stats_reset(eth_dev);
#ifdef MCE_DEBUG_PCAP
	rte_eth_dev_probing_finish(eth_dev);
	rte_eth_copy_pci_info(eth_dev, pci_dev);
	eth_dev->device->driver = (struct rte_driver *)pci_dev->driver;
	int fd = -1;

	mce_pcap_mp_init();
	if (n20_pcapng_fd == NULL) {
		fd = open("/home/debug_dump.pcap", O_WRONLY | O_CREAT,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		n20_pcapng_fd = rte_pcapng_fdopen(fd, NULL, NULL,
						  "N20 pcap tracer", NULL);
	}
	if (n20_pcapng_fd)
		rte_pcapng_add_interface(n20_pcapng_fd, eth_dev->data->port_id,
					 NULL, NULL, NULL);
#endif
	if (pf->link_down_on_close > 0 &&
		hw->fw_stat.stat0.force_link_status == FOCE_LINK_SETTED) {
		if (pf->link_down_on_close)
			mce_mbx_set_force_link_on_close(hw, true);
		else
			mce_mbx_set_force_link_on_close(hw, false);
	}
	if (strlen(pf->fw_path) > 0)
		mce_download_fw(hw, pf->fw_path);
	if (pf->axi_mhz > 0)
		mce_mbx_axi_clk_set(hw, pf->axi_mhz);
	return 0;
cleanup:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;
	rte_free(eth_dev->data->hash_mac_addrs);
	eth_dev->data->hash_mac_addrs = NULL;
	return ret;
}

static int mce_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	PMD_INIT_FUNC_TRACE();
	mce_dev_close(eth_dev);

	return 0;
}

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
static int mce_pci_remove(struct rte_pci_device *pci_dev)
{
	char device_name[PCI_PRI_STR_SIZE] = "";
	struct rte_eth_dev *eth_dev;
	int rc = 0;

#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
	rte_eal_pci_device_name(&pci_dev->addr, device_name,
				sizeof(device_name));
#else
	strlcpy(device_name, pci_dev->device.name,
		strlen(pci_dev->device.name) + 1);
#endif
	eth_dev = rte_eth_dev_allocated(device_name);
	if (eth_dev) {
		/* Cleanup eth dev */
		rc = rte_eth_dev_pci_generic_remove(pci_dev,
						    mce_eth_dev_uninit);
		if (rc)
			return rc;
	}
	return 0;
}

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
static int mce_repr_route_init(struct rte_pci_device *pci_dev)
{
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_dev *eth_dev = rte_eth_dev_allocated(pci_dev->device.name);
	struct mce_proxy_route_adapter *proxy_route;
	struct mce_pf *pf = MCE_DEV_TO_PF(eth_dev);

	proxy_route = rte_zmalloc(NULL, sizeof(struct mce_proxy_route_adapter), 0);
	proxy_route->upcall_port = eth_dev->data->port_id;
	pf->proxy_route = proxy_route;
	proxy_route->back = pf;
	mce_proxy_route_init(proxy_route);
	mce_route_proxy_register(proxy_route);

	if (pf->eswitch_mode == MCE_ESWITCH_SWITCHDEV)
		pf->is_switchdev = 1;
#else
	RTE_SET_USED(pci_dev);
#endif /* RTE_VERSION >= 21.11 */

	return 0;
}
#endif

static int mce_pci_probe(struct rte_pci_driver *pci_drv,
			 struct rte_pci_device *pci_dev)
{
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	struct rte_eth_devargs eth_da = { .nb_representor_ports = 0 };
#endif
	char device_name[PCI_PRI_STR_SIZE] = "";
	struct rte_eth_dev *parent = NULL;
	struct mce_pf *pf = NULL;
	int i = 0;
	int rc = 0;

	RTE_SET_USED(pci_drv);
	if (pci_dev->device.devargs) {
#if RTE_VERSION_NUM(24, 3, 0, 0) <= RTE_VERSION
		rc = rte_eth_devargs_parse(pci_dev->device.devargs->args,
					   &eth_da, 1);
#else /* RTE_VERSION < 24.3 */
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		rc = rte_eth_devargs_parse(pci_dev->device.devargs->args,
					   &eth_da);
#endif /* RTE_VERSION <= 18.2 */
#endif /* RTE_VERSION >= 24.3 */
		if (rc < 0)
			return rc;
	}
	rc = rte_eth_dev_pci_generic_probe(pci_dev, sizeof(struct mce_adapter),
					   mce_eth_dev_init);
	if (rc)
		return rc;
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	if (!eth_da.nb_representor_ports || !pci_dev->max_vfs)
		return 0;
	mce_repr_route_init(pci_dev);
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_DRV_LOG(ERR,
			    "Create representors from secondary process not "
			    "allowed%s.",
			    pci_dev->device.name);
		return -ENOTSUP;
	}
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
	if (eth_da.type != RTE_ETH_REPRESENTOR_VF)
		return -ENOTSUP;
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
	rte_eal_pci_device_name(&pci_dev->addr, device_name,
				sizeof(device_name));
#else
	strlcpy(device_name, pci_dev->device.name,
		strlen(pci_dev->device.name) + 1);
#endif
	parent = rte_eth_dev_allocated(device_name);

	if (parent == NULL)
		return -ENODEV;

	/* let all vf send pkts to match rule policy */
	pf = MCE_DEV_TO_PF(parent);
	/* probe VF representor ports */
	if (pf->is_switchdev)
		mce_sw_set_pf_uplink(pf);
	pf->nr_repr_ports = eth_da.nb_representor_ports;
	for (i = 0; i < eth_da.nb_representor_ports; i++) {
		struct mce_vf_representor representor = {
			.vf_id = i,
			.port_id = eth_da.representor_ports[i],
			.switch_domain_id =
				MCE_DEV_TO_PF(parent)->switch_domain_id,
			.adapter = MCE_DEV_TO_ADAPTER(parent)
		};
		char name[128] = " ";
		/* representor port net_bdf_port */
		snprintf(name, sizeof(name), "net_%s_representor_%d",
			 pci_dev->device.name, eth_da.representor_ports[i]);
		rc = rte_eth_dev_create(&pci_dev->device, name,
					sizeof(struct mce_vf_representor), NULL,
					NULL, mce_vf_representor_init,
					&representor);
		if (rc)
			PMD_DRV_LOG(ERR,
				    "failed to create mce vf representor %s.",
				    name);
	}
#else /* RTE_VERSION > 18.2 */
	RTE_SET_USED(device_name);
	RTE_SET_USED(parent);
	RTE_SET_USED(pf);
	RTE_SET_USED(i);
#endif
	return rc;
}
#endif

static const struct rte_pci_id pci_id_mce_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, MCE_DEV_ID_N20) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, 0x903f) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, 0x913f) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, 0x8500) }, /* 25G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, 0x8501) }, /* 100G */
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, 0x8502) }, /* 40G */
	{
		.vendor_id = 0,
	},
};

bool mce_is_device_supported(struct rte_eth_dev *dev,
			     struct rte_pci_driver *drv)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	char device_name[PCI_PRI_STR_SIZE] = "";
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
	rte_eal_pci_device_name(&pci_dev->addr, device_name,
				sizeof(device_name));
#else
	strlcpy(device_name, pci_dev->device.driver->name,
		strlen(pci_dev->device.name) + 1);
#endif
#if RTE_VERSION_NUM(2, 1, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
	if (strcmp(device_name, drv->name))
#else
	if (strcmp(device_name, drv->driver.name))
#endif
		return false;
	return true;
}
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
RTE_LOG_REGISTER_SUFFIX(mce_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(mce_logtype_driver, driver, NOTICE);
#elif RTE_VERSION_NUM(20, 8, 0, 0) < RTE_VERSION && \
	RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
RTE_LOG_REGISTER(mce_logtype_init, init, NOTICE);
RTE_LOG_REGISTER(mce_logtype_driver, driver, NOTICE);
#else /* RTE_VERSION < 20.2 */
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
RTE_INIT(mce_init_log)
{
	mce_logtype_init = rte_log_register("pmd.net.mce.init");
	rte_log_set_level(mce_logtype_init, RTE_LOG_NOTICE);
	mce_logtype_driver = rte_log_register("pmd.net.mce.driver");
	rte_log_set_level(mce_logtype_driver, RTE_LOG_NOTICE);
}
#endif /* RTE_VERSION >= 17.05 && RTE_VERSION < 20.02 */
#endif /* RTE_VERSION >= 21.05 */
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
static struct rte_pci_driver rte_mce_pmd = {
	.id_table = pci_id_mce_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = mce_pci_probe,
	.remove = mce_pci_remove,
};
bool is_mce_supported(struct rte_eth_dev *dev)
{
	return mce_is_device_supported(dev, &rte_mce_pmd);
}
RTE_PMD_REGISTER_PCI(net_mce, rte_mce_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_mce, pci_id_mce_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mce, "* igb_uio | vfio-pci");
#else /* RTE_VERSION < 17.05 */
static struct eth_driver rte_mce_pmd = {
	.pci_drv =
        {
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
		.name      = "rte_mce_pmd",
#endif
		.id_table  = pci_id_mce_map,
#if RTE_VERSION_NUM(17, 2, 0, 16) <= RTE_VERSION
		.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
#else /* RTE_VERSION < 17.2 */
		.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC | RTE_PCI_DRV_DETACHABLE,
#endif /* RTE_VERSION >= 17.2 */
#if RTE_VERSION_NUM(16, 11, 0, 16) <= RTE_VERSION
		.probe     = rte_eth_dev_pci_probe,
		.remove    = rte_eth_dev_pci_remove,
#endif /* RTE_VERSION >= 16.11 && RTE_VERSION < 17.05 */
        },
	.eth_dev_init     = mce_eth_dev_init,
	.eth_dev_uninit   = mce_eth_dev_uninit,
	.dev_private_size = sizeof(struct mce_adapter),
};
bool is_mce_supported(struct rte_eth_dev *dev)
{
	return mce_is_device_supported(dev, &rte_mce_pmd.pci_drv);
}
#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
RTE_PMD_REGISTER_PCI(net_mce, rte_mce_pmd.pci_drv);
RTE_PMD_REGISTER_PCI_TABLE(net_mce, pci_id_mce_map);
#if RTE_VERSION_NUM(17, 2, 0, 16) <= RTE_VERSION
RTE_PMD_REGISTER_KMOD_DEP(net_mce, "igb_uio | uio_pci_generic | vfio-pci");
#endif /* RTE_VERSION >= 17.2.0.16 && RTE_VERSION < 17.5 */
#else /* RTE_VERSION < 16.11 */
static int rte_mce_pmd_init(const char *name __rte_unused,
			    const char *params __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	rte_eth_driver_register(&rte_mce_pmd);
	return 0;
}
static struct rte_driver rte_mce_driver = {
	.type = PMD_PDEV,
	.init = rte_mce_pmd_init,
};
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
PMD_REGISTER_DRIVER(rte_mce_driver);
#else /* RTE_VERSION > 16.4.0.16 */
PMD_REGISTER_DRIVER(rte_mce_driver, mce);
DRIVER_REGISTER_PCI_TABLE(mce, pci_id_mce_map);
#endif /* RTE_VERSION <= 16.4.0.16 */
#endif /* RTE_VERSION >= 16.11 && RTE_VERSION < 17.05 */
#endif /* RTE_VERSION >=17.05 && RTE_VERSION < 21.05 */
#ifdef RTE_PARSE_ARGS_SUPPORTED
RTE_PMD_REGISTER_PARAM_STRING(net_mce, MCE_FDIR_FILTER_MODE
			      "=sign|exact|macvlan" MCE_FDIR_FLUSH_MODE
			      "=<0|1>" MCE_FW_PATH "=<string>"
			      MCE_LINK_DOWN_ON_CLOSE "=<0|1>"
			      MCE_ESWITCH_MODE "switchdev|legacy"
#ifdef RTE_VERSION_NUM(20, 11, 0, 0) > rte_version
			      MCE_SMID_VECTOR_ENA "=<0|1>"
#endif
			      );
#endif /* RTE_PARSE_ARGS_SUPPORTED */
