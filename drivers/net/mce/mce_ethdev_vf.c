/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */

/**
 * @file mce_ethdev_vf.c
 * @brief Virtual Function (VF) Ethernet device driver implementation
 *
 * Implements DPDK ethdev callbacks for MCE PMD VF (Virtual Function) ports.
 * VF devices are virtual network ports created by PF (Physical Function) for
 * SR-IOV (Single Root I/O Virtualization) based network isolation.
 * VF Features:\n * - Device configuration and lifecycle management
 * - Link state monitoring and speed negotiation
 * - MAC address management with anti-spoofing
 * - VLAN filtering and offload
 * - RSS configuration per VF
 * - Per-VF rate limiting and traffic shaping
 * - Queue management (RX/TX)
 * - Statistics collection
 * - Flow rule support (via rte_flow)
 * - Interrupt and event notification
 * VF-PF Communication
 * Uses mailbox protocol (mce_mbx.h) for communication with host PF
 * - Capability negotiation
 * - Link state updates
 * - MAC address assignment
 * - VLAN configuration
 * - Rate limit policies
 * - Statistics queries
 * Version Support:
 * - DPDK 17.2+ baseline support
 * - DPDK 19.11+ ethdev API changes (dev_infos_get return type)
 * - DPDK 21.2+ new ethdev PCI header location
 * @see mce_ethdev.c for PF implementation
 * @see base/mce_vf.h for VF hardware initialization
 * @see base/mce_mbx.h for PF-VF mailbox protocol
 */
#include <stddef.h>
#include <rte_malloc.h>
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

#include "mce.h"
#include "mce_flow.h"
#include "mce_intr.h"
#include "mce_logs.h"
#include "mce_rss.h"
#include "mce_rxtx.h"
#include "mce_compat.h"
#include "mce_mp.h"
#include "base/mce_common.h"
#include "base/mce_hw.h"
#include "base/mce_l2_filter.h"
#include "base/mce_mbx.h"
#include "base/mce_pfvf.h"
#include "base/mce_vf.h"

extern uint8_t mce_rss_default_key;

static int mcevf_link_update(struct rte_eth_dev *dev,
			     int wait_to_complete __rte_unused);
static int mcevf_default_ring_set(struct rte_eth_dev *dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int mcevf_vlan_offload_set(struct rte_eth_dev *dev, int mask);
#else
static void mcevf_vlan_offload_set(struct rte_eth_dev *dev, int mask);
#endif
static int mcevf_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

static int mcevf_dev_configure(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mcevf_dev_infos_get(struct rte_eth_dev *dev,
			       struct rte_eth_dev_info *dev_info)
#else /* RTE_VERSION < 19.11 */
static void mcevf_dev_infos_get(struct rte_eth_dev *dev,
				struct rte_eth_dev_info *dev_info)
#endif /* RTE_VERSION >= 19.11 */
{
	struct mce_vf *vf = MCE_DEV_TO_VF(dev);
	struct mce_vport *vport = vf->vf_vport;
#if RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);

	dev_info->pci_dev = pci_dev;
#endif
	dev_info->max_rx_queues = vport->attr.max_rx_queues;
	dev_info->max_tx_queues = vport->attr.max_tx_queues;

	dev_info->min_rx_bufsize = 60;
	dev_info->max_rx_pktlen = MCE_MAX_FRAME_SIZE;

	dev_info->rx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = 4096,
		.nb_min = 128,
		.nb_align = 2,
	};

	dev_info->tx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = 4096,
		.nb_min = 128,
		.nb_align = 2,
	};
	dev_info->max_mac_addrs = vport->attr.max_mac_addrs;
	dev_info->rx_offload_capa =
		RTE_ETH_RX_OFFLOAD_VLAN_FILTER | RTE_ETH_RX_OFFLOAD_QINQ_STRIP |
		RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
		RTE_ETH_RX_OFFLOAD_RSS_HASH | RTE_ETH_RX_OFFLOAD_TIMESTAMP |
		RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	dev_info->rx_queue_offload_capa = RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
	dev_info->rx_offload_capa |= dev_info->rx_queue_offload_capa;
#endif

	dev_info->reta_size = MCE_MAX_RX_QUEUE;
	dev_info->hash_key_size = MCE_MAX_HASH_KEY_SIZE * sizeof(uint32_t);
	dev_info->flow_type_rss_offloads = MCE_SUPPORT_RSS_OFFLOAD_ALL;
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
	dev_info->rss_algo_capa =
		RTE_ETH_HASH_ALGO_CAPA_MASK(DEFAULT) |
		RTE_ETH_HASH_ALGO_CAPA_MASK(TOEPLITZ) |
		RTE_ETH_HASH_ALGO_CAPA_MASK(SYMMETRIC_TOEPLITZ) |
		RTE_ETH_HASH_ALGO_CAPA_MASK(SYMMETRIC_TOEPLITZ_SORT);
#endif
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
	dev_info->default_rxconf = (struct rte_eth_rxconf){
		/* clang-format off */
		.rx_thresh = {
				.pthresh = MCE_RX_DESC_HIGH_WATER_TH,
				.hthresh = MCE_RX_DEFAULT_BURST,
			},

		.rx_free_thresh = MCE_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		.offloads = 0,
#endif
		/* clang-format on */
	};

	dev_info->default_txconf = (struct rte_eth_txconf){
		/* clang-format off */
		.tx_thresh = {
				.pthresh = MCE_TX_DESC_HIGH_WATER_TH,
				.hthresh = MCE_TX_DEFAULT_BURST,
			},
		.tx_free_thresh = MCE_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = MCE_DEFAULT_TX_RS_THRESH,
	/* clang-format on */
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
		.txq_flags =
			ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
#else
		.offloads = 0,
#endif
	};
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	/* Default Ring configure */
	dev_info->default_rxportconf.burst_size = 32;
	dev_info->default_txportconf.burst_size = 32;
	dev_info->default_rxportconf.nb_queues = 1;
	dev_info->default_txportconf.nb_queues = 1;
	dev_info->default_rxportconf.ring_size = 512;
	dev_info->default_txportconf.ring_size = 512;
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}
#endif

/**
 * @brief Start VF device: enable queues, RSS and notify PF via mailbox.
 *
 * Prepares RX/TX queues, configures RSS and notifies the physical function
 * about the VF's state. Also configures VLAN offloads and MTU for the VF.
 *
 * @param dev Pointer to the VF Ethernet device.
 * @return 0 on success, negative errno on failure.
 */
static int mcevf_dev_start(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint64_t mask = 0;
	int ret = -EINVAL;

	ret = mce_enable_all_rx_queue(dev);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "VF Failed to enable RX queues: %d", ret);
		goto error;
	}
	ret = mce_enable_all_tx_queue(dev);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "VF Failed to enable TX queues: %d", ret);
		goto error;
	}
	mce_dev_rss_configure(dev);
	/* max packet len limit setup */
	mce_rx_scattered_setup(dev);
	mce_setup_rx_function(dev);
	mce_setup_tx_function(dev);
	if (vport->attr.rx.vec_options && vport->attr.rx.simd_en)
		mce_rx_vec_cksum_db_init(dev);
	if (mce_rxq_intr_enable(dev) < 0) {
		PMD_DRV_LOG(ERR, "rxq intr setup failed");
		return -EINVAL;
	}
	mcevf_mbx_set_vf2pf_stat(hw);
	mcevf_default_ring_set(dev);
	hw->mac.ops->en_vlan_f(hw, false);
	mask = RTE_ETH_VLAN_EXTEND_MASK;
	mcevf_vlan_offload_set(dev, mask);
	hw->mac.ops->en_vlan_f(hw, false);
	hw->mac.ops->enable_mta(hw, true);
	/* max packet len limit setup */
	mcevf_dev_mtu_set(dev, dev->data->mtu);
	dev->data->dev_started = 1;
	mcevf_link_update(dev, 0);
	/* enable datapath on secondary process. */
	mce_mp_req_start_rxtx(dev);

	return 0;
error:
	return ret;
}

/**
 * @brief Stop VF device: disable queues and notify PF.
 *
 * Disables RX/TX queues and clears link status for the VF. Returns 0 on
 * success when the DPDK version expects an int, otherwise returns void.
 *
 * @param dev Pointer to the VF Ethernet device.
 * @return 0 on success (when applicable).
 */
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
static int mcevf_dev_stop(struct rte_eth_dev *dev)
#else
static void mcevf_dev_stop(struct rte_eth_dev *dev)
#endif
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct rte_eth_link link = {};

	PMD_INIT_FUNC_TRACE();
	/* Disable datapath on secondary process. */
	mce_mp_req_stop_rxtx(dev);
	mcevf_mbx_set_vf2pf_stat(hw);

	mce_disable_all_rx_queue(dev);
	mce_disable_all_tx_queue(dev);

	rte_eth_linkstatus_set(dev, &link);

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
/**
 * @brief Provide flow operations implementation to DPDK for this VF device.
 *
 * @param dev Pointer to the VF Ethernet device.
 * @param ops Output pointer to store the flow ops implementation.
 * @return 0 on success, negative errno on invalid argument.
 */
static int mcevf_dev_flow_ops_get(struct rte_eth_dev *dev,
				  const struct rte_flow_ops **ops)
{
	if (!dev)
		return -EINVAL;

	*ops = &mce_flow_ops;

	return 0;
}
#else
static int mcevf_filter_ctrl(struct rte_eth_dev *dev,
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
static int mcevf_promisc_enable(struct rte_eth_dev *dev)
#else
static void mcevf_promisc_enable(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	;
#endif
	bool vlan_filter_en = 0;

	PMD_INIT_FUNC_TRACE();
	if (vport->attr.trust_on == 0) {
		PMD_DRV_LOG(ERR, "vf can't set promisc on trust off mode");
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
		return -ENOTSUP;
#else
		return;
#endif
	}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
#else
	if (dev->data->dev_conf.rxmode.hw_vlan_filter)
#endif /* RTE_VERSION >= 17.11 */
		vlan_filter_en = 1;

	mce_update_mpfm(vport, MCE_MPF_MODE_PROMISC, vlan_filter_en, 1);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mcevf_promisc_disable(struct rte_eth_dev *dev)
#else
static void mcevf_promisc_disable(struct rte_eth_dev *dev)
#endif
{
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
#endif
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	bool vlan_filter_en = 0;

	if (vport->attr.trust_on == 0) {
		PMD_DRV_LOG(ERR, "vf can't set promisc on trust off mode");
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
		return -ENOTSUP;
#else
		return;
#endif
	}
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER)
#else
	if (dev->data->dev_conf.rxmode.hw_vlan_filter)
#endif /* RTE_VERSION >= 17.11 */
		vlan_filter_en = 1;
	mce_update_mpfm(vport, MCE_MPF_MODE_PROMISC, vlan_filter_en, 0);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mcevf_allmulticast_enable(struct rte_eth_dev *dev)
#else
static void mcevf_allmulticast_enable(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);

	if (vport->attr.trust_on == 0) {
		PMD_DRV_LOG(ERR, "vf can't set promisc on trust off mode");
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
		return -ENOTSUP;
#else
		return;
#endif
	}
	mce_update_mpfm(vport, MCE_MPF_MODE_ALLMULTI, 0, 1);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#else
	return;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mcevf_allmulticast_disable(struct rte_eth_dev *dev)
#else
static void mcevf_allmulticast_disable(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);

	PMD_INIT_FUNC_TRACE();
	if (vport->attr.trust_on == 0) {
		PMD_DRV_LOG(ERR, "vf can't set promisc on trust off mode");
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
		return -ENOTSUP;
#else
		return;
#endif
	}
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

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
static void
#else
static int
#endif
mcevf_dev_set_mac(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct rte_ether_addr *old_addr;
	int ret = 0;

	old_addr = (struct rte_ether_addr *)hw->mac.set_addr;
	if (rte_is_same_ether_addr(old_addr, addr))
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
		return;
#else
		return 0;
#endif
	if (hw->mac.ops->set_rafb) {
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
		ret = hw->mac.ops->set_rafb(hw, addr->addr_bytes);
#else
		ret = hw->mac.ops->set_rafb(hw, addr->addr_bytes);
#endif
		if (ret < 0)
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
			return;
#else
			return ret;
#endif
		rte_ether_addr_copy(addr,
				    (struct rte_ether_addr *)hw->mac.set_addr);
	} else {
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		return -ENOTSUP;
#endif
	}
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	return ret;
#endif
}

#if 0
static int
mcevf_stats_get(struct rte_eth_dev *dev,
		struct rte_eth_stats *stats)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct rte_eth_dev_data *data = dev->data;
	int i = 0;

	PMD_INIT_FUNC_TRACE();
	for (i = 0; i < data->nb_rx_queues; i++) {
		if (!data->rx_queues[i])
			continue;
		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_ipackets[i] = ((struct mce_rx_queue **)
					(data->rx_queues))[i]->stats.ipackets;
			stats->q_ibytes[i] = ((struct mce_rx_queue **)
					(data->rx_queues))[i]->stats.ibytes;
			stats->ipackets += stats->q_ipackets[i];
			stats->ibytes += stats->q_ibytes[i];
		} else {
			stats->ipackets += ((struct mce_rx_queue **)
					(data->rx_queues))[i]->stats.ipackets;
			stats->ibytes += ((struct mce_rx_queue **)
					(data->rx_queues))[i]->stats.ibytes;
		}
	}

	for (i = 0; i < data->nb_tx_queues; i++) {
		if (!data->tx_queues[i])
			continue;
		if (i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			stats->q_opackets[i] = ((struct mce_tx_queue **)
					(data->tx_queues))[i]->stats.opackets;
			stats->q_obytes[i] = ((struct mce_tx_queue **)
					(data->tx_queues))[i]->stats.obytes;
			stats->opackets += stats->q_opackets[i];
			stats->obytes += stats->q_obytes[i];
		} else {
			stats->opackets += ((struct mce_tx_queue **)
					(data->tx_queues))[i]->stats.opackets;
			stats->obytes += ((struct mce_tx_queue **)
					(data->tx_queues))[i]->stats.obytes;
		}
	}
	stats->ierrors = vport->hw_stats.rx_bad_pkts;
	stats->imissed = vport->hw_stats.rx_miss_drop;

	return 0;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
mcevf_stats_reset(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw_stats *stats = &vport->hw_stats;
	struct mce_rx_queue *rxq;
	struct mce_tx_queue *txq;
	uint8_t idx;
	PMD_INIT_FUNC_TRACE();

	memset(stats, 0, sizeof(*stats));
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

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}
#endif

#if 0
static const uint32_t *
mce_dev_supported_ptypes_get(struct rte_eth_dev *dev __rte_unused)
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
		RTE_PTYPE_TUNNEL_GRE,
		RTE_PTYPE_TUNNEL_GTPC,
		RTE_PTYPE_TUNNEL_GTPU,
		RTE_PTYPE_TUNNEL_ESP,

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

	return ptypes;
}
#endif

struct rte_mcevf_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	unsigned int offset;
};

static const struct rte_mcevf_xstats_name_off rte_mcevf_stats_strings[] = {
	{ "rx_bytes", offsetof(struct mce_hw_basic_stats, rx_bytes) },
	{ "rx_unicast_packets",
	  offsetof(struct mce_hw_basic_stats, rx_unicast_pkts) },
	{ "rx_multicast_packets",
	  offsetof(struct mce_hw_basic_stats, rx_multicast_pkts) },
	{ "rx_broadcast_packets",
	  offsetof(struct mce_hw_basic_stats, rx_broadcast_pkts) },
	{ "rx_dropped_packets",
	  offsetof(struct mce_hw_basic_stats, rx_miss_drop) },
	{ "tx_bytes", offsetof(struct mce_hw_basic_stats, tx_bytes) },
	{ "rx_unicast_packets",
	  offsetof(struct mce_hw_basic_stats, tx_unicast_pkts) },
	{ "tx_multicast_packets",
	  offsetof(struct mce_hw_basic_stats, tx_multicast_pkts) },
	{ "tx_broadcast_packets",
	  offsetof(struct mce_hw_basic_stats, tx_broadcast_pkts) },
};

#define MCEVF_NB_XSTATS \
	(sizeof(rte_mcevf_stats_strings) / sizeof(rte_mcevf_stats_strings[0]))

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mcevf_dev_xstats_reset(struct rte_eth_dev *dev)
#else
static void mcevf_dev_xstats_reset(struct rte_eth_dev *dev)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);

	mce_dev_stats_reset(dev);
	memset(&vport->basic_stats, 0, sizeof(vport->basic_stats));
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
static int mcevf_dev_xstats_get(struct rte_eth_dev *dev,
				struct rte_eth_xstats *xstats, unsigned int n)
#else
static int mcevf_dev_xstats_get(struct rte_eth_dev *dev,
				struct rte_eth_xstat *xstats, unsigned int n)
#endif
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw_basic_stats *basic_stats = &vport->basic_stats;
	struct rte_eth_stats stats;
	unsigned int i = 0;

	if (n < MCEVF_NB_XSTATS)
		return MCEVF_NB_XSTATS;
#if RTE_VERSION_NUM(16, 4, 0, 0) < RTE_VERSION
	if (xstats != NULL) {
#else
	if (xstats != NULL && n) {
#endif
#if RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
		mce_dev_stats_get(dev, &stats, NULL);
#else
		mce_dev_stats_get(dev, &stats);
#endif
		RTE_SET_USED(stats);
		/* loop over xstats array and values from pstats */
		for (i = 0; i < MCEVF_NB_XSTATS; i++) {
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
			xstats[i].id = i;
#endif
			xstats[i].value = *(
				uint64_t *)(((char *)basic_stats) +
					    rte_mcevf_stats_strings[i].offset);
#if RTE_VERSION_NUM(16, 7, 0, 0) > RTE_VERSION
			snprintf(xstats[i].name, sizeof(xstats[i].name), "%s",
				 rte_mcevf_stats_strings[i].name);
#endif
		}
	}

	return MCEVF_NB_XSTATS;
}

#if RTE_VERSION_NUM(16, 7, 0, 0) <= RTE_VERSION
static int mcevf_dev_xstats_get_names(__rte_unused struct rte_eth_dev *dev,
				      struct rte_eth_xstat_name *xstats_names,
				      __rte_unused unsigned int size)
{
	unsigned int i;

	if (xstats_names != NULL)
		for (i = 0; i < MCEVF_NB_XSTATS; i++) {
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
			strlcpy(xstats_names[i].name,
				rte_mcevf_stats_strings[i].name,
				sizeof(xstats_names[i].name));
#else
			snprintf(xstats_names[i].name,
				 sizeof(xstats_names[i].name), "%s",
				 rte_mcevf_stats_strings[i].name);
#endif
		}

	return MCEVF_NB_XSTATS;
}
#endif

static int mcevf_default_ring_set(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	uint32_t default_ring =
		vport->attr.vport_id * vport->attr.max_rx_queues;
	uint32_t value = 0;

	value = MCE_E_REG_READ(hw, MCE_VF_FWD_ATTR);
	value &= ~MCE_FWD_DEF_RING_S;
	value |= default_ring << MCE_FWD_DEF_RING_S;
	MCE_E_REG_WRITE(hw, MCE_VF_FWD_ATTR, value);

	return 0;
}

static int mcevf_link_update(struct rte_eth_dev *dev,
			     int wait_to_complete __rte_unused)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct rte_eth_link link;

	memset(&link, 0, sizeof(link));
	if (dev->data->dev_started) {
		mcevf_update_pf_stat(hw);
		link.link_speed = hw->pf_stat.pf_link_speed;
		link.link_status = hw->pf_stat.pf_link_status;
		link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
#if RTE_VERSION_NUM(17, 8, 0, 0) < RTE_VERSION
		link.link_autoneg = RTE_ETH_LINK_FIXED;
#endif
	}
	*dst = link;

	return 0;
}

static int mcevf_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t frame_size = mtu + MCE_ETH_OVERHEAD;
	struct mce_vport *vport __maybe_unused = MCE_DEV_TO_VPORT(dev);
	uint32_t vp_attr_base;
	uint32_t value = 0;

	/* mtu setting is forbidden if port is start */
	if (dev->data->dev_started != 0) {
		PMD_DRV_LOG(ERR, "port %d must be stopped before configuration",
			    dev->data->port_id);
		return -EBUSY;
	}
	/* check that mtu is within the allowed range */
	if (frame_size < 64 || frame_size > 16000)
		return -EINVAL;
	vp_attr_base = hw->vp_reg_base[MCE_VP_ATTR];
	value = MCE_E_REG_READ(hw, vp_attr_base);
	value &= ~(MCE_FWD_DROP);
	value |= MCE_FWD_LIMIT_LEN_EN;
	value &= ~MCE_FWD_MAXLEN_MASK;
	value |= frame_size << MCE_FWD_MAXLEN_SHIFT;
	MCE_E_REG_WRITE(hw, vp_attr_base, value);

	return 0;
}

static int mcevf_vlan_add(struct mce_vport *vport, uint16_t vlan)
{
	struct mce_vlan_filter *filter = NULL;
	struct mce_hw *hw = vport->hw;
	struct mce_vlan_entry entry;
	int ret = 0;

	memset(&entry, 0, sizeof(entry));
	entry.vid = vlan;
	filter = mce_vlan_filter_lookup(vport, &entry);
	if (filter) {
		PMD_DRV_LOG(INFO, "vlan already exists in filter table.");
		return 0;
	}
	filter = rte_zmalloc("mce_vlan_filter",
			sizeof(struct mce_vlan_filter), 0);
	if (filter == NULL) {
		PMD_DRV_LOG(ERR, "vlan filter memory alloc failed.");
		return -ENOMEM;
	}
	filter->vlan = entry;
	ret = hw->mac.ops->add_vlan_f(hw, vlan, true);
	if (ret < 0)
		return ret;
	TAILQ_INSERT_TAIL(&vport->vlan_list, filter, next);

	return 0;
}

static int mcevf_vlan_del(struct mce_vport *vport, uint16_t vlan)
{
	struct mce_vlan_filter *filter = NULL;
	struct mce_hw *hw = vport->hw;
	struct mce_vlan_entry entry;
	int ret = 0;

	memset(&entry, 0, sizeof(entry));
	entry.vid = vlan;
	filter = mce_vlan_filter_lookup(vport, &entry);
	if (!filter) {
		PMD_DRV_LOG(INFO, "vlan already del in table");
		return 0;
	}
	ret = hw->mac.ops->add_vlan_f(hw, vlan, false);
	if (ret < 0)
		return ret;
	TAILQ_REMOVE(&vport->vlan_list, filter, next);
	memset(filter, 0, sizeof(*filter));
	rte_free(filter);

	return 0;
}

static int mcevf_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id,
				 int add)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);

	if (add)
		return mcevf_vlan_add(vport, vlan_id);
	else
		return mcevf_vlan_del(vport, vlan_id);
}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
static int mcevf_vlan_offload_set(struct rte_eth_dev *dev, int mask)
#else
static void mcevf_vlan_offload_set(struct rte_eth_dev *dev, int mask)
#endif
{
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
#endif
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t strip_layers = 0;
	uint16_t cfg_num = 0;
	bool strip_en = false;
	uint16_t index = 0;

	if (mask & RTE_ETH_VLAN_FILTER_MASK) {
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_FILTER) {
#else
		if (dev->data->dev_conf.rxmode.hw_vlan_filter) {
#endif
			hw->mac.ops->en_vlan_f(hw, true);
		} else {
			if (hw->trust_on == 0) {
				PMD_DRV_LOG(ERR,
					"vf can't set vlan filter off trust off mode");
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
				return -ENOTSUP;
#else
				return;
#endif
			}
			hw->mac.ops->en_vlan_f(hw, false);
		}
	}
	if (mask & RTE_ETH_VLAN_STRIP_MASK) {
		strip_layers = 1;
		/*if (!(rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP))
		    strip_layers--;*/
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
#else
		if (dev->data->dev_conf.rxmode.hw_vlan_strip)
#endif
			strip_en = true;
		else
			strip_en = false;
	}
#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
	if (mask & RTE_ETH_QINQ_STRIP_MASK) {
		strip_layers = 2;
		/*if (!(rxmode->offloads & RTE_ETH_RX_OFFLOAD_QINQ_STRIP))
		    strip_layers--;*/
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_QINQ_STRIP)
#else
		if (dev->data->dev_conf.rxmode.hw_vlan_extend)
#endif
			strip_en = true;
		else
			strip_en = false;
	}
#endif
	if (strip_layers != 0) {
		cfg_num = RTE_MIN(dev->data->nb_rx_queues, 4);
		for (index = 0; index < cfg_num; index++)
			hw->mac.ops->en_strip_f(hw, strip_layers, index,
						strip_en);
	}
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static void mcevf_vlan_strip_queue_set(struct rte_eth_dev *dev, uint16_t queue,
				       int on)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_rx_queue *rxq;
	uint16_t strip_layers = 1;
	bool strip_en = false;

	rxq = dev->data->rx_queues[queue];
	if (rxq) {
		if (on) {
			strip_en = true;
			rxq->rx_offload_capa |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
		} else {
			strip_en = false;
			rxq->rx_offload_capa &= ~RTE_ETH_RX_OFFLOAD_VLAN_STRIP;
		}
	}
	hw->mac.ops->en_strip_f(hw, strip_layers, queue, strip_en);

	return;
}

static int mcevf_set_mc_addr_list(struct rte_eth_dev *dev,
				  struct rte_ether_addr *mc_addr_list,
				  uint32_t nb_mc_addr)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t index = 0;
	int ret = -EIO;

	if (nb_mc_addr > vport->attr.max_mcast_addrs) {
		PMD_DRV_LOG(ERR, "set multicast address is over max.");
		return -ENOMEM;
	}
	ret = hw->mac.ops->clear_mc_filter(hw);
	if (ret)
		return ret;
	/* remove mc_addr become to 0 */
	if (nb_mc_addr == 0)
		return 0;

	for (index = 0; index < nb_mc_addr; index++) {
		if (hw->mac.ops->update_mta) {
			ret = hw->mac.ops->update_mta(
				hw, mc_addr_list[index].addr_bytes, index);
			if (ret < 0) {
				PMD_DRV_LOG(ERR,
					    "set multicast address failed.");
				return ret;
			}
		}
	}

	return ret;
}

static bool mce_vf_is_vf_isolated_enabled(struct mce_hw *hw)
{
	unsigned int v = rd32(hw, N20_VFNUM_NO_ISOLAT);

	if ((v & 0xfff00000) == 0)
		return true;
	else
		return false;
}

static int mce_vf_get_vfnum(struct mce_hw *hw)
{
	int vfnum = -1;
	u32 val;

	hw->is_vf_isolated_enabled = mce_vf_is_vf_isolated_enabled(hw);

	if (hw->is_vf_isolated_enabled)
		val = rd32(hw, N20_VFNUM_ISOLATED);
	else
		val = rd32(hw, N20_VFNUM_NO_ISOLAT);

	vfnum = val & 0xff;
	printf("%s: vf-isolat-enabled:%d vfnum:%d\n", hw->device_name,
	       hw->is_vf_isolated_enabled, vfnum);

	return vfnum;
}
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
static void
mcevf_dev_interrupt_handler(struct rte_intr_handle *handle __rte_unused,
			    void *param)
#else
static void mcevf_dev_interrupt_handler(void *param)
#endif
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct mce_adapter *adapter = MCE_DEV_TO_ADAPTER(dev);
	struct mce_hw *hw = &adapter->hw;

	mce_mbx_clean_all_incomming_req(hw, mcevf_mbx_pf2vf_event_req_isr,
					mcevf_mbx_pf2vf_req_isr);

	return;
}

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
static int mcevf_dev_close(struct rte_eth_dev *eth_dev)
#else
static void mcevf_dev_close(struct rte_eth_dev *eth_dev)
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
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		return 0;
#else
		return;
#endif
	} else {
		mce_mp_req_removed(eth_dev);
	}
	mcevf_dev_stop(eth_dev);
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
			mcevf_dev_interrupt_handler, eth_dev);
	mce_mbx_drv_send_uninstall_notify_fw(vport->hw);
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	free(eth_dev->process_private);
#endif
	mce_destory_vport(vport);

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static const struct eth_dev_ops mcevf_eth_dev_ops = {
	.dev_configure = mcevf_dev_configure,
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.dev_infos_get = mcevf_dev_infos_get,
#endif
	.dev_start = mcevf_dev_start,
	.dev_stop = mcevf_dev_stop,
	.dev_close = mcevf_dev_close,
	.mtu_set = mcevf_dev_mtu_set,

	.link_update = mcevf_link_update,

	.rx_queue_start = mce_rx_queue_start,
	.rx_queue_stop = mce_rx_queue_stop,
	.tx_queue_start = mce_tx_queue_start,
	.tx_queue_stop = mce_tx_queue_stop,
	.rx_queue_setup = mce_rx_queue_setup,
	.tx_queue_setup = mce_tx_queue_setup,

	.rx_queue_intr_enable = mce_dev_rx_queue_intr_enable,
	.rx_queue_intr_disable = mce_dev_rx_queue_intr_disable,
	.set_queue_rate_limit = mce_dev_txq_rate_limit,
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	.rx_queue_release = mce_dev_rx_queue_release,
	.tx_queue_release = mce_dev_tx_queue_release,
#else
	.rx_queue_release = mce_rx_queue_release,
	.tx_queue_release = mce_tx_queue_release,
#endif
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	.rxq_info_get = mce_rx_queue_info_get,
	.txq_info_get = mce_tx_queue_info_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.rx_burst_mode_get = mce_rx_burst_mode_get,
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	.tx_burst_mode_get = mce_tx_burst_mode_get,
#endif
	.reta_update = mce_rss_reta_update,
	.reta_query = mce_rss_reta_query,
	.rss_hash_update = mce_rss_hash_set,
	.rss_hash_conf_get = mce_rss_hash_conf_get,
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
	.flow_ops_get = mcevf_dev_flow_ops_get,
#else
	.filter_ctrl = mcevf_filter_ctrl,
#endif
	.promiscuous_enable = mcevf_promisc_enable,
	.promiscuous_disable = mcevf_promisc_disable,
	.allmulticast_enable = mcevf_allmulticast_enable,
	.allmulticast_disable = mcevf_allmulticast_disable,
	.mac_addr_set = mcevf_dev_set_mac,

	.vlan_filter_set = mcevf_vlan_filter_set,
	.vlan_offload_set = mcevf_vlan_offload_set,
	.vlan_strip_queue_set = mcevf_vlan_strip_queue_set,

	.set_mc_addr_list = mcevf_set_mc_addr_list,

	.stats_get = mce_dev_stats_get,
	.stats_reset = mce_dev_stats_reset,

	.xstats_get = mcevf_dev_xstats_get,
#if RTE_VERSION_NUM(16, 7, 0, 0) <= RTE_VERSION
	.xstats_get_names = mcevf_dev_xstats_get_names,
#endif
	.xstats_reset = mcevf_dev_xstats_reset,
};

static int mcevf_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct mce_adapter *adapter = MCE_DEV_TO_ADAPTER(eth_dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct mce_vport *vport = MCE_DEV_TO_VPORT(eth_dev);
	struct mce_vf *vf = MCE_DEV_TO_VF(eth_dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(eth_dev);
	uint8_t fix_mac[6] = { 0x00, 0x3A, 0x56, 0xA0, 0xE7 };
	int ret = 0;

	PMD_INIT_FUNC_TRACE();
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
	if (mce_get_pcie_link_state(pci_dev, hw) < 0) {
		PMD_INIT_LOG(ERR, "Failed to read pcie config");
		return -EINVAL;
	}
#endif
	eth_dev->dev_ops = &mcevf_eth_dev_ops;
	eth_dev->rx_pkt_burst = mce_rx_recv_pkts;
	eth_dev->tx_pkt_burst = mce_xmit_simple;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	eth_dev->tx_pkt_prepare = mce_prep_pkts;
#endif
	ret = mce_mp_init(eth_dev);
	if (ret < 0) {
		PMD_INIT_LOG(ERR, "vf mp process sync init failed");
		return ret;
	}
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		mce_setup_rx_function(eth_dev);
		mce_setup_tx_function(eth_dev);
		return 0;
	}
	adapter->vf.dev_data = eth_dev->data;
	adapter->vf.dev = eth_dev;
	hw->nic_base = pci_dev->mem_resource[MCE_NIC_CTRL_BAR].addr;
	hw->pci_dev = pci_dev;
	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->back = adapter;
	hw->function = pci_dev->addr.function;
	hw->is_vf = MCE_VPORT_IS_VF;
	hw->vfnum = mce_vf_get_vfnum(hw);
	mce_init_ops_vf(hw);
	/* init mailbox */
	mce_setup_vf2pf_mbx_info(hw, &hw->vf2pf_mbx);
	mce_mbx_init_configure(&hw->vf2pf_mbx);

	/* reset vf */
	if (hw->mac.ops->reset_hw(hw))
		return -EPERM;
	hw->mac.ops->init_hw(hw);
	vport = mce_alloc_vport(hw, MCE_VPORT_IS_VF);
	if (vport == NULL)
		goto alloc_failed;
	vf->vf_vport = vport;
	/* get from hwinfo to sw init */
	fix_mac[4] += vport->attr.vport_id;
	if (!rte_is_valid_assigned_ether_addr(
			 (struct rte_ether_addr *)hw->mac.assign_addr)) {
		rte_ether_addr_copy(
			(const struct rte_ether_addr *)fix_mac,
			(struct rte_ether_addr *)(&hw->mac.assign_addr));
		printf("assgin_addr is zero \n");
	}
	eth_dev->data->mac_addrs = rte_zmalloc(
		"mcevf",
		sizeof(struct rte_ether_addr) * vport->attr.max_mac_addrs, 0);
	if (!eth_dev->data->mac_addrs) {
		PMD_DRV_LOG(ERR, "Memory allocation "
				 "for MAC failed! Exiting.\n");
		return -ENOMEM;
	}
	rte_ether_addr_copy((const struct rte_ether_addr *)hw->mac.assign_addr,
			    eth_dev->data->mac_addrs);

	/* register callback func to eal lib */
	rte_intr_callback_register(
			intr_handle, mcevf_dev_interrupt_handler, eth_dev);
	rte_intr_enable(intr_handle);
	mce_mbx_vector_set(&hw->vf2pf_mbx, 0, true);
	mcevf_set_mbx_init_done(hw, true);

	return 0;

alloc_failed:
	return -ENOMEM;
}

static int mcevf_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(eth_dev);

	/* Nothing to be done for secondary & primary processes */
	mce_mp_uinit(eth_dev);
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;
	mcevf_set_mbx_init_done(hw, false);

	return 0;
}

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
static int mcevf_pci_remove(struct rte_pci_device *pci_dev)
{
	char device_name[PCI_PRI_STR_SIZE] = "";
	struct rte_eth_dev *eth_dev;
	int rc;

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
						    mcevf_eth_dev_uninit);
		if (rc)
			return rc;
	}

	return 0;
}

static int mcevf_pci_probe(struct rte_pci_driver *pci_drv,
			   struct rte_pci_device *pci_dev)
{
	int rc;

	RTE_SET_USED(pci_drv);

	rc = rte_eth_dev_pci_generic_probe(pci_dev, sizeof(struct mce_adapter),
					   mcevf_eth_dev_init);

	return rc;
}
#endif /* RTE_VERSION >= 17.05 */
static const struct rte_pci_id pci_id_mcevf_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, 0xa03f) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_MUCSE, 0x8503) },
	{
		.vendor_id = 0,
	},
};

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
static struct rte_pci_driver rte_mcevf_pmd = {
	.id_table = pci_id_mcevf_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = mcevf_pci_probe,
	.remove = mcevf_pci_remove,
};
bool is_mcevf_supported(struct rte_eth_dev *dev)
{
	return mce_is_device_supported(dev, &rte_mcevf_pmd);
}
RTE_PMD_REGISTER_PCI(net_mcevf, rte_mcevf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_mcevf, pci_id_mcevf_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mcevf, "* igb_uio | vfio-pci");
#else /* RTE_VERSION < 17.05 */
static struct eth_driver rte_mcevf_pmd = {
	.pci_drv = {
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
		.name      = "rte_mcevf_pmd",
#endif
		.id_table  = pci_id_mcevf_map,
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
	.eth_dev_init     = mcevf_eth_dev_init,
	.eth_dev_uninit   = mcevf_eth_dev_uninit,
	.dev_private_size = sizeof(struct mce_adapter),
};
#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
RTE_PMD_REGISTER_PCI(net_mcevf, rte_mcevf_pmd.pci_drv);
RTE_PMD_REGISTER_PCI_TABLE(net_mcevf, pci_id_mcevf_map);
#if RTE_VERSION_NUM(17, 2, 0, 16) <= RTE_VERSION
RTE_PMD_REGISTER_KMOD_DEP(net_mcevf, "igb_uio | uio_pci_generic | vfio-pci");
#endif /* RTE_VERSION >= 17.2.0.16 && RTE_VERSION < 17.5 */
#else /* RTE_VERSION < 16.11 */
static int rte_mcevf_pmd_init(const char *name __rte_unused,
			      const char *params __rte_unused)
{
	PMD_INIT_FUNC_TRACE();

	rte_eth_driver_register(&rte_mcevf_pmd);
	return 0;
}
static struct rte_driver rte_mcevf_driver = {
	.type = PMD_PDEV,
	.init = rte_mcevf_pmd_init,
};
#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
PMD_REGISTER_DRIVER(rte_mcevf_driver);
#else /* RTE_VERSION > 16.4.0.16 */
PMD_REGISTER_DRIVER(rte_mcevf_driver, mcevf);
DRIVER_REGISTER_PCI_TABLE(mcevf, pci_id_mcevf_map);
#endif /* RTE_VERSION <= 16.4.0.16 */
#endif /* RTE_VERSION >= 16.11 && RTE_VERSION < 17.05 */
#endif /* RTE_VERSION >=17.05 && RTE_VERSION < 21.05 */
/*-----------------------------------------------------*/
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
RTE_LOG_REGISTER_SUFFIX(mcevf_logtype_init, init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(mcevf_logtype_driver, driver, NOTICE);
#elif RTE_VERSION_NUM(20, 8, 0, 0) < RTE_VERSION && \
	RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
RTE_LOG_REGISTER(mcevf_logtype_init, init, DEBUG);
RTE_LOG_REGISTER(mcevf_logtype_driver, driver, NOTICE);
#else /* RTE_VERSION < 20.02 */
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
int mcevf_logtype_init;
int mcevf_logtype_driver;
RTE_INIT(mcevf_init_log)
{
	mcevf_logtype_init = rte_log_register("pmd.net.mcevf.init");
	rte_log_set_level(mcevf_logtype_init, RTE_LOG_DEBUG);
	mcevf_logtype_driver = rte_log_register("pmd.net.mcevf.driver");
	if (mcevf_logtype_driver >= 0)
		rte_log_set_level(mcevf_logtype_driver, RTE_LOG_NOTICE);
}
#endif /* RTE_VERSION >= 17.05 && RTE_VERSION < 20.02 */
#endif /* RTE_VERSION >= 21.05 */
