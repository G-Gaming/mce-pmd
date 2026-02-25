/**
 * @file mce_vf_representor.c
 * @brief MCE VF Representor Device Operations and Management
 *
 * This module implements the Ethernet device operations for MCE Virtual Function
 * (VF) representor ports. VF representors are software abstractions that represent
 * VF ports in the control plane, allowing management and monitoring of VF traffic
 * through standard DPDK Ethernet device interfaces.
 *
 * @details
 * The VF representor implementation provides:
 * - Device configuration and lifecycle management (start/stop)
 * - Queue setup and tear-down operations (Rx/Tx queues)
 * - Statistics collection and reporting
 * - Link state management
 * - Flow filtering and control operations
 * - Packet burst operations for data-path simulation
 *
 * The representor devices are registered as virtual Ethernet ports and use
 * ring-based communication with the representor proxy for packet forwarding.
 *
 * @note This module requires DPDK version 18.2 or later
 * @see mce_vf_representor.h for structure definitions
 * @see mce_route_proxy.h for proxy-related operations
 */

#include <stdio.h>

#include <rte_version.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_kvargs.h>

#include "mce_rss.h"
#include "mce_rxtx.h"
#include "mce.h"
#include "mce_route_proxy.h"
#include "mce_vf_representor.h"
#include "mce_logs.h"

#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION

/**
 * @brief Retrieve VF representor device information and capabilities.
 *
 * Populates the device information structure with representor capabilities,
 * queue limits, offload capabilities, and default Rx/Tx configurations.
 * The function also sets up device link information inherited from the parent PF.
 *
 * @param ethdev Pointer to the VF representor Ethernet device
 * @param dev_info Pointer to the device info structure to be filled
 *
 * @return 0 on success (for DPDK >= 19.11)
 * @return void (for DPDK < 19.11)
 *
 * @note Capabilities include checksum offloads, TSO, VLAN operations
 * @note Maximum queues: MCE_REPR_MAX_RX_QUEUE and MCE_REPR_MAX_TX_QUEUE
 */
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_vf_representor_dev_infos_get(struct rte_eth_dev *ethdev,
					    struct rte_eth_dev_info *dev_info)
#else
static void mce_vf_representor_dev_infos_get(struct rte_eth_dev *ethdev __rte_unused,
					     struct rte_eth_dev_info *dev_info)
#endif
{
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	struct mce_vf_representor *representor = ethdev->data->dev_private;
#endif

#if RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(ethdev);

	dev_info->pci_dev = pci_dev;
#endif
	/* get dev info for the vdev */
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	dev_info->device = ethdev->device;
#endif
	dev_info->max_rx_queues = MCE_REPR_MAX_RX_QUEUE;
	dev_info->max_tx_queues = MCE_REPR_MAX_TX_QUEUE;

	dev_info->min_rx_bufsize = MCE_BUFF_SIZE_MIN;
	dev_info->max_rx_pktlen = MCE_MAX_FRAME_SIZE;
	dev_info->hash_key_size = (MCE_MAX_HASH_KEY_SIZE) * sizeof(uint32_t);
	dev_info->reta_size = MCE_MAX_RETA_LOC_SIZE;
	dev_info->flow_type_rss_offloads = MCE_SUPPORT_RSS_OFFLOAD_ALL;
	dev_info->max_mac_addrs = 1;
	dev_info->rx_offload_capa =
		RTE_ETH_RX_OFFLOAD_VLAN_STRIP | RTE_ETH_RX_OFFLOAD_QINQ_STRIP |
		RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
		RTE_ETH_RX_OFFLOAD_TCP_CKSUM | RTE_ETH_RX_OFFLOAD_VLAN_FILTER;
	dev_info->tx_offload_capa =
		RTE_ETH_TX_OFFLOAD_MULTI_SEGS | RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
		RTE_ETH_TX_OFFLOAD_QINQ_INSERT | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
		RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
		RTE_ETH_TX_OFFLOAD_SCTP_CKSUM |
		RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM |
		RTE_ETH_TX_OFFLOAD_TCP_TSO | RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO |
		RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO;

	dev_info->default_rxconf = (struct rte_eth_rxconf){
		/* clang-format off */
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
		/* clang-format on */
	};

	dev_info->default_txconf = (struct rte_eth_txconf){
		/* clang-format off */
		.tx_thresh = {
				.pthresh = MCE_TX_DESC_HIGH_WATER_TH,
				.hthresh = MCE_TX_DEFAULT_BURST,
				.wthresh = MCE_TX_DEFAULT_WTHRESH,
			},
		.tx_free_thresh = MCE_DEFAULT_TX_FREE_THRESH,
		.tx_rs_thresh = MCE_DEFAULT_TX_RS_THRESH,
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		.offloads = 0,
#endif
		/* clang-format on */
	};
	dev_info->rx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = 4096,
		.nb_min = 128,
		.nb_align = 2,
	};
	dev_info->tx_desc_lim = (struct rte_eth_desc_lim){
		.nb_max = 4096,
		.nb_min = 128,
		.nb_align = 2,
		.nb_seg_max = 32,
		.nb_mtu_seg_max = 4096,
	};
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	dev_info->switch_info.name =
		rte_eth_devices[ethdev->data->port_id].device->name;
	dev_info->switch_info.domain_id = representor->switch_domain_id;
	dev_info->switch_info.port_id = representor->vf_id;
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

static int
mce_vf_representor_dev_configure(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

/**
 * @brief Start the VF representor device.
 *
 * Sets the representor state to active, enabling packet processing and
 * management operations. This function is called after device configuration
 * is complete.
 *
 * @param dev Pointer to the VF representor Ethernet device
 *
 * @return 0 on successful start
 *
 * @note Must be called after device configuration (dev_configure)
 * @see mce_vf_representor_dev_stop() for device shutdown
 */
static int mce_vf_representor_dev_start(struct rte_eth_dev *dev)
{
	struct mce_vf_representor *representor = dev->data->dev_private;

	representor->state = 1;

	return 0;
}

/**
 * @brief Stop the VF representor device.
 *
 * Sets the representor state to inactive, disabling packet processing and
 * management operations. Cleans up any active data paths.
 *
 * @param dev Pointer to the VF representor Ethernet device
 *
 * @return 0 on successful stop (for DPDK < 20.11)
 * @return void (for DPDK >= 20.11)
 *
 * @note After stopping, device can be reconfigured or closed
 * @see mce_vf_representor_dev_start() for device startup
 */
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
static int mce_vf_representor_dev_stop(struct rte_eth_dev *dev)
#else
static void mce_vf_representor_dev_stop(struct rte_eth_dev *dev)
#endif
{
	struct mce_vf_representor *representor = dev->data->dev_private;

	representor->state = 0;

#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
	return 0;
#endif
}
/**
 * @brief Create a ring-based communication channel for VF representor.
 *
 * Allocates and initializes a ring for packet buffering between the representor
 * and its associated proxy handler. Uses single-producer/consumer mode since
 * both ends are guaranteed to be single-threaded.
 *
 * @param pf_port_id PF port identifier
 * @param repr_id Representor/VF identifier
 * @param type_name Type of queue (\"rx\" or \"tx\")
 * @param qid Queue index identifier
 * @param nb_desc Number of descriptors (ring size)
 * @param socket_id NUMA socket identifier for memory allocation
 * @param ring Output parameter: pointer to the created ring
 *
 * @return 0 on successful ring creation
 * @return -ENAMETOOLONG if ring name exceeds maximum allowed length
 * @return -rte_errno if ring creation fails
 *
 * @note DPDK version 21.11+
 * @note Uses RING_F_MP_RTS_ENQ | RING_F_SC_DEQ flags
 * @see rte_ring_create() for ring creation details
 */#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static int mce_repr_ring_create(uint16_t pf_port_id, uint16_t repr_id,
				const char *type_name, uint16_t qid,
				uint16_t nb_desc, unsigned int socket_id,
				struct rte_ring **ring)
{
	char ring_name[RTE_RING_NAMESIZE];
	int ret;

	ret = snprintf(ring_name, sizeof(ring_name), "mce_%u_repr_%u_%sq%u",
		       pf_port_id, repr_id, type_name, qid);
	if (ret >= (int)sizeof(ring_name))
		return -ENAMETOOLONG;
	/*
	 * Single producer/consumer rings are used since the API for Tx/Rx
	 * packet burst for representors are guaranteed to be called from
	 * a single thread, and the user of the other end (representor proxy)
	 * is also single-threaded.
	 */
	*ring = rte_ring_create(ring_name, nb_desc, socket_id,
				RING_F_MP_RTS_ENQ | RING_F_SC_DEQ);
	if (*ring == NULL)
		return -rte_errno;

	return 0;
}

/**
 * @brief Configure and setup a receive queue for the VF representor.
 *
 * Allocates and initializes a receive queue structure with an underlying ring
 * buffer for packet reception. The queue is connected to the parent PF for
 * receiving packets destined to the VF.
 *
 * @param dev Pointer to the VF representor Ethernet device
 * @param rx_queue_id Queue index identifier
 * @param nb_rx_desc Number of receive descriptors
 * @param socket_id NUMA socket identifier for memory allocation
 * @param rx_conf Pointer to Rx configuration (unused)
 * @param mb_pool Pointer to memory pool for mbufs (unused)
 *
 * @return 0 on successful queue setup
 * @return Negative error code on failure
 *
 * @note DPDK version 21.11+
 * @note Queue statistics are initialized to zero
 * @see mce_repr_ring_create() for ring creation
 */
static int mce_vf_representor_rx_queue_setup(
	struct rte_eth_dev *dev, uint16_t rx_queue_id, uint16_t nb_rx_desc,
	unsigned int socket_id,
	__rte_unused const struct rte_eth_rxconf *rx_conf,
	__rte_unused struct rte_mempool *mb_pool)
{
	struct mce_vf_representor *repr = dev->data->dev_private;
	struct mce_pf *pf = MCE_DEV_TO_PF(repr->adapter->pf.pf_vport);
	struct mce_repr_rxq *rxq = NULL;
	int ret = -EINVAL;

	rxq = rte_zmalloc_socket("mce-repr-rxq", sizeof(*rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);

	ret = mce_repr_ring_create(pf->dev_data->port_id, repr->port_id, "rx",
				   rx_queue_id, nb_rx_desc, socket_id,
				   &rxq->ring);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "repr[%d] rxq[%d] setup failed", repr->port_id,
			    rx_queue_id);
		return ret;
	}
	dev->data->rx_queues[rx_queue_id] = rxq;
	repr->rxqs[rx_queue_id] = rxq;

	return 0;
}

/**
 * @brief Configure and setup a transmit queue for the VF representor.
 *
 * Allocates and initializes a transmit queue structure with an underlying ring
 * buffer for packet transmission. The queue is connected to the parent PF for
 * sending packets from the VF.
 *
 * @param dev Pointer to the VF representor Ethernet device
 * @param tx_queue_id Queue index identifier
 * @param nb_tx_desc Number of transmit descriptors
 * @param socket_id NUMA socket identifier for memory allocation
 * @param tx_conf Pointer to Tx configuration (unused)
 *
 * @return 0 on successful queue setup
 * @return Negative error code on failure
 *
 * @note DPDK version 21.11+
 * @note Queue statistics are initialized to zero
 * @see mce_repr_ring_create() for ring creation
 */
static int mce_vf_representor_tx_queue_setup(
	struct rte_eth_dev *dev, uint16_t tx_queue_id, uint16_t nb_tx_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct mce_vf_representor *repr = dev->data->dev_private;
	struct mce_pf *pf = MCE_DEV_TO_PF(repr->adapter->pf.pf_vport);
	struct mce_repr_txq *txq = NULL;
	int ret = -EINVAL;

	txq = rte_zmalloc_socket("mce-repr-txq", sizeof(*txq),
				 RTE_CACHE_LINE_SIZE, socket_id);

	ret = mce_repr_ring_create(pf->dev_data->port_id, repr->port_id, "tx",
				   tx_queue_id, nb_tx_desc, socket_id,
				   &txq->ring);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "repr[%d] rxq[%d] setup failed", repr->port_id,
			    tx_queue_id);
		return ret;
	}
	dev->data->tx_queues[tx_queue_id] = txq;
	repr->txqs[tx_queue_id] = txq;

	return 0;
}
#else
static int mce_vf_representor_rx_queue_setup(
	struct rte_eth_dev *dev, uint16_t rx_queue_id, uint16_t nb_rx_desc,
	unsigned int socket_id,
	__rte_unused const struct rte_eth_rxconf *rx_conf,
	__rte_unused struct rte_mempool *mb_pool)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(rx_queue_id);
	RTE_SET_USED(nb_rx_desc);
	RTE_SET_USED(socket_id);

	return 0;
}

static int mce_vf_representor_tx_queue_setup(
	struct rte_eth_dev *dev, uint16_t tx_queue_id, uint16_t nb_tx_desc,
	unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf __rte_unused)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(tx_queue_id);
	RTE_SET_USED(nb_tx_desc);
	RTE_SET_USED(socket_id);

	return 0;
}
#endif

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_vf_representor_promiscuous_enable(struct rte_eth_dev *ethdev)
#else
static void mce_vf_representor_promiscuous_enable(struct rte_eth_dev *ethdev)
#endif
{
	RTE_SET_USED(ethdev);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int mce_vf_representor_promiscuous_disable(struct rte_eth_dev *ethdev)
#else
static void mce_vf_representor_promiscuous_disable(struct rte_eth_dev *ethdev)
#endif
{
	RTE_SET_USED(ethdev);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
mce_vf_representor_allmulticast_enable(__rte_unused struct rte_eth_dev *ethdev)
#else
static void
mce_vf_representor_allmulticast_enable(__rte_unused struct rte_eth_dev *ethdev)
#endif
{
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
mce_vf_representor_allmulticast_disable(__rte_unused struct rte_eth_dev *ethdev)
#else
static void
mce_vf_representor_allmulticast_disable(__rte_unused struct rte_eth_dev *ethdev)
#endif
{
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

/**
 * @brief Retrieve accumulated statistics from all representor queues.
 *
 * Collects packet counts and byte counts from all active receive and transmit
 * queues, aggregating them into the provided statistics structure.
 *
 * @param eth_dev Pointer to the VF representor Ethernet device
 * @param stats Pointer to statistics structure to be filled
 * @param qstats Pointer to per-queue statistics (DPDK >= 25.11, unused)
 *
 * @return 0 on successful statistics retrieval
 *
 * @note Statistics include:
 *   - ipackets: Total received packets
 *   - ibytes: Total received bytes
 *   - opackets: Total transmitted packets
 *   - obytes: Total transmitted bytes
 * @see mce_vf_representor_stats_reset() for clearing statistics
 */
#if RTE_VERSION_NUM(25, 11, 0, 0) <= RTE_VERSION
static int mce_vf_representor_stats_get(struct rte_eth_dev *eth_dev,
					struct rte_eth_stats *stats,
					struct eth_queue_stats *qstats __rte_unused
					)
#else
static int mce_vf_representor_stats_get(struct rte_eth_dev *eth_dev,
					struct rte_eth_stats *stats)
#endif
{
	struct mce_repr_rxq *rxq = NULL;
	struct mce_repr_txq *txq = NULL;
	uint16_t i;

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		rxq = eth_dev->data->rx_queues[i];
		if (rxq == NULL)
			continue;
		stats->ipackets += rxq->stats.ipackets;
		stats->ibytes += rxq->stats.ibytes;
	}
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		txq = eth_dev->data->tx_queues[i];

		stats->opackets += txq->stats.opackets;
		stats->obytes += txq->stats.obytes;
	}

	return 0;
}

/**
 * @brief Reset all accumulated statistics for the representor.
 *
 * Clears the statistics counters for all active receive and transmit queues,
 * resetting packet and byte counters to zero.
 *
 * @param eth_dev Pointer to the VF representor Ethernet device (unused)
 *
 * @return 0 on successful reset (for DPDK >= 19.11)
 * @return void (for DPDK < 19.11)
 *
 * @note All queue statistics are set to zero
 * @see mce_vf_representor_stats_get() for retrieving statistics
 */
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static int
#else
static void
#endif
mce_vf_representor_stats_reset(__rte_unused struct rte_eth_dev *eth_dev)
{
	struct mce_repr_rxq *rxq = NULL;
	struct mce_repr_txq *txq = NULL;
	uint16_t i;

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		rxq = eth_dev->data->rx_queues[i];
		if (rxq == NULL)
			continue;
		memset(&rxq->stats, 0, sizeof(rxq->stats));
	}
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		txq = eth_dev->data->tx_queues[i];

		memset(&rxq->stats, 0, sizeof(txq->stats));
	}
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	return 0;
#endif
}

/**
 * @brief Update link state information for the representor.
 *
 * Queries and updates the link state (speed, duplex, status) of the VF representor.
 * The representor inherits link state from its parent PF device.
 *
 * @param ethdev Pointer to the VF representor Ethernet device
 * @param wait_to_complete Wait for link state to stabilize (unused)
 *
 * @return 0 on successful link update
 *
 * @note Link state is inherited from parent PF
 */
static int mce_vf_representor_link_update(struct rte_eth_dev *ethdev,
					  int wait_to_complete)
{
	RTE_SET_USED(ethdev);
	RTE_SET_USED(wait_to_complete);

	return 0;
}

/**
 * @brief Retrieve flow operation callbacks for the representor.
 *
 * Returns the flow filter operation table for the VF representor, enabling
 * rte_flow-based traffic filtering and steering on the representor port.
 *
 * @param dev Pointer to the VF representor Ethernet device
 * @param ops Output parameter: pointer to flow operations structure
 *
 * @return 0 on successful retrieval of flow operations
 * @return -EIO if parent PF is invalid
 *
 * @note DPDK version 21.5+
 * @note Uses mce_flow_ops from the parent PF
 * @see mce_flow_ops for available flow operations
 */
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
static int mce_vf_rep_flow_ops_get(struct rte_eth_dev *dev,
				   const struct rte_flow_ops **ops)
{
	struct mce_pf *pf = NULL;

	if (mce_eth_dev_is_repr(dev)) {
		struct mce_vf_representor *vfr = dev->data->dev_private;

		pf = &vfr->adapter->pf;
		/* parent is deleted while children are still valid */
		if (!pf) {
			printf("mce Port:%d VFR Error", dev->data->port_id);
			return -EIO;
		}
	}
	*ops = &mce_flow_ops;

	return 0;
}
#else
static int mce_vf_rep_filter_ctrl(struct rte_eth_dev *dev,
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

static const struct eth_dev_ops mce_representor_dev_ops = {
	.dev_infos_get = mce_vf_representor_dev_infos_get,

	.dev_start = mce_vf_representor_dev_start,
	.dev_configure = mce_vf_representor_dev_configure,
	.dev_stop = mce_vf_representor_dev_stop,

	.rx_queue_setup = mce_vf_representor_rx_queue_setup,
	.tx_queue_setup = mce_vf_representor_tx_queue_setup,

	.link_update = mce_vf_representor_link_update,

	.stats_get = mce_vf_representor_stats_get,
	.stats_reset = mce_vf_representor_stats_reset,

	.promiscuous_enable = mce_vf_representor_promiscuous_enable,
	.promiscuous_disable = mce_vf_representor_promiscuous_disable,

	.allmulticast_enable = mce_vf_representor_allmulticast_enable,
	.allmulticast_disable = mce_vf_representor_allmulticast_disable,
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
	.flow_ops_get = mce_vf_rep_flow_ops_get,
#else
	.filter_ctrl = mce_vf_rep_filter_ctrl,
#endif
};

/**
 * @brief Receive burst of packets from the representor receive queue.
 *
 * Dequeues packets from the representor receive ring buffer and returns them
 * to the caller. Updates queue statistics with received packet and byte counts.
 *
 * @param rx_queue Pointer to the representor receive queue
 * @param rx_pkts Array of mbufs to store received packets
 * @param nb_pkts Maximum number of packets to dequeue
 *
 * @return Number of packets successfully dequeued
 *
 * @note DPDK version 21.11+
 * @note Updates queue statistics (ipackets, ibytes)
 * @note Uses single-consumer dequeue (sc_dequeue)
 */
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static uint16_t
mce_vf_representor_rx_burst(__rte_unused void *rx_queue,
			    __rte_unused struct rte_mbuf **rx_pkts,
			    __rte_unused uint16_t nb_pkts)
{
	struct mce_repr_rxq *rxq = rx_queue;
	void **objs = (void *)&rx_pkts[0];
	unsigned int n_rx;

	/* mbufs port is already filled correctly by representors proxy */
	n_rx = rte_ring_sc_dequeue_burst(rxq->ring, objs, nb_pkts, NULL);

	if (n_rx > 0) {
		unsigned int n_bytes = 0;
		unsigned int i = 0;

		do {
			n_bytes += rx_pkts[i]->pkt_len;
		} while (++i < n_rx);
		rxq->stats.ibytes += n_bytes;
		rxq->stats.ipackets += n_rx;
	}

	return n_rx;
}

/**
 * @brief Transmit burst of packets from the representor transmit queue.
 *
 * Enqueues packets into the representor transmit ring buffer for forwarding
 * to the parent PF. Updates queue statistics with transmitted packet and byte counts.
 *
 * @param tx_queue Pointer to the representor transmit queue
 * @param tx_pkts Array of mbufs containing packets to transmit
 * @param nb_pkts Number of packets to enqueue
 *
 * @return Number of packets successfully enqueued
 *
 * @note DPDK version 21.11+
 * @note Updates queue statistics (opackets, obytes)
 * @note Uses single-producer enqueue (sp_enqueue)
 */
static uint16_t mce_vf_representor_tx_burst(void *tx_queue,
					    struct rte_mbuf **tx_pkts,
					    uint16_t nb_pkts)
{
	struct mce_repr_txq *txq = tx_queue;
	void **objs = (void *)&tx_pkts[0];
	unsigned int n_tx;

	/* mbufs port is already filled correctly by representors proxy */
	n_tx = rte_ring_sp_enqueue_burst(txq->ring, objs, nb_pkts, NULL);
	if (n_tx > 0) {
		unsigned int n_bytes = 0;
		unsigned int i = 0;

		do {
			n_bytes += tx_pkts[i]->pkt_len;
		} while (++i < n_tx);
		txq->stats.obytes += n_bytes;
		txq->stats.opackets += n_tx;
	}

	return n_tx;
}
#endif

/**
 * @brief Initialize a VF representor device.
 *
 * Initializes the VF representor Ethernet device with device operations,
 * queue configuration, link information, and proxy route registration.
 * Sets up device flags, MAC address, and statistics counters.
 *
 * @param ethdev Pointer to the VF representor Ethernet device
 * @param init_params Pointer to mce_vf_representor structure with initialization parameters
 *   - vf_id: Virtual Function identifier
 *   - switch_domain_id: Switch domain identifier
 *   - adapter: Pointer to the MCE adapter structure
 *
 * @return 0 on successful initialization
 * @return -ENODEV if VF ID exceeds maximum VFs
 *
 * @note Registers device operations, Rx/Tx functions, and flow operations
 * @note Inherits link state from parent PF device
 * @note Registers port with proxy route for packet forwarding
 * @see mce_vf_representor_uninit() for device cleanup
 */
int mce_vf_representor_init(struct rte_eth_dev *ethdev, void *init_params)
{
	struct mce_vf_representor *representor = ethdev->data->dev_private;
	struct mce_vf_info *vf = NULL;
	struct mce_pf *pf;
	struct rte_eth_link *link;

	representor->vf_id = ((struct mce_vf_representor *)init_params)->vf_id;
	representor->switch_domain_id =
		((struct mce_vf_representor *)init_params)->switch_domain_id;
	representor->adapter =
		((struct mce_vf_representor *)init_params)->adapter;
	representor->port_id = ethdev->data->port_id;

	pf = MCE_DEV_TO_PF(representor->adapter->pf.pf_vport);

	if (representor->vf_id > pf->max_vfs)
		return -ENODEV;
	representor->vport_id = representor->vf_id;
	representor->repr_dev = ethdev;
	/* Set representor device ops */
	ethdev->dev_ops = &mce_representor_dev_ops;
	/* No data-path, but need stub Rx/Tx functions to avoid crash
	 * when testing with the likes of testpmd.
	 */
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	ethdev->rx_pkt_burst = mce_vf_representor_rx_burst;
	ethdev->tx_pkt_burst = mce_vf_representor_tx_burst;
#else
	ethdev->rx_pkt_burst = rte_eth_pkt_burst_dummy;
	ethdev->tx_pkt_burst = rte_eth_pkt_burst_dummy;
#endif /* RTE_VERSION < 21.11 */
	vf = &pf->vfinfos[representor->vf_id];
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	ethdev->data->dev_flags |= RTE_ETH_DEV_REPRESENTOR;
#endif
#if RTE_VERSION_NUM(21, 5, 0, 0) < RTE_VERSION
	ethdev->data->representor_id = representor->vf_id;
#endif
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	ethdev->data->backer_port_id = pf->dev_data->port_id;
#endif
	/* Setting the number queues allocated to the VF */
	ethdev->data->nb_rx_queues = vf->max_qps;
	ethdev->data->nb_tx_queues = vf->max_qps;

	ethdev->data->mac_addrs = &vf->set_addr;

	/* Link state. Inherited from PF */
	link = &representor->adapter->pf.dev_data->dev_link;

	ethdev->data->dev_link.link_speed = link->link_speed;
	ethdev->data->dev_link.link_duplex = link->link_duplex;
	ethdev->data->dev_link.link_status = link->link_status;
	ethdev->data->dev_link.link_autoneg = link->link_autoneg;

	pf->vf_reprs[representor->vf_id] = representor;
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	mce_route_proxy_add_port(pf->proxy_route, MCE_PROXY_VF_REPR,
				 (void *)representor);
#endif

	return 0;
}

/**
 * @brief Uninitialize a VF representor device.
 *
 * Performs cleanup operations for the VF representor device, including
 * clearing MAC address pointers. Note that MAC addresses are owned by the
 * parent VF structure and should not be freed.
 *
 * @param ethdev Pointer to the VF representor Ethernet device
 *
 * @return 0 on successful uninitialization
 *
 * @note MAC addresses are not freed as they are shared with parent VF
 * @see mce_vf_representor_init() for device initialization
 */
int mce_vf_representor_uninit(struct rte_eth_dev *ethdev)
{
	/* mac_addrs must not be freed because part of i40e_pf_vf */
	ethdev->data->mac_addrs = NULL;

	return 0;
}
#endif /* RTE_VERSION >= 18.02 */
