/**
 * @file mce_vf_representor.h
 * @brief MCE VF Representor Device Structures and API Declarations
 *
 * This header file defines the structures and interfaces for VF (Virtual Function)
 * representor devices in the MCE (DPDK MCE Poll Mode Driver) driver. Representors
 * are control-plane abstractions of VF ports that enable unified management and
 * monitoring through DPDK standard Ethernet device interfaces.
 *
 * @details
 * The VF representor module provides:
 * - Device lifecycle management (initialization and uninitialization)
 * - Statistics collection and tracking (Rx/Tx packets, errors, discards)
 * - Queue management for Rx and Tx data paths
 * - Integration with MCE adapter and proxy routing
 *
 * @note Representors require DPDK 18.2+ and are conditionally compiled
 * @see mce.h for main MCE driver definitions
 * @see mce_route_proxy.h for proxy-related structures
 */

#ifndef _MCE_VF_REPRESENTOR_H_
#define _MCE_VF_REPRESENTOR_H_
#include "base/mce_osdep.h"

/**
 * @struct mce_eth_stats
 * @brief Ethernet statistics collected by ports, VSIs, VEBs, and S-channels
 *
 * Comprehensive statistics counters for monitoring Ethernet device performance,
 * including unicast/multicast/broadcast traffic, errors, and discards.
 */
struct mce_eth_stats {
	u64 rx_bytes;        /**< Received bytes (gorc) */
	u64 rx_unicast;      /**< Received unicast packets (uprc) */
	u64 rx_multicast;    /**< Received multicast packets (mprc) */
	u64 rx_broadcast;    /**< Received broadcast packets (bprc) */
	u64 rx_discards;     /**< Received discarded packets (rdpc) */
	u64 rx_unknown_protocol; /**< Received packets with unknown protocol (rupp) */
	u64 tx_bytes;        /**< Transmitted bytes (gotc) */
	u64 tx_unicast;      /**< Transmitted unicast packets (uptc) */
	u64 tx_multicast;    /**< Transmitted multicast packets (mptc) */
	u64 tx_broadcast;    /**< Transmitted broadcast packets (bptc) */
	u64 tx_discards;     /**< Transmitted discarded packets (tdpc) */
	u64 tx_errors;       /**< Transmitted packets with errors (tepc) */
};

/** @def MCE_REPR_MAX_RX_QUEUE Maximum number of receive queues per representor */
#define MCE_REPR_MAX_RX_QUEUE (1)

/** @def MCE_REPR_MAX_TX_QUEUE Maximum number of transmit queues per representor */
#define MCE_REPR_MAX_TX_QUEUE (1)

/**
 * @struct mce_vf_representor
 * @brief VF Representor Device Structure
 *
 * Represents a virtual function (VF) in the control plane. Provides DPDK-compatible
 * Ethernet device interface for management and monitoring of VF traffic and state.
 */
struct mce_vf_representor {
	struct rte_eth_dev *repr_dev;   /**< Associated DPDK Ethernet device */
	uint16_t switch_domain_id;      /**< Switch domain identifier */
	uint16_t vf_id;                 /**< Virtual Function ID */
	uint16_t vport_id;              /**< Virtual Port ID */
	uint16_t port_id;               /**< DPDK port ID */
	struct mce_adapter *adapter;    /**< Private data store of associated physical function */
	struct mce_eth_stats stats_offset; /**< Statistics zero-point for relative measurements */
	struct mce_repr_rxq *rxqs[MCE_REPR_MAX_RX_QUEUE]; /**< Receive queues */
	struct mce_repr_txq *txqs[MCE_REPR_MAX_TX_QUEUE]; /**< Transmit queues */
	uint16_t state;                 /**< Device state (active/inactive) */
};

/**
 * @brief Initialize a VF representor device.
 *
 * Sets up the VF representor Ethernet device with device operations,
 * queue configuration, and proxy route registration.
 *
 * @param ethdev Pointer to the VF representor Ethernet device
 * @param init_params Pointer to mce_vf_representor structure with initialization parameters
 *
 * @return 0 on successful initialization
 * @return -ENODEV if VF ID exceeds maximum VFs
 *
 * @see mce_vf_representor_uninit() for cleanup
 */
int mce_vf_representor_init(struct rte_eth_dev *ethdev, void *init_params);

/**
 * @brief Uninitialize a VF representor device.
 *
 * Performs cleanup operations for the VF representor device. MAC addresses
 * are not freed as they are shared with the parent VF structure.
 *
 * @param ethdev Pointer to the VF representor Ethernet device
 *
 * @return 0 on successful uninitialization
 *
 * @see mce_vf_representor_init() for initialization
 */
int mce_vf_representor_uninit(struct rte_eth_dev *ethdev);

/**
 * @brief Check if an Ethernet device is a representor.
 *
 * Wrapper function to check if the given Ethernet device is a representor
 * device (requires DPDK 19.11+). For earlier versions, always returns 0.
 *
 * @param dev Pointer to the Ethernet device to check
 *
 * @return 1 if device is a representor (DPDK 19.11+)
 * @return 0 if device is not a representor or DPDK version is < 19.11
 *
 * @note This is a compatibility wrapper for different DPDK versions
 */
static inline int mce_eth_dev_is_repr(struct rte_eth_dev *dev __maybe_unused)
{
#ifdef HAVE_RTE_ETH_DEV_IS_REPR
	return rte_eth_dev_is_repr(dev);
#else
	return 0;
#endif
}

#endif /* _MCE_VF_REPRESENTOR_H_ */
