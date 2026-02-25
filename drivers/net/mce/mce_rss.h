/**
 * @file mce_rss.h
 * @brief Receive Side Scaling (RSS) configuration interface
 * RSS enables hardware-based packet distribution across multiple RX queues based on
 * packet header fields (protocol, IP addresses, ports). Supported types include:
 * - IPv4, IPv6 (fragmented and non-fragmented)
 * - TCP, UDP, SCTP over IPv4/IPv6
 * - GTP, ESP (Encapsulated Security Payload)
 * - Multi-level RSS (outer and inner headers)
 * Features:
 * - Hash function configuration (symmetric/asymmetric Toeplitz)
 * - 52-byte RSS key management with default key
 * - RETA (Receive Table) configuration for queue mapping
 * - Per-VF RSS policy support
 * - DPDK 18.11+ support with version-specific handling
 * @see mce_rss.c for implementation
 * @see mce_flow.h for flow rule integration
 */

#ifndef _MCE_RSS_H_

#include "base/mce_eth_regs.h"
#include "base/mce_common.h"
#include "mce_flow.h"

/**
 * @struct mce_rss_hash_cfg
 * @brief RSS hash configuration entry mapping hardware to DPDK types
 *
 * @var func_id Hardware function ID (MCE_RSS_IPV4, MCE_RSS_IPV6, etc.)
 * @var reg_val Hardware register value for packet fields in hash calculation
 * @var rss_flag DPDK RSS flag (RTE_ETH_RSS_IPV4, RTE_ETH_RSS_NONFRAG_IPV4_TCP)
 */
struct mce_rss_hash_cfg {
	uint32_t func_id;
	uint32_t reg_val;
	uint64_t rss_flag;
};

/**
 * @enum mce_rss_hash_type
 * @brief RSS hash function types supported by hardware
 *
 * @var MCE_RSS_IPV4 IPv4 header hashing
 * @var MCE_RSS_IPV6 IPv6 header hashing
 * @var MCE_RSS_IPV4_TCP IPv4 + TCP header hashing
 * @var MCE_RSS_IPV4_UDP IPv4 + UDP header hashing
 * @var MCE_RSS_IPV4_SCTP IPv4 + SCTP header hashing
 * @var MCE_RSS_IPV6_TCP IPv6 + TCP header hashing
 * @var MCE_RSS_IPV6_UDP IPv6 + UDP header hashing
 * @var MCE_RSS_IPV6_SCTP IPv6 + SCTP header hashing
 * @var MCE_RSS_GTP GTP (tunnel) packet hashing
 * @var MCE_RSS_ESP IPsec ESP packet hashing
 */
enum mce_rss_hash_type {
	MCE_RSS_IPV4,
	MCE_RSS_IPV6,
	MCE_RSS_IPV4_TCP,
	MCE_RSS_IPV4_UDP,
	MCE_RSS_IPV4_SCTP,
	MCE_RSS_IPV6_TCP,
	MCE_RSS_IPV6_UDP,
	MCE_RSS_IPV6_SCTP,
	MCE_RSS_GTP,
	MCE_RSS_ESP,
};

static const struct mce_rss_hash_cfg mce_rss_cfg[] = {
	{ MCE_RSS_IPV4, MCE_RSS_INPUT_IPV4, RTE_ETH_RSS_IPV4 },
	{ MCE_RSS_IPV4, MCE_RSS_INPUT_IPV4, RTE_ETH_RSS_FRAG_IPV4 },
	{ MCE_RSS_IPV4, MCE_RSS_INPUT_IPV4, RTE_ETH_RSS_NONFRAG_IPV4_OTHER },
	{ MCE_RSS_IPV6, MCE_RSS_INPUT_IPV6, RTE_ETH_RSS_IPV6 },
	{ MCE_RSS_IPV6, MCE_RSS_INPUT_IPV6, RTE_ETH_RSS_FRAG_IPV6 },
	{ MCE_RSS_IPV6, MCE_RSS_INPUT_IPV6, RTE_ETH_RSS_NONFRAG_IPV6_OTHER },
	{ MCE_RSS_IPV6, MCE_RSS_INPUT_IPV6, RTE_ETH_RSS_IPV6_EX },
	{ MCE_RSS_IPV4_TCP, MCE_RSS_INPUT_IPV4_TCP, RTE_ETH_RSS_NONFRAG_IPV4_TCP },
	{ MCE_RSS_IPV4_UDP, MCE_RSS_INPUT_IPV4_UDP, RTE_ETH_RSS_NONFRAG_IPV4_UDP },
	{ MCE_RSS_IPV4_SCTP, MCE_RSS_INPUT_IPV4_SCTP, RTE_ETH_RSS_NONFRAG_IPV4_SCTP },
	{ MCE_RSS_IPV6_TCP, MCE_RSS_INPUT_IPV6_TCP, RTE_ETH_RSS_NONFRAG_IPV6_TCP },
	{ MCE_RSS_IPV6_UDP, MCE_RSS_INPUT_IPV6_UDP, RTE_ETH_RSS_NONFRAG_IPV6_UDP },
	{ MCE_RSS_IPV6_SCTP, MCE_RSS_INPUT_IPV6_SCTP, RTE_ETH_RSS_NONFRAG_IPV6_SCTP },
	{ MCE_RSS_GTP, MCE_RSS_INPUT_IPV6_TEID | MCE_RSS_INPUT_IPV4_TEID, RTE_ETH_RSS_GTPU },
	{ MCE_RSS_ESP, MCE_RSS_INPUT_IPV6_SPI | MCE_RSS_INPUT_IPV4_SPI, RTE_ETH_RSS_ESP },
};

#define MCE_SUPPORT_RSS_OFFLOAD_ALL                                           \
	(RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4 |                           \
	 RTE_ETH_RSS_NONFRAG_IPV4_OTHER | RTE_ETH_RSS_NONFRAG_IPV4_TCP |      \
	 RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV4_SCTP |       \
	 RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_FRAG_IPV6 |                           \
	 RTE_ETH_RSS_NONFRAG_IPV6_OTHER | RTE_ETH_RSS_IPV6_EX |               \
	 RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP|         \
	 RTE_ETH_RSS_NONFRAG_IPV6_SCTP | RTE_ETH_RSS_ESP | RTE_ETH_RSS_GTPU | \
	 RTE_ETH_RSS_LEVEL_OUTERMOST | RTE_ETH_RSS_LEVEL_INNERMOST)

#define MCE_RSS_INSET_QUEUE  RTE_BIT32(0)
#define MCE_RSS_INSET_KEY    RTE_BIT32(1)
#define MCE_RSS_INSET_TYPE   RTE_BIT32(2)
#define MCE_RSS_INSET_FUNC   RTE_BIT32(3)
#define MCE_RSS_INSET_LEVEL  RTE_BIT32(4)
#define MCE_RSS_MAX_KEY_SIZE (52)
struct mce_rss_rule {
	enum mce_rule_engine_module rule_engine;
	struct mce_flow_action action;

	uint8_t phy_id;
	uint16_t inset;
};

/**
 * @struct mce_rss_handle
 * @brief Per-device RSS configuration handle
 *
 * @var rss_cfg DPDK RSS configuration (hash function, key, RETA)
 */
struct mce_rss_handle {
	struct rte_flow_action_rss rss_cfg;
};

/**
 * @brief Set RSS hash function and key for the device
 *
 * Configure RSS hash function type and key for packet distribution.
 * Supports symmetric and asymmetric Toeplitz hashing (DPDK 23.11+).
 *
 * @param dev Pointer to Ethernet device
 * @param rss_conf RSS configuration (hash key, key length, hash fields)
 *
 * @return 0 on success, -EINVAL for unsupported hash flags, -ENOMEM on allocation failure
 *
 * @note Key change takes effect immediately on running device
 */
int mce_rss_hash_set(struct rte_eth_dev *dev,
		     struct rte_eth_rss_conf *rss_conf);

/**
 * @brief Get current RSS hash configuration
 *
 * Query device's RSS hash function and key settings.
 *
 * @param dev Pointer to Ethernet device
 * @param rss_conf Output RSS configuration structure (52-byte key + flags)
 *
 * @return 0 on success, -EINVAL if output buffer invalid
 */
int mce_rss_hash_conf_get(struct rte_eth_dev *dev,
			  struct rte_eth_rss_conf *rss_conf);

/**
 * @brief Update the RSS Redirection Table (RETA)
 *
 * Reconfigure RSS queue selection table. RETA maps 128 hash buckets to device RX queues.
 * Each hash value [0-127] selects a queue via RETA[hash % 128].
 *
 * @param dev Pointer to Ethernet device
 * @param reta_conf Array of RETA entries (mask + 64 queue IDs per entry)
 * @param reta_size Number of entries in reta_conf (128 / 64 = 2)
 *
 * @return 0 on success, -EINVAL for queue ID overflow, -ENOTSUP if unsupported
 *
 * @note RETA has 128 entries (2 entries of 64 bits each in DPDK API)
 * @note Only valid after RSS hash function configured
 */
int mce_rss_reta_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_reta_entry64 *reta_conf,
			uint16_t reta_size);

/**
 * @brief Query the RSS Redirection Table (RETA)
 *
 * Read current RSS queue selection mapping.
 *
 * @param dev Pointer to Ethernet device
 * @param reta_conf Output array to receive RETA entries and current queue mappings
 * @param reta_size Size of reta_conf array (128 / 64)
 *
 * @return 0 on success, -EINVAL for incorrect buffer size, -ENOTSUP if unsupported
 */
int mce_rss_reta_query(struct rte_eth_dev *dev,
		       struct rte_eth_rss_reta_entry64 *reta_conf,
		       uint16_t reta_size);

/**
 * @brief Configure RSS for the device
 *
 * Initialize and enable RSS functionality with default configuration.
 * Must be called during device setup phase (before start).
 *
 * @param dev Pointer to Ethernet device
 *
 * @return 0 on success, -ENOMEM on memory allocation failure, -ENOTSUP if unsupported
 *
 * @note Called automatically during mce_dev_configure() if RSS enabled
 */
int mce_dev_rss_configure(struct rte_eth_dev *dev);

#endif /* _MCE_RSS_H_*/
