#ifndef __RTE_COMPANT_H_
#define __RTE_COMPANT_H_
#include <stdbool.h>

#include <rte_ip.h>
#include <rte_version.h>
#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_memzone.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>

#if RTE_VERSION_NUM(23, 11, 0, 0) > RTE_VERSION
#define RTE_BIT32(nr) (UINT32_C(1) << (nr))
#define RTE_BIT64(nr) (UINT64_C(1) << (nr))
#endif /* RTE_VERSION < 23.11 */

#define RTE_ETHER_ADDR_LEN 6 /**< Length of Ethernet address. */
#define RTE_ETHER_TYPE_LEN 2 /**< Length of Ethernet type field. */
#define RTE_ETHER_CRC_LEN  4 /**< Length of Ethernet CRC. */
#define RTE_ETHER_HDR_LEN         \
	(RTE_ETHER_ADDR_LEN * 2 + \
	 RTE_ETHER_TYPE_LEN) /**< Length of Ethernet header. */
#define RTE_ETHER_MIN_LEN 64 /**< Minimum frame len, including CRC. */
#define RTE_ETHER_MAX_LEN 1518 /**< Maximum frame len, including CRC. */
#define RTE_ETHER_MTU                            \
	(RTE_ETHER_MAX_LEN - RTE_ETHER_HDR_LEN - \
	 RTE_ETHER_CRC_LEN) /**< Ethernet MTU. */

/* We cannot use rte_cpu_to_be_16() on a constant in a switch/case */
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
#define _htons(x) ((uint16_t)((((x) & 0x00ffU) << 8) | (((x) & 0xff00U) >> 8)))
#else
#define _htons(x) (x)
#endif
/*
 * The following types should be used when handling values according to a
 * specific byte ordering, which may differ from that of the host CPU.
 *
 * Libraries, public APIs and applications are encouraged to use them for
 * documentation purposes.
 */
typedef uint16_t rte_be16_t; /**< 16-bit big-endian value. */
typedef uint32_t rte_be32_t; /**< 32-bit big-endian value. */
typedef uint64_t rte_be64_t; /**< 64-bit big-endian value. */
typedef uint16_t rte_le16_t; /**< 16-bit little-endian value. */
typedef uint32_t rte_le32_t; /**< 32-bit little-endian value. */
typedef uint64_t rte_le64_t; /**< 64-bit little-endian value. */

#if RTE_VERSION_NUM(2, 2, 0, 16) >= RTE_VERSION
#if 0
typedef struct {
	volatile bool locked;
} rte_spinlock_t;

#define rte_spinlock_init(lock_ptr)         \
	do {                                \
		(lock_ptr)->locked = false; \
	} while (0)

#define rte_spinlock_lock(lock_ptr)                                           \
	do {                                                                  \
		while (__sync_lock_test_and_set(&(lock_ptr)->locked, true)) { \
			__asm__ __volatile__("pause" ::: "memory");           \
		}                                                             \
		__asm__ __volatile__("" ::: "memory");                        \
	} while (0)

#define rte_spinlock_unlock(lock_ptr)                     \
	do {                                              \
		__asm__ __volatile__("" ::: "memory");    \
		__sync_lock_release(&(lock_ptr)->locked); \
	} while (0)
#endif
#ifdef RTE_ARCH_X86_64
/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define rte_mb()      _mm_mfence()

#define rte_wmb()     _mm_sfence()

#define rte_rmb()     _mm_lfence()

#define rte_smp_wmb() rte_compiler_barrier()

#define rte_smp_rmb() rte_compiler_barrier()
#endif /* RTE_ARCH_X86_64 */

#ifdef RTE_ARCH_ARM64
#define dsb(opt)                                          \
	do {                                              \
		asm volatile("dsb " #opt : : : "memory"); \
	} while (0)
#define dmb(opt)                                          \
	do {                                              \
		asm volatile("dmb " #opt : : : "memory"); \
	} while (0)

#define rte_mb()      dsb(sy)

#define rte_wmb()     dsb(st)

#define rte_rmb()     dsb(ld)

#define rte_smp_mb()  dmb(ish)

#define rte_smp_wmb() dmb(ishst)

#define rte_smp_rmb() dmb(ishld)

#define rte_io_mb()   rte_mb()

#define rte_io_wmb()  rte_wmb()

#define rte_io_rmb()  rte_rmb()

#define rte_cio_wmb() dmb(oshst)

#define rte_cio_rmb() dmb(oshld)
#endif /* RTE_ARCH_ARM64 */

#ifdef RTE_ARCH_ARM
#define rte_mb() __sync_synchronize()

#define rte_wmb()                                      \
	do {                                           \
		asm volatile("dmb st" : : : "memory"); \
	} while (0)

#define rte_rmb()     __sync_synchronize()

#define rte_smp_mb()  rte_mb()

#define rte_smp_wmb() rte_wmb()

#define rte_smp_rmb() rte_rmb()

#define rte_io_mb()   rte_mb()

#define rte_io_wmb()  rte_wmb()

#define rte_io_rmb()  rte_rmb()

#define rte_cio_wmb() rte_wmb()

#define rte_cio_rmb() rte_rmb()
#endif /* RTE_ARCH_ARM64 */

#ifdef RTE_ARCH_PPC_64
#define rte_mb()                                     \
	do {                                         \
		asm volatile("sync" : : : "memory"); \
	} while (0)

#define rte_wmb()                                    \
	do {                                         \
		asm volatile("sync" : : : "memory"); \
	} while (0)

#define rte_rmb()                                    \
	do {                                         \
		asm volatile("sync" : : : "memory"); \
	} while (0)

#define rte_smp_mb()  rte_mb()

#define rte_smp_wmb() rte_wmb()

#define rte_smp_rmb() rte_rmb()

#define rte_io_mb()   rte_mb()

#define rte_io_wmb()  rte_wmb()

#define rte_io_rmb()  rte_rmb()

#define rte_cio_wmb() rte_wmb()

#define rte_cio_rmb() rte_rmb()

#endif /* RTE_ARCH_PPC_64 */
/*
 * Rings setup and release.
 *
 * TDBA/RDBA should be aligned on 16 byte boundary. But TDLEN/RDLEN should be
 * multiple of 128 bytes. So we align TDBA/RDBA on 128 byte boundary. This will
 * also optimize cache line size effect. H/W supports up to cache line size 128.
 */
#if RTE_VERSION_NUM(2, 2, 0, 0) > RTE_VERSION
#define MCE_ALIGN    128
/*
 * Create memzone for HW rings. malloc can't be used as the physical address is
 * needed. If the memzone is already created, then this function returns a ptr
 * to the old one.
 */
#define __rte_packed __attribute__((__packed__))
static const __attribute__((unused)) struct rte_memzone *
ring_dma_zone_reserve(struct rte_eth_dev *dev, const char *ring_name,
		      uint16_t queue_id, uint32_t ring_size, int socket_id)
{
	char z_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;

	snprintf(z_name, sizeof(z_name), "%s_%s_%d_%d",
		 dev->driver->pci_drv.name, ring_name, dev->data->port_id,
		 queue_id);

	mz = rte_memzone_lookup(z_name);
	if (mz)
		return mz;

#ifdef RTE_LIBRTE_XEN_DOM0
	return rte_memzone_reserve_bounded(z_name, ring_size, socket_id, 0,
					   MCE_ALIGN, RTE_PGSIZE_2M);
#else
	return rte_memzone_reserve_aligned(z_name, ring_size, socket_id, 0,
					   MCE_ALIGN);
#endif
}
/* Macros to check for valid port */
#define RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, retval)                   \
	do {                                                               \
		if (!rte_eth_dev_is_valid_port(port_id)) {                 \
			PMD_DRV_LOG(ERR, "Invalid port_id=%d\n", port_id); \
			return retval;                                     \
		}                                                          \
	} while (0)
#endif /* RTE_VERSION < 2.2.0 */
/**
 * RX/TX queue states
 */
#define RTE_ETH_QUEUE_STATE_STOPPED 0
#define RTE_ETH_QUEUE_STATE_STARTED 1

/**
 * VLAN types to indicate if it is for single VLAN, inner VLAN or outer VLAN.
 * Note that single VLAN is treated the same as inner VLAN.
 */
enum rte_vlan_type {
	ETH_VLAN_TYPE_UNKNOWN = 0,
	ETH_VLAN_TYPE_INNER, /**< Inner VLAN. */
	ETH_VLAN_TYPE_OUTER, /**< Single VLAN, or outer VLAN. */
	ETH_VLAN_TYPE_MAX,
};
#endif /* RTE_VERSION <= 2.2.0.16 */

#if RTE_VERSION_NUM(17, 2, 0, 0) > RTE_VERSION
#define rte_io_wmb() rte_wmb()
#define rte_io_rmb() rte_rmb()
enum rte_flow_action_type {
	/**
	 * [META]
	 *
	 * End marker for action lists. Prevents further processing of
	 * actions, thereby ending the list.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_END,

	/**
	 * [META]
	 *
	 * Used as a placeholder for convenience. It is ignored and simply
	 * discarded by PMDs.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_VOID,

	/**
	 * Leaves packets up for additional processing by subsequent flow
	 * rules. This is the default when a rule does not contain a
	 * terminating action, but can be specified to force a rule to
	 * become non-terminating.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_PASSTHRU,

	/**
	 * [META]
	 *
	 * Attaches an integer value to packets and sets PKT_RX_FDIR and
	 * PKT_RX_FDIR_ID mbuf flags.
	 *
	 * See struct rte_flow_action_mark.
	 */
	RTE_FLOW_ACTION_TYPE_MARK,

	/**
	 * [META]
	 *
	 * Flags packets. Similar to MARK without a specific value; only
	 * sets the PKT_RX_FDIR mbuf flag.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_FLAG,

	/**
	 * Assigns packets to a given queue index.
	 *
	 * See struct rte_flow_action_queue.
	 */
	RTE_FLOW_ACTION_TYPE_QUEUE,

	/**
	 * Drops packets.
	 *
	 * PASSTHRU overrides this action if both are specified.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_DROP,

	/**
	 * [META]
	 *
	 * Enables counters for this rule.
	 *
	 * These counters can be retrieved and reset through rte_flow_query(),
	 * see struct rte_flow_query_count.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_COUNT,

	/**
	 * Duplicates packets to a given queue index.
	 *
	 * This is normally combined with QUEUE, however when used alone, it
	 * is actually similar to QUEUE + PASSTHRU.
	 *
	 * See struct rte_flow_action_dup.
	 */
	RTE_FLOW_ACTION_TYPE_DUP,

	/**
	 * Similar to QUEUE, except RSS is additionally performed on packets
	 * to spread them among several queues according to the provided
	 * parameters.
	 *
	 * See struct rte_flow_action_rss.
	 */
	RTE_FLOW_ACTION_TYPE_RSS,

	/**
	 * Redirects packets to the physical function (PF) of the current
	 * device.
	 *
	 * No associated configuration structure.
	 */
	RTE_FLOW_ACTION_TYPE_PF,

	/**
	 * Redirects packets to the virtual function (VF) of the current
	 * device with the specified ID.
	 *
	 * See struct rte_flow_action_vf.
	 */
	RTE_FLOW_ACTION_TYPE_VF,
};

#define rte_io_rmb() rte_rmb()
#define rte_io_wmb() rte_wmb()
struct rte_flow_action {
	enum rte_flow_action_type type; /**< Action type. */
	const void *conf; /**< Pointer to action configuration structure. */
};

#if 0
/**
 * Verbose error types.
 *
 * Most of them provide the type of the object referenced by struct
 * rte_flow_error.cause.
 */
enum rte_flow_error_type {
	RTE_FLOW_ERROR_TYPE_NONE, /**< No error. */
	RTE_FLOW_ERROR_TYPE_UNSPECIFIED, /**< Cause unspecified. */
	RTE_FLOW_ERROR_TYPE_HANDLE, /**< Flow rule (handle). */
	RTE_FLOW_ERROR_TYPE_ATTR_GROUP, /**< Group field. */
	RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY, /**< Priority field. */
	RTE_FLOW_ERROR_TYPE_ATTR_INGRESS, /**< Ingress field. */
	RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, /**< Egress field. */
	RTE_FLOW_ERROR_TYPE_ATTR, /**< Attributes structure. */
	RTE_FLOW_ERROR_TYPE_ITEM_NUM, /**< Pattern length. */
	RTE_FLOW_ERROR_TYPE_ITEM, /**< Specific pattern item. */
	RTE_FLOW_ERROR_TYPE_ACTION_NUM, /**< Number of actions. */
	RTE_FLOW_ERROR_TYPE_ACTION, /**< Specific action. */
};

/**
 * Verbose error structure definition.
 *
 * This object is normally allocated by applications and set by PMDs, the
 * message points to a constant string which does not need to be freed by
 * the application, however its pointer can be considered valid only as long
 * as its associated DPDK port remains configured. Closing the underlying
 * device or unloading the PMD invalidates it.
 *
 * Both cause and message may be NULL regardless of the error type.
 */
struct rte_flow_error {
	enum rte_flow_error_type type; /**< Cause field and error types. */
	const void *cause; /**< Object responsible for the error. */
	const char *message; /**< Human-readable error message. */
};
#endif
/**
 * Flow rule attributes.
 *
 * Priorities are set on two levels: per group and per rule within groups.
 *
 * Lower values denote higher priority, the highest priority for both levels
 * is 0, so that a rule with priority 0 in group 8 is always matched after a
 * rule with priority 8 in group 0.
 *
 * Although optional, applications are encouraged to group similar rules as
 * much as possible to fully take advantage of hardware capabilities
 * (e.g. optimized matching) and work around limitations (e.g. a single
 * pattern type possibly allowed in a given group).
 *
 * Group and priority levels are arbitrary and up to the application, they
 * do not need to be contiguous nor start from 0, however the maximum number
 * varies between devices and may be affected by existing flow rules.
 *
 * If a packet is matched by several rules of a given group for a given
 * priority level, the outcome is undefined. It can take any path, may be
 * duplicated or even cause unrecoverable errors.
 *
 * Note that support for more than a single group and priority level is not
 * guaranteed.
 *
 * Flow rules can apply to inbound and/or outbound traffic (ingress/egress).
 *
 * Several pattern items and actions are valid and can be used in both
 * directions. Those valid for only one direction are described as such.
 *
 * At least one direction must be specified.
 *
 * Specifying both directions at once for a given rule is not recommended
 * but may be valid in a few cases (e.g. shared counter).
 */
struct rte_flow_attr {
	uint32_t group; /**< Priority group. */
	uint32_t priority; /**< Priority level within group. */
	uint32_t ingress : 1; /**< Rule applies to ingress traffic. */
	uint32_t egress : 1; /**< Rule applies to egress traffic. */
	uint32_t reserved : 30; /**< Reserved, must be zero. */
};

#endif /* RTE_VERSION < 17.02 */

#if RTE_VERSION_NUM(16, 4, 0, 0) > RTE_VERSION
#define ETH_SPEED_NUM_NONE     0 /**< Not defined */
#define ETH_SPEED_NUM_10M      10 /**<  10 Mbps */
#define ETH_SPEED_NUM_100M     100 /**< 100 Mbps */
#define ETH_SPEED_NUM_1G       1000 /**<   1 Gbps */
#define ETH_SPEED_NUM_2_5G     2500 /**< 2.5 Gbps */
#define ETH_SPEED_NUM_5G       5000 /**<   5 Gbps */
#define ETH_SPEED_NUM_10G      10000 /**<  10 Gbps */
#define ETH_SPEED_NUM_20G      20000 /**<  20 Gbps */
#define ETH_SPEED_NUM_25G      25000 /**<  25 Gbps */
#define ETH_SPEED_NUM_40G      40000 /**<  40 Gbps */
#define ETH_SPEED_NUM_50G      50000 /**<  50 Gbps */
#define ETH_SPEED_NUM_56G      56000 /**<  56 Gbps */
#define ETH_SPEED_NUM_100G     100000 /**< 100 Gbps */

#define ETH_LINK_SPEED_25G     25000
#define ETH_LINK_SPEED_1G      ETH_LINK_SPEED_1000
#define ETH_LINK_SPEED_100M    ETH_LINK_SPEED_100
#define ETH_LINK_SPEED_100M_HD ETH_LINK_SPEED_100
#define ETH_LINK_SPEED_10M     ETH_LINK_SPEED_10
#define ETH_LINK_SPEED_10M_HD  ETH_LINK_SPEED_10
/* Utility constants */
#define ETH_LINK_DOWN	       0 /**< Link is down. */
#define ETH_LINK_UP	       1 /**< Link is up. */
#define ETH_LINK_FIXED	       0 /**< No autonegotiation. */
#define ETH_LINK_AUTONEG       1 /**< Autonegotiated. */

/**
 * Return the DMA address of the beginning of the mbuf data
 *
 * @param mb
 *   The pointer to the mbuf.
 * @return
 *   The physical address of the beginning of the mbuf data
 */
static inline phys_addr_t rte_mbuf_data_dma_addr(const struct rte_mbuf *mb)
{
	return mb->buf_physaddr + mb->data_off;
}

#define rte_prefetch_non_temporal(p) \
	do {                         \
	} while (0);
#endif /* RTE_VERSION < 16.04 */

#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
static inline struct rte_mbuf *rte_rxmbuf_alloc(struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	m = __rte_mbuf_raw_alloc(mp);
	__rte_mbuf_sanity_check_raw(m, 0);

	return m;
}
#define rte_mbuf_raw_alloc rte_rxmbuf_alloc
#endif /*  RTE_VERSION <= 16.04.16 */

#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
#define RTE_PTYPE_L2_ETHER_VLAN (0x00000006)
/* This macro permits both remove and free var within the loop safely.*/
#define TAILQ_FOREACH_SAFE(var, head, field, tvar) \
	for ((var) = TAILQ_FIRST((head));          \
	     (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))
#endif /* RTE_VERSION < 16.07 */

#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
#define PKT_TX_TUNNEL_VXLAN	(0x1ULL << 45)
#define PKT_TX_TUNNEL_MASK	(0xFULL << 45)
#define PKT_TX_TUNNEL_GRE	(0x2ULL << 45)

#define PKT_RX_QINQ_STRIPPED	(1ULL << 15)
#define PKT_RX_L4_CKSUM_GOOD	(0)
#define PKT_RX_IP_CKSUM_GOOD	(0)
#define PCI_PRI_STR_SIZE	sizeof("XXXXXXXX:XX:XX.X")
#define RTE_PTYPE_L2_ETHER_QINQ 0x00000007
#define RTE_PTYPE_L2_ETHER_NSH	0x00000005

/** Formatting string for PCI device identifier: Ex: 0000:00:01.0 */
#define PCI_PRI_FMT		"%.4" PRIx16 ":%.2" PRIx8 ":%.2" PRIx8 ".%" PRIx8
static inline void rte_eal_pci_device_name(const struct rte_pci_addr *addr,
					   char *output, size_t size)
{
	RTE_VERIFY(size >= PCI_PRI_STR_SIZE);
	RTE_VERIFY(snprintf(output, size, PCI_PRI_FMT, addr->domain, addr->bus,
			    addr->devid, addr->function) >= 0);
}
#endif /* RTE_VERSION < 16.11 */

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
#define RTE_MEMZONE_IOVA_CONTIG \
	0x00100000 /**< Ask for IOVA-contiguous memzone. */
/**
 * @internal
 * Atomically get the link speed and status.
 *
 * @param dev
 *  Pointer to struct rte_eth_dev.
 * @param link
 *  link status value.
 */
static inline void rte_eth_linkstatus_get(const struct rte_eth_dev *dev,
					  struct rte_eth_link *link)
{
	volatile uint64_t *src = (uint64_t *)&(dev->data->dev_link);
	uint64_t *dst = (uint64_t *)link;

	RTE_BUILD_BUG_ON(sizeof(*link) != sizeof(uint64_t));

#ifdef __LP64__
	/* if cpu arch has 64 bit unsigned lon then implicitly atomic */
	*dst = *src;
#else
	/* can't use rte_atomic64_read because it returns signed int */
	do {
		*dst = *src;
	} while (!rte_atomic64_cmpset(src, *dst, *dst));
#endif
}
#define LCORE_CACHE_SIZE 64
#include <rte_hash.h>
#include <rte_hash_crc.h>
#ifndef strlcpy
/*
 * @internal
 * DPDK-specific version of strlcpy for systems without
 * libc or libbsd copies of the function
 */
static inline size_t
rte_strlcpy(char *dst, const char *src, size_t size)
{
        return (size_t)snprintf(dst, size, "%s", src);
}
#define strlcpy(dst, src, size) rte_strlcpy(dst, src, size)
#endif /* strlcpy */
#endif /* RTE_VERSION < 18.05 */
#if RTE_VERSION_NUM(17, 2, 0, 0) > RTE_VERSION
enum rte_flow_item_type {
	/**
	 * [META]
	 *
	 * End marker for item lists. Prevents further processing of items,
	 * thereby ending the pattern.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_END,

	/**
	 * [META]
	 *
	 * Used as a placeholder for convenience. It is ignored and simply
	 * discarded by PMDs.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_VOID,

	/**
	 * [META]
	 *
	 * Inverted matching, i.e. process packets that do not match the
	 * pattern.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_INVERT,

	/**
	 * Matches any protocol in place of the current layer, a single ANY
	 * may also stand for several protocol layers.
	 *
	 * See struct rte_flow_item_any.
	 */
	RTE_FLOW_ITEM_TYPE_ANY,

	/**
	 * [META]
	 *
	 * Matches packets addressed to the physical function of the device.
	 *
	 * If the underlying device function differs from the one that would
	 * normally receive the matched traffic, specifying this item
	 * prevents it from reaching that device unless the flow rule
	 * contains a PF action. Packets are not duplicated between device
	 * instances by default.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_PF,

	/**
	 * [META]
	 *
	 * Matches packets addressed to a virtual function ID of the device.
	 *
	 * If the underlying device function differs from the one that would
	 * normally receive the matched traffic, specifying this item
	 * prevents it from reaching that device unless the flow rule
	 * contains a VF action. Packets are not duplicated between device
	 * instances by default.
	 *
	 * See struct rte_flow_item_vf.
	 */
	RTE_FLOW_ITEM_TYPE_VF,

	/**
	 * [META]
	 *
	 * Matches packets coming from the specified physical port of the
	 * underlying device.
	 *
	 * The first PORT item overrides the physical port normally
	 * associated with the specified DPDK input port (port_id). This
	 * item can be provided several times to match additional physical
	 * ports.
	 *
	 * See struct rte_flow_item_port.
	 */
	RTE_FLOW_ITEM_TYPE_PORT,

	/**
	 * Matches a byte string of a given length at a given offset.
	 *
	 * See struct rte_flow_item_raw.
	 */
	RTE_FLOW_ITEM_TYPE_RAW,

	/**
	 * Matches an Ethernet header.
	 *
	 * See struct rte_flow_item_eth.
	 */
	RTE_FLOW_ITEM_TYPE_ETH,

	/**
	 * Matches an 802.1Q/ad VLAN tag.
	 *
	 * See struct rte_flow_item_vlan.
	 */
	RTE_FLOW_ITEM_TYPE_VLAN,

	/**
	 * Matches an IPv4 header.
	 *
	 * See struct rte_flow_item_ipv4.
	 */
	RTE_FLOW_ITEM_TYPE_IPV4,

	/**
	 * Matches an IPv6 header.
	 *
	 * See struct rte_flow_item_ipv6.
	 */
	RTE_FLOW_ITEM_TYPE_IPV6,

	/**
	 * Matches an ICMP header.
	 *
	 * See struct rte_flow_item_icmp.
	 */
	RTE_FLOW_ITEM_TYPE_ICMP,

	/**
	 * Matches a UDP header.
	 *
	 * See struct rte_flow_item_udp.
	 */
	RTE_FLOW_ITEM_TYPE_UDP,

	/**
	 * Matches a TCP header.
	 *
	 * See struct rte_flow_item_tcp.
	 */
	RTE_FLOW_ITEM_TYPE_TCP,

	/**
	 * Matches a SCTP header.
	 *
	 * See struct rte_flow_item_sctp.
	 */
	RTE_FLOW_ITEM_TYPE_SCTP,

	/**
	 * Matches a VXLAN header.
	 *
	 * See struct rte_flow_item_vxlan.
	 */
	RTE_FLOW_ITEM_TYPE_VXLAN,

	/**
	 * Matches a E_TAG header.
	 *
	 * See struct rte_flow_item_e_tag.
	 */
	RTE_FLOW_ITEM_TYPE_E_TAG,

	/**
	 * Matches a NVGRE header.
	 *
	 * See struct rte_flow_item_nvgre.
	 */
	RTE_FLOW_ITEM_TYPE_NVGRE,
};

struct rte_flow_action_rss {
	const struct rte_eth_rss_conf *rss_conf; /**< RSS parameters. */
	uint16_t num; /**< Number of entries in queue[]. */
	uint16_t queue[]; /**< Queues indices to use. */
};

/**
 * Verbose error types.
 *
 * Most of them provide the type of the object referenced by struct
 * rte_flow_error.cause.
 */
enum rte_flow_error_type {
	RTE_FLOW_ERROR_TYPE_NONE, /**< No error. */
	RTE_FLOW_ERROR_TYPE_UNSPECIFIED, /**< Cause unspecified. */
	RTE_FLOW_ERROR_TYPE_HANDLE, /**< Flow rule (handle). */
	RTE_FLOW_ERROR_TYPE_ATTR_GROUP, /**< Group field. */
	RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY, /**< Priority field. */
	RTE_FLOW_ERROR_TYPE_ATTR_INGRESS, /**< Ingress field. */
	RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, /**< Egress field. */
	RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER, /**< Transfer field. */
	RTE_FLOW_ERROR_TYPE_ATTR, /**< Attributes structure. */
	RTE_FLOW_ERROR_TYPE_ITEM_NUM, /**< Pattern length. */
	RTE_FLOW_ERROR_TYPE_ITEM_SPEC, /**< Item specification. */
	RTE_FLOW_ERROR_TYPE_ITEM_LAST, /**< Item specification range. */
	RTE_FLOW_ERROR_TYPE_ITEM_MASK, /**< Item specification mask. */
	RTE_FLOW_ERROR_TYPE_ITEM, /**< Specific pattern item. */
	RTE_FLOW_ERROR_TYPE_ACTION_NUM, /**< Number of actions. */
	RTE_FLOW_ERROR_TYPE_ACTION_CONF, /**< Action configuration. */
	RTE_FLOW_ERROR_TYPE_ACTION, /**< Specific action. */
};

struct rte_flow_item {
	enum rte_flow_item_type type; /**< Item type. */
	const void *spec; /**< Pointer to item specification structure. */
	const void *last; /**< Defines an inclusive range (spec to last). */
	const void *mask; /**< Bit-mask applied to spec and last. */
};

/**
 * Verbose error structure definition.
 *
 * This object is normally allocated by applications and set by PMDs, the
 * message points to a constant string which does not need to be freed by
 * the application, however its pointer can be considered valid only as long
 * as its associated DPDK port remains configured. Closing the underlying
 * device or unloading the PMD invalidates it.
 *
 * Both cause and message may be NULL regardless of the error type.
 */
struct rte_flow_error {
	enum rte_flow_error_type type; /**< Cause field and error types. */
	const void *cause; /**< Object responsible for the error. */
	const char *message; /**< Human-readable error message. */
};

#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(int, _rte_errno); /**< Per core error number. */

/**
 * Error number value, stored per-thread, which can be queried after
 * calls to certain functions to determine why those functions failed.
 *
 * Uses standard values from errno.h wherever possible, with a small number
 * of additional possible values for RTE-specific conditions.
 */
#define rte_errno RTE_PER_LCORE(_rte_errno)

/**
 * Initialize generic flow error structure.
 *
 * This function also sets rte_errno to a given value.
 *
 * @param[out] error
 *   Pointer to flow error structure (may be NULL).
 * @param code
 *   Related error code (rte_errno).
 * @param type
 *   Cause field and error types.
 * @param cause
 *   Object responsible for the error.
 * @param message
 *   Human-readable error message.
 *
 * @return
 *   Error code.
 */
static inline int rte_flow_error_set(struct rte_flow_error *error, int code,
				     enum rte_flow_error_type type,
				     const void *cause, const char *message)
{
	if (error) {
		*error = (struct rte_flow_error){
			.type = type,
			.cause = cause,
			.message = message,
		};
	}
	rte_errno = code;

	return code;
}

/**
 * RTE_FLOW_ACTION_TYPE_MARK
 *
 * Attaches an integer value to packets and sets PKT_RX_FDIR and
 * PKT_RX_FDIR_ID mbuf flags.
 *
 * This value is arbitrary and application-defined. Maximum allowed value
 * depends on the underlying implementation. It is returned in the
 * hash.fdir.hi mbuf field.
 */
struct rte_flow_action_mark {
	uint32_t id; /**< Integer value to return with packets. */
};
/**
 * RTE_FLOW_ACTION_TYPE_QUEUE
 *
 * Assign packets to a given queue index.
 *
 * Terminating by default.
 */
struct rte_flow_action_queue {
	uint16_t index; /**< Queue index to use. */
};
/**
 * RTE_FLOW_ACTION_TYPE_VF
 *
 * Redirects packets to a virtual function (VF) of the current device.
 *
 * Packets matched by a VF pattern item can be redirected to their original
 * VF ID instead of the specified one. This parameter may not be available
 * and is not guaranteed to work properly if the VF part is matched by a
 * prior flow rule or if packets are not addressed to a VF in the first
 * place.
 *
 * Terminating by default.
 */
struct rte_flow_action_vf {
	uint32_t original : 1; /**< Use original VF ID if possible. */
	uint32_t reserved : 31; /**< Reserved, must be zero. */
	uint32_t id; /**< VF ID to redirect packets to. */
};
struct rte_flow;

/**
 * Offload the MACsec. This flag must be set by the application to enable
 * this offload feature for a packet to be transmitted.
 */
#define PKT_TX_MACSEC	     (1ULL << 44)
#define PKT_RX_VLAN_STRIPPED (1ULL << 6)

/**
 * Bitmask of all supported packet Tx offload features flags,
 * which can be set for packet.
 */
#define PKT_TX_OFFLOAD_MASK                                         \
	(PKT_TX_IP_CKSUM | PKT_TX_L4_MASK | PKT_TX_OUTER_IP_CKSUM | \
	 PKT_TX_TCP_SEG | PKT_TX_IEEE1588_TMST | PKT_TX_QINQ_PKT |  \
	 PKT_TX_VLAN_PKT | PKT_TX_TUNNEL_MASK | PKT_TX_MACSEC)
#define RTE_ETH_DEV_TO_PCI(eth_dev) ((eth_dev)->pci_dev)
#endif /* RTE_VERSION < 17.02 */
#if RTE_VERSION_NUM(17, 5, 0, 16) > RTE_VERSION
#define rte_pktmbuf_prefree_seg __rte_pktmbuf_prefree_seg
#endif

#if RTE_VERSION_NUM(17, 8, 0, 16) > RTE_VERSION && \
	RTE_VERSION_NUM(17, 2, 0, 16) <= RTE_VERSION
#define RTE_ETH_DEV_TO_PCI(eth_dev) RTE_DEV_TO_PCI((eth_dev)->device)
#endif /* 17.2 < RTE_VERSION < 17.05 */

#if RTE_VERSION_NUM(17, 8, 0, 0) > RTE_VERSION
#define __rte_always_inline inline __attribute__((always_inline))

/**
 * Return the rounded-up log2 of a integer.
 *
 * @param v
 *     The input parameter.
 * @return
 *     The rounded-up log2 of the input, or 0 if the input is 0.
 */
static inline uint32_t rte_log2_u32(uint32_t v)
{
	if (v == 0)
		return 0;
	v = rte_align32pow2(v);
	return rte_bsf32(v);
}
#endif /* RTE_VERSION < 17.08 */

#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
/* Mbuf dma Address  */
#define rte_mbuf_data_iova(m)	   rte_mbuf_data_dma_addr(m)

#define DEV_RX_OFFLOAD_TIMESTAMP   0x00004000
#define DEV_RX_OFFLOAD_SCATTER	   0x00002000
#define DEV_RX_OFFLOAD_JUMBO_FRAME 0x00000800
#define DEV_RX_OFFLOAD_CHECKSUM                                 \
	(DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_UDP_CKSUM | \
	 DEV_RX_OFFLOAD_TCP_CKSUM)
#define DEV_RX_OFFLOAD_VLAN_FILTER 0x00000200
#define DEV_RX_OFFLOAD_VLAN_EXTEND 0x00000400
#define DEV_RX_OFFLOAD_VLAN                                       \
	(DEV_RX_OFFLOAD_VLAN_STRIP | DEV_RX_OFFLOAD_VLAN_FILTER | \
	 DEV_RX_OFFLOAD_VLAN_EXTEND)
#define DEV_RX_OFFLOAD_TIMESTAMP   0x00004000
#define DEV_TX_OFFLOAD_MULTI_SEGS  0x00008000
#define DEV_TX_OFFLOAD_GRE_TNL_TSO 0x00000400 /**< Used for tunneling packet. */
#define DEV_TX_OFFLOAD_VXLAN_TNL_TSO \
	0x00000200 /**< Used for tunneling packet. */

#define PKT_RX_VLAN PKT_RX_VLAN_PKT
static inline uint64_t rte_mbuf_data_iova_default(const struct rte_mbuf *mb)
{
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
	return mb->buf_physaddr + RTE_PKTMBUF_HEADROOM;
#else
	return mb->buf_iova + RTE_PKTMBUF_HEADROOM;
#endif
}
#define RTE_PTYPE_TUNNEL_GTPC               0x00007000
#define RTE_PTYPE_TUNNEL_GTPU               0x00008000
#define RTE_PTYPE_TUNNEL_ESP                0x00009000
#endif /* RTE_VERSION < 17.11 */
#if RTE_VERSION_NUM(16, 7, 0, 0) < RTE_VERSION
#define PKT_RX_QINQ_PKT PKT_RX_QINQ_STRIPPED
#endif /* RTE_VERSION > 16.07 */
#if RTE_VERSION_NUM(17, 11, 0, 16) <= RTE_VERSION
#define rte_mbuf_data_dma_addr rte_mbuf_data_iova
#endif /* RTE_VERSION > 17.08 */
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
static inline uint64_t rte_atomic64_exchange(volatile uint64_t *dst,
					     uint64_t val)
{
#if defined(RTE_ARCH_ARM64) && defined(RTE_TOOLCHAIN_CLANG)
	return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
	return __atomic_exchange_8(dst, val, __ATOMIC_SEQ_CST);
#endif
}
/**
 * @internal
 * Atomically set the link status for the specific device.
 * It is for use by DPDK device driver use only.
 * User applications should not call it
 *
 * @param dev
 *  Pointer to struct rte_eth_dev.
 * @param link
 *  New link status value.
 * @return
 *  Same convention as eth_link_update operation.
 *  0   if link up status has changed
 *  -1  if link up status was unchanged
 */
static inline int rte_eth_linkstatus_set(struct rte_eth_dev *dev,
					 const struct rte_eth_link *new_link)
{
	volatile uint64_t *dev_link =
		(volatile uint64_t *)&(dev->data->dev_link);
	union {
		uint64_t val64;
		struct rte_eth_link link;
	} orig;

	RTE_BUILD_BUG_ON(sizeof(*new_link) != sizeof(uint64_t));

	orig.val64 =
		rte_atomic64_exchange(dev_link, *(const uint64_t *)new_link);

	return (orig.link.link_status == new_link->link_status) ? -1 : 0;
}
#endif /* RTE_VERSION < 18.05 */

#if RTE_VERSION_NUM(18, 8, 0, 0) > RTE_VERSION
static inline int rte_hash_count(void *handle)
{
	RTE_SET_USED(handle);
	return 0;
}
#endif /* RTE_VERSION < 18.08 */

#if RTE_VERSION_NUM(18, 11, 0, 0) > RTE_VERSION
#define DEV_RX_OFFLOAD_SCTP_CKSUM	0x00020000
#define DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM 0x00000040
#define DEV_RX_OFFLOAD_KEEP_CRC		0x00010000
/**
 * MPLS header.
 */
struct mpls_hdr {
	uint16_t tag_msb; /**< Label(msb). */
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t tag_lsb : 4; /**< Label(lsb). */
	uint8_t tc : 3; /**< Traffic class. */
	uint8_t bs : 1; /**< Bottom of stack. */
#else
	uint8_t bs : 1; /**< Bottom of stack. */
	uint8_t tc : 3; /**< Traffic class. */
	uint8_t tag_lsb : 4; /**< label(lsb) */
#endif
	uint8_t ttl; /**< Time to live. */
} __attribute__((__packed__));

#define RTE_PTYPE_TUNNEL_MPLS_IN_UDP   0x0000d000
#define RTE_PTYPE_L2_ETHER_FCOE	       0x00000009
#define RTE_PTYPE_L2_ETHER_MPLS	       0x0000000a
#define PKT_RX_OUTER_L4_CKSUM_GOOD     (1ULL << 22)
#define PKT_RX_OUTER_L4_CKSUM_BAD      (1ULL << 21)
#define PKT_TX_UDP_SEG		       (1ULL << 42)
#define PKT_TX_OUTER_UDP_CKSUM	       (1ULL << 41)

#define DEV_TX_OFFLOAD_OUTER_UDP_CKSUM 0x00100000
#define DEV_RX_OFFLOAD_OUTER_UDP_CKSUM 0x00040000
#define RTE_HASH_EXTRA_FLAGS_EXT_TABLE 0x08
#endif /* RTE_VERSION < 18.11 */
#if RTE_VERSION_NUM(19, 2, 0, 0) >= RTE_VERSION
//#define rte_bsf64(a) __builtin_ctzll(a)
/**
 * Return the last (most-significant) bit set.
 *
 * @note The last (most significant) bit is at position 64.
 * @note rte_fls_u64(0) = 0, rte_fls_u64(1) = 1,
 *       rte_fls_u64(0x8000000000000000) = 64
 *
 * @param x
 *     The input parameter.
 * @return
 *     The last (most-significant) bit set, or 0 if the input is 0.
 */
static inline int rte_fls_u64(uint64_t x)
{
	return (x == 0) ? 0 : 64 - __builtin_clzll(x);
}
#endif /* RTE_VERSION <= 19.02 */

#if RTE_VERSION_NUM(19, 11, 0, 0) > RTE_VERSION
#define DEV_RX_OFFLOAD_RSS_HASH 0x00080000
#define ETH_RSS_GTPU		(1ULL << 23)
/**
  Simplified GTP protocol header.
 * Contains 8-bit header info, 8-bit message type,
 * 16-bit payload length after mandatory header, 32-bit TEID.
 * No optional fields and next extension header.
 */
struct rte_gtp_hdr {
	uint8_t gtp_hdr_info; /**< GTP header info */
	uint8_t msg_type; /**< GTP message type */
	uint16_t plen; /**< Total payload length */
	uint32_t teid; /**< Tunnel endpoint ID */
} __attribute__((__packed__));

/**
 * Size of the array holding mbufs from the same mempool pending to be freed
 * in bulk.
 */
/**
 * @internal helper function for freeing a bulk of packet mbuf segments
 * via an array holding the packet mbuf segments from the same mempool
 * pending to be freed.
 *
 * @param m
 *  The packet mbuf segment to be freed.
 * @param pending
 *  Pointer to the array of packet mbuf segments pending to be freed.
 * @param nb_pending
 *  Pointer to the number of elements held in the array.
 * @param pending_sz
 *  Number of elements the array can hold.
 *  Note: The compiler should optimize this parameter away when using a
 *  constant value, such as RTE_PKTMBUF_FREE_PENDING_SZ.
 */
static void __rte_pktmbuf_free_seg_via_array(struct rte_mbuf *m,
					     struct rte_mbuf **const pending,
					     unsigned int *const nb_pending,
					     const unsigned int pending_sz)
{
	m = rte_pktmbuf_prefree_seg(m);
	if (likely(m != NULL)) {
		if (*nb_pending == pending_sz ||
		    (*nb_pending > 0 && m->pool != pending[0]->pool)) {
			rte_mempool_put_bulk(pending[0]->pool, (void **)pending,
					     *nb_pending);
			*nb_pending = 0;
		}

		pending[(*nb_pending)++] = m;
	}
}

#define RTE_PKTMBUF_FREE_PENDING_SZ 64

/* Free a bulk of packet mbufs back into their original mempools. */
static inline void rte_pktmbuf_free_bulk(struct rte_mbuf **mbufs,
					 unsigned int count)
{
	struct rte_mbuf *m, *m_next, *pending[RTE_PKTMBUF_FREE_PENDING_SZ];
	unsigned int idx, nb_pending = 0;

	for (idx = 0; idx < count; idx++) {
		m = mbufs[idx];
		if (unlikely(m == NULL))
			continue;

		__rte_mbuf_sanity_check(m, 1);

		do {
			m_next = m->next;
			__rte_pktmbuf_free_seg_via_array(
				m, pending, &nb_pending,
				RTE_PKTMBUF_FREE_PENDING_SZ);
			m = m_next;
		} while (m != NULL);
	}

	if (nb_pending > 0)
		rte_mempool_put_bulk(pending[0]->pool, (void **)pending,
				     nb_pending);
}
#endif /* RTE_VERSION < 19.11 */

#if RTE_VERSION_NUM(19, 8, 0, 0) < RTE_VERSION
#define ETHER_MIN_MTU		  RTE_ETHER_MIN_MTU
#define ETHER_ADDR_LEN		  RTE_ETHER_ADDR_LEN
#define ETHER_CRC_LEN		  RTE_ETHER_CRC_LEN
#define ETHER_HDR_LEN		  RTE_ETHER_HDR_LEN
#define ETHER_MIN_LEN		  RTE_ETHER_MIN_LEN
#define ETHER_MAX_LEN		  RTE_ETHER_MAX_LEN
#define ETHER_TYPE_1588		  RTE_ETHER_TYPE_1588
#define ETHER_TYPE_VLAN		  RTE_ETHER_TYPE_VLAN
#define ETHER_TYPE_IPv4		  RTE_ETHER_TYPE_IPV4
#define ETHER_TYPE_IPv6		  RTE_ETHER_TYPE_IPV6
#define ETHER_MAX_JUMBO_FRAME_LEN RTE_ETHER_MAX_JUMBO_FRAME_LEN
#define ETHER_LOCAL_ADMIN_ADDR	  RTE_ETHER_LOCAL_ADMIN_ADDR
#define IPV4_MAX_PKT_LEN	  RTE_IPV4_MAX_PKT_LEN
#define TCP_SYN_FLAG		  RTE_TCP_SYN_FLAG
#define ETHER_MAX_VLAN_ID	  RTE_ETHER_MAX_VLAN_ID

#define ipv4_hdr		  rte_ipv4_hdr
#define ipv6_hdr		  rte_ipv6_hdr

#else /* RTE_VERSION <= 19.05 */
#if RTE_VERSION_NUM(19, 5, 0, 0) > RTE_VERSION
#define RTE_TUNNEL_TYPE_VXLAN_GPE (RTE_TUNNEL_TYPE_MAX - 1)
#endif
#define RTE_TCP_SYN_FLAG 0x02 /**< Synchronize sequence numbers */
#define rte_ether_addr	 ether_addr
#define rte_tcp_hdr	 tcp_hdr
#define rte_sctp_hdr	 sctp_hdr
#define rte_vlan_hdr	 vlan_hdr

#define rte_vxlan_hdr	 vxlan_hdr
/**
 * UDP Header
 */
struct rte_udp_hdr {
	rte_be16_t src_port; /**< UDP source port. */
	rte_be16_t dst_port; /**< UDP destination port. */
	rte_be16_t dgram_len; /**< UDP datagram length */
	rte_be16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__((__packed__));

/**
 * GRE Header
 */
__extension__ struct rte_gre_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint16_t res2 : 4; /**< Reserved */
	uint16_t s : 1; /**< Sequence Number Present bit */
	uint16_t k : 1; /**< Key Present bit */
	uint16_t res1 : 1; /**< Reserved */
	uint16_t c : 1; /**< Checksum Present bit */
	uint16_t ver : 3; /**< Version Number */
	uint16_t res3 : 5; /**< Reserved */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint16_t c : 1; /**< Checksum Present bit */
	uint16_t res1 : 1; /**< Reserved */
	uint16_t k : 1; /**< Key Present bit */
	uint16_t s : 1; /**< Sequence Number Present bit */
	uint16_t res2 : 4; /**< Reserved */
	uint16_t res3 : 5; /**< Reserved */
	uint16_t ver : 3; /**< Version Number */
#endif
	uint16_t proto; /**< Protocol Type */
} __attribute__((__packed__));

#define rte_ipv6_hdr			 ipv6_hdr
#define rte_ipv4_hdr			 ipv4_hdr

#define rte_eth_random_addr		 eth_random_addr
#define rte_is_zero_ether_addr		 is_zero_ether_addr
#define rte_is_broadcast_ether_addr	 is_broadcast_ether_addr
#define rte_is_valid_assigned_ether_addr is_valid_assigned_ether_addr
#define rte_is_multicast_ether_addr	 is_multicast_ether_addr

#define RTE_ETHER_MIN_MTU		 68 /**< Minimum MTU for IPv4 packets, see RFC 791. */
#endif /* RTE_VERSION > 19.05 */

#if RTE_VERSION_NUM(16, 11, 0, 0) < RTE_VERSION && \
	RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
#define RTE_FLOW_ERROR_TYPE_ITEM_MASK	RTE_FLOW_ERROR_TYPE_ITEM_NUM
#define RTE_FLOW_ERROR_TYPE_ACTION	RTE_FLOW_ERROR_TYPE_ACTION
#define RTE_FLOW_ERROR_TYPE_ACTION_CONF RTE_FLOW_ERROR_TYPE_ACTION
#endif

#if RTE_VERSION_NUM(19, 5, 0, 0) > RTE_VERSION
#define RTE_TCP_SYN_FLAG 0x02 /**< Synchronize sequence numbers */
#endif
#if RTE_VERSION_NUM(19, 8, 0, 0) > RTE_VERSION
/**
 * Ethernet header: Contains the destination address, source address
 * and frame type.
 */
struct rte_ether_hdr {
	struct rte_ether_addr d_addr; /**< Destination address. */
	struct rte_ether_addr s_addr; /**< Source address. */
	uint16_t ether_type; /**< Frame type. */
} __attribute__((__packed__));
#define RTE_ETHER_MIN_MTU   68 /**< Minimum MTU for IPv4 packets, see RFC 791. */
/* Ethernet frame types */
#define RTE_ETHER_TYPE_QINQ 0x88A8 /**< IEEE 802.1ad QinQ tagging. */
#define RTE_ETHER_TYPE_VLAN 0x8100 /**< Arp Protocol. */
#define RTE_ETHER_TYPE_IPV4 0x0800 /**< IPv4 Protocol. */
#define RTE_ETHER_TYPE_IPV6 0x86DD /**< IPv6 Protocol. */
#define RTE_ETHER_TYPE_ARP  0x0806 /**< Arp Protocol. */
/**
  Fast copy an Ethernet address.
 *
 * @param ea_from
 *   A pointer to a ether_addr structure holding the Ethernet address to copy.
 * @param ea_to
 *   A pointer to a ether_addr structure where to copy the Ethernet address.
 */
static inline void rte_ether_addr_copy(const struct rte_ether_addr *ea_from,
				       struct rte_ether_addr *ea_to)
{
#ifdef __INTEL_COMPILER
	uint16_t *from_words = (uint16_t *)(ea_from->addr_bytes);
	uint16_t *to_words = (uint16_t *)(ea_to->addr_bytes);

	to_words[0] = from_words[0];
	to_words[1] = from_words[1];
	to_words[2] = from_words[2];
#else
	/*
	 * Use the common way, because of a strange gcc warning.
	 */
	*ea_to = *ea_from;
#endif
}

/**
 * Check if two Ethernet addresses are the same.
 *
 * @param ea1
 *  A pointer to the first ether_addr structure containing
 *  the ethernet address.
 * @param ea2
 *  A pointer to the second ether_addr structure containing
 *  the ethernet address.
 *
 * @return
 *  True  (1) if the given two ethernet address are the same;
 *  False (0) otherwise.
 */
static inline int rte_is_same_ether_addr(const struct rte_ether_addr *ea1,
					 const struct rte_ether_addr *ea2)
{
	const unaligned_uint16_t *w1 = (const uint16_t *)ea1;
	const unaligned_uint16_t *w2 = (const uint16_t *)ea2;

	return ((w1[0] ^ w2[0]) | (w1[1] ^ w2[1]) | (w1[2] ^ w2[2])) == 0;
}

#define ETH_QINQ_STRIP_MASK  0x0008 /**< QINQ Strip  setting mask */
#define RTE_ETHER_GROUP_ADDR 0x01 /**< Multicast or broadcast Eth. address. */
/**
 * Check if an Ethernet address is a unicast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a unicast address;
 *   false (0) otherwise.
 */
static inline int rte_is_unicast_ether_addr(const struct rte_ether_addr *ea)
{
	return (ea->addr_bytes[0] & RTE_ETHER_GROUP_ADDR) == 0;
}
static inline void rte_ether_format_addr(char *buf, uint16_t size,
					 const struct rte_ether_addr *eth_addr)
{
	snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X",
		 eth_addr->addr_bytes[0], eth_addr->addr_bytes[1],
		 eth_addr->addr_bytes[2], eth_addr->addr_bytes[3],
		 eth_addr->addr_bytes[4], eth_addr->addr_bytes[5]);
}
/**
 * VXLAN-GPE protocol header (draft-ietf-nvo3-vxlan-gpe-05).
 * Contains the 8-bit flag, 8-bit next-protocol, 24-bit VXLAN Network
 * Identifier and Reserved fields (16 bits and 8 bits).
 */
struct rte_vxlan_gpe_hdr {
	uint8_t vx_flags; /**< flag (8). */
	uint8_t reserved[2]; /**< Reserved (16). */
	uint8_t proto; /**< next-protocol (8). */
	uint32_t vx_vni; /**< VNI (24) + Reserved (8). */
} __attribute__((__packed__));
/**
 * ESP Header
 */
struct rte_esp_hdr {
	rte_be32_t spi; /**< Security Parameters Index */
	rte_be32_t seq; /**< packet sequence number */
} __attribute__((__packed__));
#define RTE_ETHER_ADDR_LEN 6 /**< Length of Ethernet address. */
#endif /* RTE_VERSION < 19.08 */

#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
#define ETH_RSS_LEVEL_PMD_DEFAULT (0ULL << 50)
#define ETH_RSS_LEVEL_OUTERMOST	  (1ULL << 50)
#define ETH_RSS_LEVEL_INNERMOST	  (2ULL << 50)
#define ETH_RSS_LEVEL_MASK	  (3ULL << 50)
#endif /* RTE_VERSION < 20.11 */

#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD PKT_RX_OUTER_IP_CKSUM_BAD
#endif /* 21.05 <= RTE_VERIONO < 21.11 */

#if RTE_VERSION_NUM(22, 3, 0, 0) > RTE_VERSION
static uint16_t __attribute__((unused))
rte_eth_pkt_burst_dummy(void *queue __rte_unused,
			struct rte_mbuf **pkts __rte_unused,
			uint16_t nb_pkts __rte_unused)
{
	return 0;
}
#endif

#if RTE_VERSION_NUM(21, 5, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD PKT_RX_EIP_CKSUM_BAD
#endif /* RTE_VERSION < 21.05 */

#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_TX_TUNNEL_VXLAN	    PKT_TX_TUNNEL_VXLAN
#define RTE_MBUF_F_TX_TUNNEL_GRE	    PKT_TX_TUNNEL_GRE
#define RTE_ETH_32_POOLS		    ETH_32_POOLS
#define RTE_ETH_RX_OFFLOAD_KEEP_CRC	    DEV_RX_OFFLOAD_KEEP_CRC
#define RTE_ETH_RX_OFFLOAD_CHECKSUM	    DEV_RX_OFFLOAD_CHECKSUM
#define RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM
#define RTE_ETH_RX_OFFLOAD_SCTP_CKSUM	    DEV_RX_OFFLOAD_SCTP_CKSUM
#define RTE_ETH_RX_OFFLOAD_TCP_CKSUM	    DEV_RX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_RX_OFFLOAD_UDP_CKSUM	    DEV_RX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_RX_OFFLOAD_IPV4_CKSUM	    DEV_RX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_RX_OFFLOAD_VLAN		    DEV_RX_OFFLOAD_VLAN
#define RTE_ETH_RX_OFFLOAD_VLAN_FILTER	    DEV_RX_OFFLOAD_VLAN_FILTER
#define RTE_ETH_RX_OFFLOAD_VLAN_STRIP	    DEV_RX_OFFLOAD_VLAN_STRIP
#define RTE_ETH_RX_OFFLOAD_QINQ_STRIP	    DEV_RX_OFFLOAD_QINQ_STRIP
#define RTE_ETH_RX_OFFLOAD_VLAN_EXTEND	    DEV_RX_OFFLOAD_VLAN_EXTEND
#define RTE_ETH_RX_OFFLOAD_JUMBO_FRAME	    DEV_RX_OFFLOAD_JUMBO_FRAME
#define RTE_ETH_RX_OFFLOAD_TIMESTAMP	    DEV_RX_OFFLOAD_TIMESTAMP
#define RTE_ETH_RX_OFFLOAD_RSS_HASH	    DEV_RX_OFFLOAD_RSS_HASH
#define RTE_ETH_RX_OFFLOAD_SCATTER	    DEV_RX_OFFLOAD_SCATTER
#define RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM  DEV_RX_OFFLOAD_OUTER_UDP_CKSUM

#define RTE_ETH_RSS_IPV6_UDP_EX		    ETH_RSS_IPV6_UDP_EX
#define RTE_ETH_RSS_IPV6_TCP_EX		    ETH_RSS_IPV6_TCP_EX
#define RTE_ETH_RSS_IPV6_EX		    ETH_RSS_IPV6_EX
#define RTE_ETH_RSS_NONFRAG_IPV6_SCTP	    ETH_RSS_NONFRAG_IPV6_SCTP
#define RTE_ETH_RSS_L4_SRC_ONLY		    ETH_RSS_L4_SRC_ONLY
#define RTE_ETH_RSS_GTPU		    ETH_RSS_GTPU
#define RTE_ETH_RSS_NVGRE		    ETH_RSS_NVGRE
#define RTE_ETH_RSS_PORT		    ETH_RSS_PORT
#define RTE_ETH_RSS_L2_PAYLOAD		    ETH_RSS_L2_PAYLOAD
#define RTE_ETH_RSS_NONFRAG_IPV6_UDP	    ETH_RSS_NONFRAG_IPV6_UDP
#define RTE_ETH_RSS_NONFRAG_IPV6_TCP	    ETH_RSS_NONFRAG_IPV6_TCP
#define RTE_ETH_RSS_NONFRAG_IPV6_SCTP	    ETH_RSS_NONFRAG_IPV6_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV4_UDP	    ETH_RSS_NONFRAG_IPV4_UDP
#define RTE_ETH_RSS_NONFRAG_IPV4_TCP	    ETH_RSS_NONFRAG_IPV4_TCP
#define RTE_ETH_RSS_NONFRAG_IPV4_SCTP	    ETH_RSS_NONFRAG_IPV4_SCTP
#define RTE_ETH_RSS_IPV4		    ETH_RSS_IPV4
#define RTE_ETH_RSS_IPV6		    ETH_RSS_IPV6
#define RTE_ETH_RSS_FRAG_IPV6		    ETH_RSS_FRAG_IPV6
#define RTE_ETH_RSS_FRAG_IPV4		    ETH_RSS_FRAG_IPV4
#define RTE_ETH_RSS_NONFRAG_IPV4_OTHER	    ETH_RSS_NONFRAG_IPV4_OTHER
#define RTE_ETH_RSS_NONFRAG_IPV6_OTHER	    ETH_RSS_NONFRAG_IPV6_OTHER
#define RTE_ETH_RSS_NONFRAG_IPV4_TCP	    ETH_RSS_NONFRAG_IPV4_TCP
#define RTE_ETH_RSS_L4_DST_ONLY		    ETH_RSS_L4_DST_ONLY
#define RTE_ETH_RSS_L4_SRC_ONLY		    ETH_RSS_L4_SRC_ONLY
#define RTE_ETH_RSS_L3_DST_ONLY		    ETH_RSS_L3_DST_ONLY
#define RTE_ETH_RSS_L3_SRC_ONLY		    ETH_RSS_L3_SRC_ONLY
#define RTE_ETH_RSS_GENEVE		    ETH_RSS_GENEVE
#define RTE_ETH_RSS_VXLAN		    ETH_RSS_VXLAN

#define RTE_ETH_RSS_LEVEL_INNERMOST	    ETH_RSS_LEVEL_INNERMOST
#define RTE_ETH_RSS_LEVEL_OUTERMOST	    ETH_RSS_LEVEL_OUTERMOST
#define RTE_ETH_RSS_LEVEL(rss_hf)	    ETH_RSS_LEVEL(rss_hf)
#define RTE_ETH_RSS_LEVEL_MASK		    ETH_RSS_LEVEL_MASK
#define RTE_ETH_RSS_LEVEL_PMD_DEFAULT	    (0x7ULL << 45)
#define RTE_ETH_MQ_RX_RSS_FLAG		    ETH_MQ_RX_RSS_FLAG
#define RTE_ETH_RETA_GROUP_SIZE		    RTE_RETA_GROUP_SIZE

#define RTE_ETH_TUNNEL_TYPE_VXLAN	    RTE_TUNNEL_TYPE_VXLAN
#define RTE_ETH_TUNNEL_TYPE_VXLAN_GPE       RTE_TUNNEL_TYPE_VXLAN_GPE
#define RTE_ETH_TUNNEL_TYPE_GENEVE          RTE_TUNNEL_TYPE_GENEVE
#define RTE_ETH_VLAN_FILTER_OFFLOAD	    ETH_VLAN_FILTER_OFFLOAD
#define RTE_ETH_VLAN_EXTEND_MASK	    ETH_VLAN_EXTEND_MASK
#define RTE_ETH_VLAN_STRIP_MASK		    ETH_VLAN_STRIP_MASK
#define RTE_ETH_QINQ_STRIP_MASK		    ETH_QINQ_STRIP_MASK
#define RTE_ETH_VLAN_FILTER_MASK	    ETH_VLAN_FILTER_MASK

#define RTE_ETH_TX_OFFLOAD_VLAN_INSERT	    DEV_TX_OFFLOAD_VLAN_INSERT
#define RTE_ETH_TX_OFFLOAD_QINQ_INSERT	    DEV_TX_OFFLOAD_QINQ_INSERT
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#define DEV_TX_OFFLOAD_MBUF_FAST_FREE 0x00010000
#endif
#define RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE   DEV_TX_OFFLOAD_MBUF_FAST_FREE
#define RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM  DEV_TX_OFFLOAD_OUTER_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_IPV4_CKSUM	    DEV_TX_OFFLOAD_IPV4_CKSUM
#define RTE_ETH_TX_OFFLOAD_UDP_CKSUM	    DEV_TX_OFFLOAD_UDP_CKSUM
#define RTE_ETH_TX_OFFLOAD_TCP_CKSUM	    DEV_TX_OFFLOAD_TCP_CKSUM
#define RTE_ETH_TX_OFFLOAD_SCTP_CKSUM	    DEV_TX_OFFLOAD_SCTP_CKSUM
#define RTE_ETH_TX_OFFLOAD_MULTI_SEGS	    DEV_TX_OFFLOAD_MULTI_SEGS
#define RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO    DEV_TX_OFFLOAD_VXLAN_TNL_TSO
#define RTE_ETH_TX_OFFLOAD_TCP_TSO	    DEV_TX_OFFLOAD_TCP_TSO
#define RTE_ETH_TX_OFFLOAD_UDP_TSO	    DEV_TX_OFFLOAD_UDP_TSO
#define RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO	    DEV_TX_OFFLOAD_GRE_TNL_TSO
#define RTE_ETH_MQ_TX_DCB		    ETH_MQ_TX_DCB

#define RTE_ETH_FC_NONE			    RTE_FC_NONE
#define RTE_ETH_FC_FULL			    RTE_FC_FULL
#define RTE_ETH_FC_TX_PAUSE		    RTE_FC_TX_PAUSE
#define RTE_ETH_FC_RX_PAUSE		    RTE_FC_RX_PAUSE

#define RTE_ETH_LINK_SPEED_AUTONEG	    ETH_LINK_SPEED_AUTONEG
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
#define RTE_ETH_LINK_SPEED_FIXED ETH_LINK_SPEED_FIXED
#endif
#define RTE_ETH_SPEED_NUM_10M	   ETH_SPEED_NUM_10M
#define RTE_ETH_SPEED_NUM_100M	   ETH_SPEED_NUM_100M
#define RTE_ETH_SPEED_NUM_1G	   ETH_SPEED_NUM_1G
#define RTE_ETH_SPEED_NUM_40G	   ETH_SPEED_NUM_40G
#define RTE_ETH_SPEED_NUM_100G	   ETH_SPEED_NUM_100G
#define RTE_ETH_SPEED_NUM_25G	   ETH_SPEED_NUM_25G
#define RTE_ETH_SPEED_NUM_10G	   ETH_SPEED_NUM_10G

#define RTE_ETH_LINK_FIXED	   ETH_LINK_FIXED
#define RTE_ETH_LINK_AUTONEG	   ETH_LINK_AUTONEG
#define RTE_ETH_LINK_DOWN	   ETH_LINK_DOWN
#define RTE_ETH_LINK_UP		   ETH_LINK_UP
#define RTE_ETH_LINK_FULL_DUPLEX   ETH_LINK_FULL_DUPLEX
#define RTE_ETH_LINK_HALF_DUPLEX   ETH_LINK_HALF_DUPLEX
#define RTE_ETH_LINK_SPEED_40G	   ETH_LINK_SPEED_40G
#define RTE_ETH_LINK_SPEED_25G	   ETH_LINK_SPEED_25G
#define RTE_ETH_LINK_SPEED_100G	   ETH_LINK_SPEED_100G
#define RTE_ETH_LINK_SPEED_10G	   ETH_LINK_SPEED_10G
#define RTE_ETH_LINK_SPEED_1G	   ETH_LINK_SPEED_1G
#define RTE_ETH_LINK_SPEED_100M	   ETH_LINK_SPEED_100M
#define RTE_ETH_LINK_SPEED_100M_HD ETH_LINK_SPEED_100M_HD
#define RTE_ETH_LINK_SPEED_10M	   ETH_LINK_SPEED_10M
#define RTE_ETH_LINK_SPEED_10M_HD  ETH_LINK_SPEED_10M_HD

#define RTE_ETH_VLAN_TYPE_OUTER	   ETH_VLAN_TYPE_OUTER
#define RTE_ETH_VLAN_TYPE_INNER	   ETH_VLAN_TYPE_INNER
#if RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_TX_VLAN PKT_TX_VLAN_PKT
#else
#define RTE_MBUF_F_TX_VLAN PKT_TX_VLAN
#endif
#define RTE_MBUF_F_TX_QINQ		  PKT_TX_QINQ_PKT
#define RTE_MBUF_F_TX_TUNNEL_MASK	  PKT_TX_TUNNEL_MASK
#define RTE_MBUF_F_TX_TCP_SEG		  PKT_TX_TCP_SEG
#define RTE_MBUF_F_TX_OUTER_IP_CKSUM	  PKT_TX_OUTER_IP_CKSUM
#define RTE_MBUF_F_TX_OUTER_UDP_CKSUM	  PKT_TX_OUTER_UDP_CKSUM
#define RTE_MBUF_F_TX_IP_CKSUM		  PKT_TX_IP_CKSUM
#define RTE_MBUF_F_TX_UDP_CKSUM		  PKT_TX_UDP_CKSUM
#define RTE_MBUF_F_TX_TCP_CKSUM		  PKT_TX_TCP_CKSUM
#define RTE_MBUF_F_TX_SCTP_CKSUM	  PKT_TX_SCTP_CKSUM
#define RTE_MBUF_F_TX_L4_MASK		  PKT_TX_L4_MASK
#define RTE_MBUF_F_TX_IPV4		  PKT_TX_IPV4
#define RTE_MBUF_F_TX_IPV6		  PKT_TX_IPV6
#define RTE_MBUF_F_TX_OUTER_IPV4	  PKT_TX_OUTER_IPV4
#define RTE_MBUF_F_TX_OUTER_IPV6	  PKT_TX_OUTER_IPV6
#define RTE_MBUF_F_TX_OFFLOAD_MASK	  PKT_TX_OFFLOAD_MASK
#define RTE_MBUF_F_TX_IEEE1588_TMST	  PKT_TX_IEEE1588_TMST
#define RTE_MBUF_F_TX_UDP_SEG		  PKT_TX_UDP_SEG
#define RTE_MBUF_F_TX_TCP_SEG		  PKT_TX_TCP_SEG

#define RTE_MBUF_F_TX_TUNNEL_ESP	  (0x8ULL << 45)
#define RTE_MBUF_F_TX_TUNNEL_GENEVE	  (0x4ULL << 45)
#define RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE	  (0x6ULL << 45)
#define RTE_MBUF_F_TX_TUNNEL_GTP	  (0x7ULL << 45)

#define RTE_MBUF_F_RX_VLAN_STRIPPED	  PKT_RX_VLAN_STRIPPED
#define RTE_MBUF_F_RX_QINQ_STRIPPED	  PKT_RX_QINQ_STRIPPED
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD	  PKT_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_IP_CKSUM_BAD	  PKT_RX_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD	  PKT_RX_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD	  PKT_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD PKT_RX_OUTER_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD  PKT_RX_OUTER_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_RSS_HASH		  PKT_RX_RSS_HASH
#define RTE_MBUF_F_RX_FDIR		  PKT_RX_FDIR
#define RTE_MBUF_F_RX_FDIR_ID		  PKT_RX_FDIR_ID
#define RTE_MBUF_F_RX_VLAN		  PKT_RX_VLAN
#define RTE_MBUF_F_RX_IEEE1588_PTP	  PKT_RX_IEEE1588_PTP
#define RTE_MBUF_F_RX_IEEE1588_TMST	  PKT_RX_IEEE1588_TMST
#define RTE_MBUF_F_RX_QINQ		  PKT_RX_QINQ_PKT

#define RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO \
	RTE_BIT64(12) /**< Used for tunneling packet. */
#define RTE_TAILQ_FOREACH_SAFE TAILQ_FOREACH_SAFE
#define RTE_TAILQ_FOREACH      TAILQ_FOREACH

#define RTE_VLAN_HLEN	       4 /**< VLAN (IEEE 802.1Q) header length. */
#define RTE_ETH_RSS_ESP	       RTE_BIT64(27)

#define RTE_ETH_DCB_PFC_SUPPORT \
	RTE_BIT32(1) /**< Priority Flow Control support. */
#define RTE_ETH_DCB_PG_SUPPORT RTE_BIT32(0) /**< Priority Group(ETS) support. */

/**
 * Macro to extract the MAC address bytes from rte_ether_addr struct
 */
#define RTE_ETHER_ADDR_BYTES(mac_addrs) ((mac_addrs)->addr_bytes[0]), \
					((mac_addrs)->addr_bytes[1]), \
					((mac_addrs)->addr_bytes[2]), \
					((mac_addrs)->addr_bytes[3]), \
					((mac_addrs)->addr_bytes[4]), \
					((mac_addrs)->addr_bytes[5])
#endif /* RTE_VERSION < 21.11 */

#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
struct rte_geneve_hdr {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t ver : 2; /**< Version. */
	uint8_t opt_len : 6; /**< Options length. */
	uint8_t oam : 1; /**< Control packet. */
	uint8_t critical : 1; /**< Critical packet. */
	uint8_t reserved1 : 6; /**< Reserved. */
#else
	uint8_t opt_len : 6; /**< Options length. */
	uint8_t ver : 2; /**< Version. */
	uint8_t reserved1 : 6; /**< Reserved. */
	uint8_t critical : 1; /**< Critical packet. */
	uint8_t oam : 1; /**< Control packet. */
#endif
	rte_be16_t proto; /**< Protocol type. */
	uint8_t vni[3]; /**< Virtual network identifier. */
	uint8_t reserved2; /**< Reserved. */
	uint32_t opts[]; /**< Variable length options. */
} __rte_packed;
#endif /* RTE_VERSION <= 21.11 */

#if RTE_VERSION_NUM(22, 11, 0, 0) <= RTE_VERSION
#define DEV_RX_OFFLOAD_CHECKSUM		RTE_ETH_RX_OFFLOAD_CHECKSUM
#define DEV_RX_OFFLOAD_IPV4_CKSUM	RTE_ETH_RX_OFFLOAD_IPV4_CKSUM
#define DEV_RX_OFFLOAD_UDP_CKSUM	RTE_ETH_RX_OFFLOAD_UDP_CKSUM
#define DEV_RX_OFFLOAD_TCP_CKSUM	RTE_ETH_RX_OFFLOAD_TCP_CKSUM
#define DEV_RX_OFFLOAD_SCTP_CKSUM	RTE_ETH_RX_OFFLOAD_SCTP_CKSUM
#define DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM
#define DEV_RX_OFFLOAD_VLAN_STRIP	RTE_ETH_RX_OFFLOAD_VLAN_STRIP
#define DEV_RX_OFFLOAD_VLAN_FILTER	RTE_ETH_RX_OFFLOAD_VLAN_FILTER
#define DEV_RX_OFFLOAD_VLAN_EXTEND	RTE_ETH_RX_OFFLOAD_VLAN_EXTEND
#define DEV_RX_OFFLOAD_RSS_HASH		RTE_ETH_RX_OFFLOAD_RSS_HASH
#define DEV_RX_OFFLOAD_TIMESTAMP	RTE_ETH_RX_OFFLOAD_TIMESTAMP
#define DEV_RX_OFFLOAD_SCATTER		RTE_ETH_RX_OFFLOAD_SCATTER

#define DEV_TX_OFFLOAD_MBUF_FAST_FREE	RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
#define DEV_TX_OFFLOAD_IPV4_CKSUM	RTE_ETH_TX_OFFLOAD_IPV4_CKSUM
#define DEV_TX_OFFLOAD_UDP_CKSUM	RTE_ETH_TX_OFFLOAD_UDP_CKSUM
#define DEV_TX_OFFLOAD_TCP_CKSUM	RTE_ETH_TX_OFFLOAD_TCP_CKSUM
#define DEV_TX_OFFLOAD_SCTP_CKSUM	RTE_ETH_TX_OFFLOAD_SCTP_CKSUM
#define DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM
#define DEV_TX_OFFLOAD_TCP_TSO		RTE_ETH_TX_OFFLOAD_TCP_TSO
#define DEV_TX_OFFLOAD_VLAN_INSERT	RTE_ETH_TX_OFFLOAD_VLAN_INSERT
#define DEV_TX_OFFLOAD_VXLAN_TNL_TSO	RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO
#define DEV_TX_OFFLOAD_GRE_TNL_TSO	RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO
#define DEV_TX_OFFLOAD_QINQ_INSERT	RTE_ETH_TX_OFFLOAD_QINQ_INSERT

#define ETH_RSS_IPV4			RTE_ETH_RSS_IPV4
#define ETH_RSS_FRAG_IPV4		RTE_ETH_RSS_FRAG_IPV4
#define ETH_RSS_NONFRAG_IPV4_OTHER	RTE_ETH_RSS_NONFRAG_IPV4_OTHER
#define ETH_RSS_NONFRAG_IPV4_TCP	RTE_ETH_RSS_NONFRAG_IPV4_TCP
#define ETH_RSS_NONFRAG_IPV4_UDP	RTE_ETH_RSS_NONFRAG_IPV4_UDP
#define ETH_RSS_NONFRAG_IPV4_SCTP	RTE_ETH_RSS_NONFRAG_IPV4_SCTP
#define ETH_RSS_IPV6			RTE_ETH_RSS_IPV6
#define ETH_RSS_FRAG_IPV6		RTE_ETH_RSS_FRAG_IPV6
#define ETH_RSS_NONFRAG_IPV6_OTHER	RTE_ETH_RSS_NONFRAG_IPV6_OTHER
#define ETH_RSS_IPV6_EX			RTE_ETH_RSS_IPV6_EX
#define ETH_RSS_IPV6_TCP_EX		RTE_ETH_RSS_IPV6_TCP_EX
#define ETH_RSS_NONFRAG_IPV6_TCP	RTE_ETH_RSS_NONFRAG_IPV6_TCP
#define ETH_RSS_IPV6_UDP_EX		RTE_ETH_RSS_IPV6_UDP_EX
#define ETH_RSS_NONFRAG_IPV6_SCTP	RTE_ETH_RSS_NONFRAG_IPV6_SCTP

#define ETH_RSS_L2_PAYLOAD		RTE_ETH_RSS_L2_PAYLOAD
#define ETH_RSS_PORT			RTE_ETH_RSS_PORT
#define ETH_RSS_VXLAN			RTE_ETH_RSS_VXLAN
#define ETH_RSS_GENEVE			RTE_ETH_RSS_GENEVE
#define ETH_RSS_NVGRE			RTE_ETH_RSS_NVGRE
#define ETH_RSS_GTPU			RTE_ETH_RSS_GTPU
#define ETH_RSS_L3_SRC_ONLY		RTE_ETH_RSS_L3_SRC_ONLY
#define ETH_RSS_L3_DST_ONLY		RTE_ETH_RSS_L3_DST_ONLY
#define ETH_RSS_L4_SRC_ONLY		RTE_ETH_RSS_L4_SRC_ONLY
#define ETH_RSS_L4_DST_ONLY		RTE_ETH_RSS_L4_DST_ONLY

#define RTE_MBUF_F_TX_TUNNEL_GTP	(0x7ULL << 45)
#endif /* RTE_VERSION < 22.11 */

#if RTE_VERSION_NUM(23, 11, 0, 0) > RTE_VERSION
/**
 * Get the count of 1-bits in v.
 *
 * @param v
 *   The value.
 * @return
 *   The count of 1-bits.
 */
static inline unsigned int rte_popcount64(uint64_t v)
{
	return (unsigned int)__builtin_popcountll(v);
}
#ifdef RTE_ENABLE_STDATOMIC
#include <stdatomic.h>
#define rte_atomic_load_explicit(ptr, memorder) \
        atomic_load_explicit(ptr, memorder)
#define rte_atomic_store_explicit(ptr, val, memorder) \
        atomic_store_explicit(ptr, val, memorder)
#define rte_atomic_exchange_explicit(ptr, val, memorder) \
        atomic_exchange_explicit(ptr, val, memorder)
#define rte_atomic_fetch_add_explicit(ptr, val, memorder) \
	atomic_fetch_add_explicit(ptr, val, memorder)
#define rte_atomic_fetch_sub_explicit(ptr, val, memorder) \
	atomic_fetch_sub_explicit(ptr, val, memorder)
#define RTE_ATOMIC(type) _Atomic(type)
#else
/* The memory order is an integer type in GCC built-ins */
#define RTE_ATOMIC(type) type
#define rte_atomic_load_explicit(ptr, memorder) \
	__atomic_load_n(ptr, memorder)
#define rte_atomic_store_explicit(ptr, val, memorder) \
	__atomic_store_n(ptr, val, memorder)
#define rte_atomic_fetch_add_explicit(ptr, val, memorder) \
		__atomic_fetch_add(ptr, val, memorder)
#define rte_atomic_fetch_sub_explicit(ptr, val, memorder) \
	__atomic_fetch_sub(ptr, val, memorder)
#define rte_memory_order_relaxed __ATOMIC_RELAXED
#define rte_memory_order_consume __ATOMIC_CONSUME
#define rte_memory_order_acquire __ATOMIC_ACQUIRE
#define rte_memory_order_release __ATOMIC_RELEASE
#define rte_memory_order_acq_rel __ATOMIC_ACQ_REL
#define rte_memory_order_seq_cst __ATOMIC_SEQ_CST
#endif /* RTE_ENABLE_STDATOMIC */
#endif /* RTE_VERSION < 23.11 */
#if RTE_VERSION_NUM(25, 3, 0, 0) > RTE_VERSION
static inline unsigned int rte_ffs64(uint64_t v)
{
	return (unsigned int)__builtin_ffsll(v);
}
#endif /* RTE_VERSION < 25.03 */
#if RTE_VERSION_NUM(24, 3, 0, 0) <= RTE_VERSION
#define HAVE_RTE_ETH_DEV_IS_REPR
#endif /* RTE_VERSION >= 24.03 */
#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
#define HAVE_TM_MODULE
#endif /* RTE_VERSION >= 17.08 */

#if RTE_VERSION_NUM(25, 3, 0, 0) > RTE_VERSION
#define __rte_packed_begin
#define __rte_packed_end __rte_packed
#endif

/**
 * Generate a contiguous 32-bit mask
 * starting at bit position low and ending at position high.
 *
 * @param high
 *   High bit position.
 * @param low
 *   Low bit position.
 */
#define RTE_GENMASK32(high, low) \
                (((~UINT32_C(0)) << (low)) & (~UINT32_C(0) >> (31u - (high))))

/**
 * Generate a contiguous 64-bit mask
 * starting at bit position low and ending at position high.
 *
 * @param high
 *   High bit position.
 * @param low
 *   Low bit position.
 */
#define RTE_GENMASK64(high, low) \
                (((~UINT64_C(0)) << (low)) & (~UINT64_C(0) >> (63u - (high))))

#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
#define RTE_VXLAN_DEFAULT_PORT 4789 /** VXLAN default port. */
#define RTE_VXLAN_GPE_DEFAULT_PORT 4790 /** VXLAN GPE port. */
#define RTE_GENEVE_DEFAULT_PORT 6081 /** GENEVE default port. */
#else
#include <rte_vxlan.h>
#include <rte_geneve.h>
#endif /* RTE_VERSION < 20.11 */
#ifndef RTE_MPLSoUDP_DEFAULT_PORT
#define RTE_MPLSoUDP_DEFAULT_PORT 6635 /** MPLS o UDP Default port */
#endif
#if RTE_VERSION_NUM(20, 2, 0, 0) >= RTE_VERSION
#define RTE_GTPC_UDP_PORT 2123 /**< GTP-C UDP destination port */
#define RTE_GTPU_UDP_PORT 2152 /**< GTP-U UDP destination port */
#else
#include <rte_gtp.h>
#endif /* RTE_VERSION < 19.11 */
#endif /* __RTE_COMPANT_H_ */
