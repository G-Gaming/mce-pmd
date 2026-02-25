/**
 * @file mce_rxtx.h
 * @brief Receive and Transmit queue management interface
 *
 * This header defines the RX/TX queue operations for the MCE PMD driver.
 * Provides queue lifecycle management (setup, start, stop, release),
 * buffer descriptor structures, and packet header parsing definitions.
 *
 * Key features:
 * - Queue setup and configuration
 * - Queue start/stop operations
 * - RX/TX buffer descriptor formats
 * - Checksum and packet type parsing
 * - VLAN stripping and insertion support
 * - Timestamp and mark ID handling
 * - Support for tunneled packets (GTP, GRE, VXLAN, etc.)
 * - Vectorized RX/TX operations (SSE, NEON)
 *
 * Queue lifecycle:
 * 1. mce_rx_queue_setup() / mce_tx_queue_setup()  - Configure queue
 * 2. mce_dev_start() - Enable device and queues
 * 3. mce_rx_queue_start() / mce_tx_queue_start() - Start individual queues
 * 4. [Packet processing]
 * 5. mce_rx_queue_stop() / mce_tx_queue_stop()   - Stop individual queues
 * 6. mce_rx_queue_release() / mce_tx_queue_release() - Clean up resources
 *
 * @see base/mce_osdep.h for OS-dependent definitions
 * @see mce_rxtx.c for implementation
 * @see base/mce_ptype.h for packet type definitions
 */

#ifndef _MCE_RXTX_H_
#define _MCE_RXTX_H_

#include "base/mce_osdep.h"

/**
 * @brief Start a RX queue on the device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id RX queue index to start.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_rx_queue_start(struct rte_eth_dev *dev, uint16_t queue_id);

/**
 * @brief Stop a RX queue on the device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id RX queue index to stop.
 */
int mce_rx_queue_stop(struct rte_eth_dev *dev, uint16_t queue_id);

/**
 * @brief Start a TX queue on the device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id TX queue index to start.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_tx_queue_start(struct rte_eth_dev *dev, uint16_t queue_id);

/**
 * @brief Stop a TX queue on the device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id TX queue index to stop.
 */
int mce_tx_queue_stop(struct rte_eth_dev *dev, uint16_t queue_id);

/**
 * @brief Setup an RX queue for the device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_idx Software queue index.
 * @param nb_desc Number of descriptors for the ring.
 * @param socket_id Socket identifier for memory allocation.
 * @param rx_conf RX queue configuration.
 * @param mp Mempool to allocate mbufs from.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			   uint16_t nb_desc, unsigned int socket_id,
			   const struct rte_eth_rxconf *rx_conf,
			   struct rte_mempool *mp);

/**
 * @brief Setup a TX queue for the device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_idx Software queue index.
 * @param nb_desc Number of descriptors for the ring.
 * @param socket_id Socket identifier for memory allocation.
 * @param tx_conf TX queue configuration.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			   uint16_t nb_desc, unsigned int socket_id,
			   const struct rte_eth_txconf *tx_conf);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
void mce_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id);
void mce_dev_tx_queue_release(struct rte_eth_dev *dev, uint16_t qid);
#endif
void mce_rx_queue_release(void *rxq);
void mce_tx_queue_release(void *rxq);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
uint32_t mce_dev_rx_queue_count(void *rx_queue);
#else
uint32_t mce_dev_rx_queue_count(struct rte_eth_dev *dev, uint16_t q_id);
#endif
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
int mce_dev_rx_descriptor_done(void *rx_queue, uint16_t offset);
#endif
#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
int mce_dev_rx_descriptor_status(void *rx_queue, uint16_t offset);
int mce_dev_tx_descriptor_status(void *tx_queue, uint16_t offset);
#endif
struct mce_queue_attr {
	uint64_t sriov_st;
	uint16_t vf_num;          /**< Mark Ring belong to which VF */
	uint16_t queue_id;        /**< Software Queue Index */
	uint16_t index;           /**< DMA Ring Index */
	uint16_t lane_id;         /**< Ring Belong To Which Physical Lane */
	uint16_t nb_desc;         /**< Max Buffer Descriptors */
	uint16_t nb_desc_mask;    /**< Mask of Buffer Descriptors (nb_desc - 1) */
	uint16_t rte_pid;         /**< DPDK Managed Port Sequence ID */
};

#define MCE_CMD_EOP RTE_BIT32(0)
#define MCE_CMD_DD  RTE_BIT32(1)
#define MCE_CMD_RS  RTE_BIT32(2)
#pragma pack(push)
#pragma pack(1)

/**
 * @enum mce_rx_l4type
 * @brief RX descriptor L4 protocol type values
 *
 * @var MCE_RX_L4_FRAG IP fragmented packet
 * @var MCE_RX_L4_UDP UDP protocol
 * @var MCE_RX_L4_TCP TCP protocol
 * @var MCE_RX_L4_SCTP SCTP protocol
 * @var MCE_RX_L4_ICMP ICMP protocol
 * @var MCE_RX_L4_ESP IPsec ESP protocol
 * @var MCE_RX_L4_PAY Generic payload (no recognized L4 header)
 * @var MCE_RX_L4_UDP_ESP UDP tunneling ESP
 */
enum mce_rx_l4type {
	MCE_RX_L4_FRAG = 1,
	MCE_RX_L4_UDP,
	MCE_RX_L4_TCP,
	MCE_RX_L4_SCTP,
	MCE_RX_L4_ICMP,
	MCE_RX_L4_ESP,
	MCE_RX_L4_PAY,
	MCE_RX_L4_UDP_ESP,
};

/**
 * @enum mce_rx_l2type
 * @brief RX descriptor L2 frame type values
 *
 * @var MCE_RX_L2_UC_MPLS Unicast MPLS label
 * @var MCE_RX_L2_MC_MPLS Multicast MPLS label
 * @var MCE_RX_L2_802_3 IEEE 802.3 Ethernet frame
 * @var MCE_RX_L2_NSH Network Service Header
 * @var MCE_RX_L2_QINQ 802.1Q VLAN-in-VLAN (QinQ/stacked VLAN)
 * @var MCE_RX_L2_FCOE Fibre Channel over Ethernet
 */
enum mce_rx_l2type {
	MCE_RX_L2_UC_MPLS = 1,
	MCE_RX_L2_MC_MPLS,
	MCE_RX_L2_802_3,
	MCE_RX_L2_NSH,
	MCE_RX_L2_QINQ,
	MCE_RX_L2_FCOE,
};

/**
 * @enum mce_rx_l3type
 * @brief RX descriptor L3 protocol type values
 *
 * @var MCE_RX_L3_IPV4 IPv4 protocol
 * @var MCE_RX_L3_IPV6 IPv6 protocol
 * @var MCE_RX_L3_ARP Address Resolution Protocol
 */
enum mce_rx_l3type {
	MCE_RX_L3_IPV4 = 1,
	MCE_RX_L3_IPV6,
	MCE_RX_L3_ARP,
};

/**
 * @enum mce_rx_tun_type
 * @brief RX descriptor tunnel protocol type values
 *
 * @var MCE_RX_TUN_VXLAN VXLAN tunnel
 * @var MCE_RX_TUN_GRE Generic Routing Encapsulation tunnel
 * @var MCE_RX_TUN_GENEVE GENEVE tunnel
 * @var MCE_RX_TUN_GTP_U GTP-U (GTP User Plane) tunnel
 * @var MCE_RX_TUN_GTP_C GTP-C (GTP Control Plane) tunnel
 * @var MCE_RX_TUN_IPINIP IP-in-IP tunnel
 * @var MCE_RX_TUN_MPLS_UDP MPLS over UDP tunnel
 */
enum mce_rx_tun_type {
	MCE_RX_TUN_VXLAN = 1,
	MCE_RX_TUN_GRE,
	MCE_RX_TUN_GENEVE,
	MCE_RX_TUN_GTP_U,
	MCE_RX_TUN_GTP_C,
	MCE_RX_TUN_IPINIP,
	MCE_RX_TUN_MPLS_UDP,
};

/* RX buffer descriptor */
union mce_rx_desc {
	struct {
		__le64 pkt_addr; /* Packet buffer address */
		__le64 rsvd1;
		__le64 rsvd2;
		__le64 rsvd3;
		/* bit 2 is rs */
		/* bit 1 is dd */
	} d;
	struct {
		__le32 rss_hash;
		__le32 len_pad;

		__le16 vlan_tag1;
		__le16 vlan_tag2;

		struct {
			u32 timestamp_l;
			u32 timestamp_h;
		} stamp;
		__le32 mark_id;

		__le16 rsvd;
#define MCE_RX_STRIP_VLAN      GENMASK_U32(11, 10)
#define MCE_RX_STRIP_VLAN_S    (10)
#define MCE_RX_RSS_VALID       RTE_BIT32(9)
#define MCE_RX_MARK_VALID      RTE_BIT32(8)
#define MCE_RX_INNER_L4CKSUM_E RTE_BIT32(5)
#define MCE_RX_INNER_L3CKSUM_E RTE_BIT32(4)
#define MCE_RX_OUT_L4CKSUM_E   RTE_BIT32(3)
#define MCE_RX_OUT_L3CKSUM_E   RTE_BIT32(2)
#define MCE_RX_HDR_INVALID     RTE_BIT32(1)
#define MCE_RX_MAC_INVALID     RTE_BIT32(0)
#define MCE_RX_CKSUM_ERR_MASK  GENMASK_U32(5, 0)
		__le16 err_cmd;
#define MCE_RX_F_RPU		 RTE_BIT32(23)
#define MCE_RX_INNER_L4TYPE_MASK GENMASK_U32(22, 19)
#define MCE_RX_INNER_L4TYPE_S	 (19)
#define MCE_RX_INNER_L3TYPE_MASK GENMASK_U32(18, 17)
#define MCE_RX_INNER_L3TYPE_S	 (17)
#define MCE_RX_INNER_L2_ETHER	 RTE_BIT32(16)
#define MCE_RX_TUNNEL_TYPE_MASK	 GENMASK_U32(15, 13)
#define MCE_RX_TUNNEL_TYPE_S	 (13)
#define MCE_RX_OUT_L4TYPE_MASK	 GENMASK_U32(12, 9)
#define MCE_RX_OUT_L4TYPE_S	 (9)
#define MCE_RX_OUT_L3TYPE_MASK	 GENMASK_U32(8, 7)
#define MCE_RX_OUT_L3TYPE_S	 (7)
#define MCE_RX_OUT_L2TYPE_MASK	 GENMASK_U32(6, 4)
#define MCE_RX_OUT_L2TYPE_S	 (4)
#define MCE_RX_L2TYPE_VLAN	 RTE_BIT32(3)
#define MCE_RX_PTP		 RTE_BIT32(2)
#define MCE_RX_DD		 RTE_BIT32(1)
#define MCE_RX_EOP		 RTE_BIT32(0)
		__le32 cmd;
	} wb;
};
#pragma pack(pop)

#define MCE_RX_DEFAULT_WTHRESH     (1)
#define MCE_TX_DEFAULT_WTHRESH	   (1)
/* 8(BURST) + 56(THRESH) <= 64 */
#define MCE_RX_DEFAULT_BURST	   (16)
#define MCE_TX_DEFAULT_BURST	   (16)
#define MCE_RX_DESC_HIGH_WATER_TH  (48)
#define MCE_TX_DESC_HIGH_WATER_TH  (48)
#define MCE_DEFAULT_TX_RS_THRESH   (32)
#define MCE_DEFAULT_TX_FREE_THRESH (32)
#define upper_32_bits(n)	   ((uint32_t)(((n) >> 16) >> 16))
#define lower_32_bits(n)	   ((uint32_t)(n))
#define MCE_BD_RING_ALIGN	   (64)
#define MCE_RX_MAX_BURST_SIZE	   (32)
#define MCE_MAX_RING_DESC	   (4096)
#define MCE_RX_MAX_RING_SZ                             \
	((MCE_MAX_RING_DESC + MCE_RX_MAX_BURST_SIZE) * \
		 sizeof(union mce_rx_desc))
#define MCE_TX_MAX_RING_SZ                             \
	((MCE_MAX_RING_DESC + MCE_RX_MAX_BURST_SIZE) * \
	 sizeof(union mce_tx_desc))
struct mce_rxsw_entry {
	struct rte_mbuf *mbuf; /* Sync With Tx Desc Dma Physical Addr */
};

struct xstats {
	uint64_t obytes;
	uint64_t opackets;

	uint64_t ibytes;
	uint64_t ipackets;
	uint64_t rx_missed;

	uint64_t errors;
	/* xmit func can't recycle bd  because of the DD hw Don't set */
	uint64_t tx_ring_full;
	/* Tx sw Drop Pkts because of bd resource */
	uint64_t tx_full_drop;
	uint64_t tx_tso_pkts;
};

struct mce_rx_queue {
	struct rte_mempool *mb_pool; /* mbuf pool to populate RX ring. */
	const struct rte_memzone *rz; /* used for store ring base mem */
	volatile union mce_rx_desc *rx_bdr; /* Rx Dma Ring Virtual Addr */
	struct mce_rx_desc_addr *rx_buf;
	uint64_t ring_phys_addr; /* Rx Dma Ring Physical Addr */
	struct mce_rxsw_entry *sw_ring; /* Rx Software Ring Addr */
	void *rx_tailreg; /* HW Desc Tail Register */
	void *rx_headreg; /* HW Desc Head Register*/
	struct mce_queue_attr attr;
	uint8_t l3_l4_cksum[16];
	uint16_t rx_buf_len;
	uint8_t strip_len;
	bool rx_desc_cb;
	bool mark_enabled;
	bool pad_len;
	uint16_t rx_tail;
	uint16_t nb_rx_free;
	uint16_t rx_free_trigger; /* Rx Free Desc Resource Trigger */
	uint16_t rx_free_thresh; /* Rx Free Desc Resource Thresh */
	uint8_t wthresh; /* desc Write-back threshold */
	uint8_t pthresh; /* hw prefetch desc threshold */
	uint8_t hthresh;
	struct rte_mbuf fake_mbuf; /**< dummy mbuf */

	uint64_t mbuf_initializer; /**< value to init mbufs */
	uint16_t rxrearm_start;
	uint16_t rxrearm_nb;

	uint64_t rx_offload_capa; /* Enable rxq offload feature */

	struct rte_mbuf *pkt_first_seg; /* First Segment Pkt Of Jumbo Frame */
	struct rte_mbuf *pkt_last_seg; /* Last Segment Pkts Of Jumbo Frame */
	uint64_t rx_desc_drop;

	int mce_sport_dynfield_offset;
	uint64_t mce_sport_rx_dynflag;
	int mce_admin_dynfield_offset;
	uint64_t mce_admin_dynflag;
	int ts_offset; /* dynamic mbuf timestamp field offset */
	uint64_t ts_flag; /* dynamic mbuf timestamp flag */
	uint32_t time_high;
	uint32_t time_low;

	struct xstats rep_stats;
};

struct mce_txsw_entry {
	struct rte_mbuf *mbuf; /* Sync With Tx Desc Dma Physical Addr */
	uint16_t next_id; /* Next Entry Resource Hold Index */
	uint16_t prev_id; /* Prev Entry Resource Hold Index */
	uint16_t cur_id; /* Cur Entry Resource Hold Index */
	uint16_t rs_bit_set;
	uint16_t last_id; /* Last Entry Resource Hold Index */
	uint16_t nb_seg;
};
enum mce_tx_tun_type {
	MCE_TX_TUN_VXLAN = 1,
	MCE_TX_TUN_GRE,
	MCE_TX_TUN_GENEVE,
	MCE_TX_TUN_GTP_U,
	MCE_TX_TUN_GTP_C,
	MCE_TX_TUN_ESP,
	MCE_TX_TUN_UDP_ESP,
};
enum mce_tx_l3_type {
	MCE_TX_L3_IPV4 = 1,
	MCE_TX_L3_IPV6,
	MCE_TX_L3_ARP,
};
enum mce_tx_l4_type {
	MCE_TX_L4_FRAG = 1,
	MCE_TX_L4_UDP,
	MCE_TX_L4_TCP,
	MCE_TX_L4_SCTP,
	MCE_TX_L4_ICMP,
	MCE_TX_L4_ICMP6,
	MCE_TX_L4_PAY,
	MCE_TX_L4_PTPV1,
	MCE_TX_L4_PTPV2,
	MCE_TX_L4_ESP,
	MCE_TX_L4_802_3,
	MCE_TX_L4_WPI
};
enum mce_tx_vlan_strip {
	MCE_TX_INSERT_1VLAN = 1,
	MCE_TX_INSERT_2VLAN,
	MCE_TX_INSERT_3VLAN,
};
#pragma pack(push)
#pragma pack(1)

union mce_tx_desc {
	struct {
		__le64 pkt_addr; /* Packet buffer address */
		struct {
			__le16 length;
#define MCE_MAC_LEN_S (9)
			__le16 macip_len;
		} qword1;
		struct {
			__le16 in_macip_len;
			__le16 vlan0;
		} qword2;
		struct {
			uint16_t vlan1;
			uint16_t vlan2;
		} qword3;
		struct {
			union {
				uint16_t mss;
				uint16_t vfr;
			};
#define MCE_TX_TUN_LEN_S (8)
			uint16_t l4_tun_len;
		} qword4;
		struct {
/* get this packet if is a vlan */
#define MCE_TX_FD_PROGRAM RTE_BIT32(13)
#define MCE_TX_VLAN_TYPE  GENMASK_U32(12, 11)
			uint16_t mac_vlan_ctrl;
			uint8_t rev;
#define MCE_TX_I_L4_TYPE  GENMASK_U32(7, 4)
#define MCE_TX_I_L4_TYP_S (4)
#define MCE_TX_I_L3_TYPE  GENMASK_U32(1, 0)
			uint8_t in_l3l4_type;
		} qword5;
		struct {
#define MCE_TX_VLAN_INSET    GENMASK_U32(31, 30)
#define MCE_TX_VLAN_INSET_S  (30)
#define MCE_TX_O_VLAN_TYPE   GENMASK_U32(29, 27)
#define MCE_TX_O_VLAN_TYPE_S (27)
#define MCE_TX_VLAN_O_EN     RTE_BIT32(26)
#define MCE_TX_PTP_EN	     RTE_BIT32(25)
#define MCE_TX_TUN_TYPE	     GENMASK_U32(24, 22)
#define MCE_TX_TUN_TYPE_S    (22)
#define MCE_TX_CKSUM_OF	     GENMASK_U32(21, 16)
#define MCE_TX_I_L4_CK_EN    RTE_BIT32(21)
#define MCE_TX_I_L3_CK_EN    RTE_BIT32(20)
#define MCE_TX_O_L4_CK_EN    RTE_BIT32(19)
#define MCE_TX_O_L3_CK_EN    RTE_BIT32(18)
#define MCE_TX_O_L3_TYPE     GENMASK_U32(15, 14)
#define MCE_TX_O_L3_TYPE_S   (14)
#define MCE_TX_O_L4_TYPE     GENMASK_U32(13, 10)
#define MCE_TX_O_L4_TYPE_S   (10)
#define MCE_TX_TSO_EN	     RTE_BIT32(7)
			uint32_t cmd;
		} qword6;
	} d;
	struct {
		__le64 rsvd1;
		__le64 rsvd2;
		__le64 rsvd3;
		__le32 rsvd4;
		__le32 cmd;
	} wb;
};

#pragma pack(pop)

struct mce_tx_queue {
	const struct rte_memzone *rz; /* used for store ring base mem */
	uint64_t ring_phys_addr;
	volatile union mce_tx_desc *tx_bdr;
	struct mce_txsw_entry *sw_ring; /* Rx Software Ring Addr */
	struct mce_queue_attr attr;

	uint16_t tx_tail;
	uint16_t nb_tx_used;
	uint16_t next_to_use;
	uint16_t next_to_clean;
	uint16_t tx_free_thresh;
	uint16_t tx_free_trigger;
	uint16_t tx_rs_thresh;
	uint16_t tx_next_dd;
	uint16_t tx_next_rs;
	uint16_t last_desc_cleaned;
	uint8_t wthresh;
	uint8_t pthresh;
	uint8_t hthresh;

	struct rte_mbuf fake_mbuf; /**< dummy mbuf */

	void *tx_tailreg; /* HW Desc Tail Register */
	void *tx_headreg; /* HW Desc Head Register*/
	volatile uint32_t *hw_head;

	bool vlan3_insert_en;
	uint16_t vlan_id;

	uint16_t nb_tx_free;

	uint16_t offloads;
	bool tx_deferred_start;

	struct xstats stats;

	uint64_t mce_admin_dynflag;
	int mce_admin_dynfield_offset;
	pthread_mutex_t lock;

	struct rte_mbuf *free_mbuf[64];

	struct xstats rep_stats;
};

struct mce_repr_rxq {
	struct rte_ring *ring;
	struct xstats stats;
};

struct mce_repr_txq {
	struct rte_ring *ring;
	struct xstats stats;
};

#/**
 * @brief Receive packets from an RX queue into an array of mbuf pointers.
 *
 * @param rx_queue Pointer to the RX queue context.
 * @param rx_pkts Array to fill with received mbuf pointers.
 * @param nb_pkts Maximum number of packets to receive.
 *
 * @return Number of packets actually received.
 */
uint16_t mce_rx_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
			  uint16_t nb_pkts);

/**
 * @brief Transmit a burst of packets using a simple xmit routine.
 *
 * @param tx_queue Pointer to the TX queue context.
 * @param tx_pkts Array of mbuf pointers to transmit.
 * @param nb_pkts Number of packets to transmit.
 *
 * @return Number of packets actually transmitted.
 */
uint16_t mce_xmit_simple(void *tx_queue, struct rte_mbuf **tx_pkts,
			 uint16_t nb_pkts);

/**
 * @brief Prepare packets for transmission (descriptor population, offloads).
 *
 * @param tx_queue Pointer to the TX queue context.
 * @param tx_pkts Array of mbuf pointers to prepare.
 * @param nb_pkts Number of packets to prepare.
 *
 * @return Number of packets prepared.
 */
uint16_t mce_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
			   uint16_t nb_pkts);

/**
 * @brief Setup RX function pointers on the device (called at init).
 *
 * @param dev Pointer to the Ethernet device.
 */
void mce_setup_rx_function(struct rte_eth_dev *dev);

/**
 * @brief Setup TX function pointers on the device (called at init).
 *
 * @param dev Pointer to the Ethernet device.
 */
void mce_setup_tx_function(struct rte_eth_dev *dev);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
int mce_rx_burst_mode_get(struct rte_eth_dev *dev,
			  __rte_unused uint16_t queue_id,
			  struct rte_eth_burst_mode *mode);
int mce_tx_burst_mode_get(struct rte_eth_dev *dev,
			  __rte_unused uint16_t queue_id,
			  struct rte_eth_burst_mode *mode);
#endif
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
void mce_tx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			   struct rte_eth_txq_info *qinfo);
void mce_rx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			   struct rte_eth_rxq_info *qinfo);
#endif
struct mce_fdir_handle;
struct mce_fdir_fifo_commit;
struct mce_vport;
int mce_fdir_programming(struct mce_fdir_fifo_commit *commit);
int mce_fdir_tx_queue_start(struct rte_eth_dev *dev);
int mce_fdir_setup_txq(struct mce_vport *vport);
int mce_fdir_tx_queue_start(struct rte_eth_dev *dev);
int mce_fdir_tx_queue_stop(struct rte_eth_dev *dev);
int mce_enable_all_tx_queue(struct rte_eth_dev *dev);
int mce_enable_all_rx_queue(struct rte_eth_dev *dev);
int mce_disable_all_rx_queue(struct rte_eth_dev *dev);
int mce_disable_all_tx_queue(struct rte_eth_dev *dev);
void mce_rx_vec_cksum_db_init(struct rte_eth_dev *dev);
#endif /* _MCE_RXTX_H_ */
