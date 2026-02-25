#include <assert.h>
#include <string.h>

#include <rte_string_fns.h>
#include <rte_malloc.h>
#include <rte_cpuflags.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_net.h>
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
#include <rte_vxlan.h>
#endif
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
#include <rte_geneve.h>
#endif
#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
#include <rte_mpls.h>
#endif
#if RTE_VERSION_NUM(19, 8, 0, 0) < RTE_VERSION
#include <rte_gre.h>
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
#include <rte_gtp.h>
#endif
#include <rte_vect.h>
#include <rte_hexdump.h>

#include "base/mce_dma_regs.h"
#include "base/mce_hw.h"
#include "base/mce_ptype.h"
#include "mce.h"
#include "mce_logs.h"
#include "mce_rxtx.h"
#include "mce_rxtx_vec.h"

#ifdef MCE_DEBUG_PCAP
#include <rte_pcapng.h>
extern rte_pcapng_t *n20_pcapng_fd;
extern struct rte_mempool *n20_pkt_mp;
#endif
#define CACHE_FETCH_RX (4)
static uint16_t mce_scattered_rx(void *rx_queue, struct rte_mbuf **rx_pkts,
				 uint16_t nb_pkts);
static uint16_t mce_tx_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
				 uint16_t nb_pkts);
/**
 * @brief Allocate mbufs for all entries in an RX queue and populate descriptors.
 *
 * @param rxq Pointer to the RX queue structure.
 *
 * @return 0 on success, -ENOMEM on allocation failure.
 */
static int mce_alloc_rx_mbuf(struct mce_rx_queue *rxq)
{
	struct mce_rxsw_entry *rx_swbd = rxq->sw_ring;
	volatile union mce_rx_desc *rxd;
	struct rte_mbuf *mbuf = NULL;
	uint64_t dma_addr;
	uint16_t i = 0;

	for (i = 0; i < rxq->attr.nb_desc; i++) {
		mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);

		if (!mbuf)
			return -ENOMEM;
		rte_mbuf_refcnt_set(mbuf, 1);
		mbuf->next = NULL;
		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova(mbuf));
		rxd = &rxq->rx_bdr[i];
		rxd->d.pkt_addr = dma_addr;
		rxd->d.rsvd3 = 0;
		mbuf->port = rxq->attr.rte_pid;
		rx_swbd[i].mbuf = mbuf;
	}

	memset(&rxq->fake_mbuf, 0x0, sizeof(rxq->fake_mbuf));
	for (i = 0; i < MCE_RX_MAX_BURST_SIZE; ++i)
		rxq->sw_ring[rxq->attr.nb_desc + i].mbuf = &rxq->fake_mbuf;

	return 0;
}

/**
 * @brief Start an RX queue: allocate mbufs, initialize ring and enable HW.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id RX queue index to start.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_rx_queue_start(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_rx_queue *rxq;
	uint16_t dma_idx;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	rxq = dev->data->rx_queues[queue_id];
	if (!rxq) {
		PMD_DRV_LOG(ERR, "RX queue %u is Null or Not setup\n",
			    queue_id);
		return -EINVAL;
	}
	if (dev->data->rx_queue_state[queue_id] ==
	    RTE_ETH_QUEUE_STATE_STOPPED) {
		/* disable ring */
		dma_idx = rxq->attr.index;
		modify32(hw, MCE_DMA_RXQ_START(dma_idx), MCE_RXQ_START_EN, false);
		if (mce_alloc_rx_mbuf(rxq) != 0) {
			PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
				     queue_id);
			return -ENOMEM;
		}
		rxq->nb_rx_free = rxq->attr.nb_desc - 1;
		MCE_REG_ADDR_WRITE(rxq->rx_tailreg, 0, rxq->attr.nb_desc_mask);
		dev->data->rx_queue_state[queue_id] =
			RTE_ETH_QUEUE_STATE_STARTED;
		modify32(hw, MCE_DMA_RXQ_START(dma_idx), MCE_RXQ_START_EN, true);
	}
#else
	if (queue_id < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[queue_id];
		if (!rxq)
			return -EINVAL;
		/* enable ring */
		dma_idx = rxq->attr.index;
		modify32(hw, MCE_DMA_RXQ_START(dma_idx), MCE_RXQ_START_EN, false);
		if (mce_alloc_rx_mbuf(rxq) != 0) {
			PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
				     queue_id);
			return -ENOMEM;
		}
		rxq->nb_rx_free = rxq->attr.nb_desc - 1;
		MCE_REG_ADDR_WRITE(rxq->rx_tailreg, 0, rxq->attr.nb_desc_mask);
		modify32(hw, MCE_DMA_RXQ_START(dma_idx), MCE_RXQ_START_EN, true);
	} else {
		return -1;
	}
#endif
	return 0;
}

/**
 * @brief Release and free all mbufs associated with an RX queue software ring.
 *
 * @param rxq Pointer to the RX queue whose mbufs should be freed.
 */
static void mce_rx_queue_release_mbuf(struct mce_rx_queue *rxq)
{
	unsigned int mask = 0;
	unsigned int i = 0;

	if (!rxq || !rxq->sw_ring)
		return;
	if (unlikely(rxq->attr.nb_desc == 0))
		return;
	mask = rxq->attr.nb_desc_mask;
	if (unlikely(!rxq->sw_ring)) {
		PMD_DRV_LOG(DEBUG, "sw_ring is NULL");
		return;
	}
	if (rxq->rxrearm_nb >= rxq->attr.nb_desc)
		return;
	/* free all mbufs that are valid in the ring */
	if (rxq->rxrearm_nb == 0) {
		for (i = 0; i < rxq->attr.nb_desc; i++) {
			if (rxq->sw_ring[i].mbuf)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	} else {
		for (i = rxq->rx_tail;
				i != rxq->rxrearm_start;
				i = (i + 1) & mask) {
			if (rxq->sw_ring[i].mbuf)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	}
	rxq->rxrearm_nb = rxq->attr.nb_desc;
	/* set all entries to NULL */
	memset(rxq->sw_ring, 0, sizeof(rxq->sw_ring[0]) * rxq->attr.nb_desc);
}

/**
 * @brief Reset RX queue software state (pointers, counters, fake mbufs).
 *
 * @param rxq Pointer to the RX queue to reset.
 */
static void mce_rx_queue_sw_reset(struct mce_rx_queue *rxq)
{
	int i = 0;

	rxq->rx_free_trigger = (uint16_t)(rxq->rx_free_thresh - 1);
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;
	rxq->rx_tail = 0;
	rxq->nb_rx_free = 0;

	rxq->rxrearm_start = 0;
	rxq->rxrearm_nb = 0;

	for (i = 0; i < MCE_RX_MAX_BURST_SIZE; ++i)
		rxq->sw_ring[rxq->attr.nb_desc + i].mbuf = &rxq->fake_mbuf;
}

/**
 * @brief Stop an RX queue and release associated resources.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id RX queue index to stop.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_rx_queue_stop(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_rx_queue *rxq;
	uint16_t index = 0;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	if (queue_id < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[queue_id];
		if (!rxq) {
			PMD_DRV_LOG(ERR, "RX queue %u is Null or Not setup\n",
				    queue_id);
			return -EINVAL;
		}
		index = rxq->attr.index;
		if (dev->data->rx_queue_state[queue_id] ==
		    RTE_ETH_QUEUE_STATE_STARTED) {
			modify32(hw, MCE_DMA_RXQ_START(index), MCE_RXQ_START_EN, false);
			MCE_E_REG_WRITE(hw, MCE_DMA_RXQ_TAIL(index), 0);
			mce_rx_queue_release_mbuf(rxq);
			mce_rx_queue_sw_reset(rxq);
			dev->data->rx_queue_state[queue_id] =
				RTE_ETH_QUEUE_STATE_STOPPED;
		}
	} else {
		return -1;
	}
#else
	if (queue_id < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[queue_id];
		if (!rxq) {
			PMD_DRV_LOG(ERR, "RX queue %u is Null or Not setup",
				    queue_id);
			return -EINVAL;
		}
		index = rxq->attr.index;
		modify32(hw, MCE_DMA_RXQ_START(index), MCE_RXQ_START_EN, false);
		mce_rx_queue_release_mbuf(rxq);
		mce_rx_queue_sw_reset(rxq);
	} else {
		return -1;
	}
#endif

	return 0;
}

/**
 * @brief Start a TX queue and enable it in hardware.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id TX queue index to start.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_tx_queue_start(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_tx_queue *txq;
	uint32_t dma_index;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	txq = dev->data->tx_queues[queue_id];
	if (!txq) {
		PMD_INIT_LOG(ERR,
			     "Can't start Tx Queue %d it's not Setup By "
			     "tx_queue_setup API\n",
			     queue_id);
		return -EINVAL;
	}
	if (dev->data->tx_queue_state[queue_id] ==
	    RTE_ETH_QUEUE_STATE_STOPPED) {
		dev->data->tx_queue_state[queue_id] =
			RTE_ETH_QUEUE_STATE_STARTED;
		dma_index = txq->attr.index;
		/* Enable Tx Queue */
		modify32(hw, MCE_DMA_TXQ_START(dma_index), MCE_TXQ_START_EN, true);
	}
#else
	if (queue_id < dev->data->nb_tx_queues) {
		txq = dev->data->tx_queues[queue_id];
		if (!txq) {
			PMD_INIT_LOG(ERR,
				     "Can't start Tx Queue %d "
				     "it's not Setup By tx_queue_setup API\n",
				     queue_id);
			return -EINVAL;
		}
		dma_index = txq->attr.index;
		/* Enable Tx Queue */
		modify32(hw, MCE_DMA_TXQ_START(dma_index), MCE_TXQ_START_EN, true);
	} else {
		return -EINVAL;
	}
#endif
	return 0;
}

/**
 * @brief Release and free all mbufs associated with a TX queue software ring.
 *
 * @param txq Pointer to the TX queue whose mbufs should be freed.
 */
static void mce_tx_queue_release_mbuf(struct mce_tx_queue *txq)
{
	union mce_tx_desc zero_bd;
	uint16_t i;

	memset(&zero_bd, 0, sizeof(zero_bd));
	if (!txq)
		return;

	if (txq->sw_ring)
		for (i = 0; i < txq->attr.nb_desc; i++) {
			if (txq->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
				txq->tx_bdr[i] = zero_bd;
			}
		}
}

/**
 * @brief Reset TX queue software state (indices, counters, stats).
 *
 * @param txq Pointer to the TX queue to reset.
 */
static void mce_tx_queue_sw_reset(struct mce_tx_queue *txq)
{
	txq->nb_tx_free = txq->attr.nb_desc - 1;
	txq->nb_tx_used = 0;
	txq->tx_free_trigger = txq->tx_free_thresh + 1;
	txq->tx_next_dd = txq->tx_rs_thresh - 1;
	txq->tx_next_rs = txq->tx_rs_thresh - 1;
	txq->last_desc_cleaned = (uint16_t)(txq->attr.nb_desc - 1);
	txq->tx_tail = 0;
	memset(&txq->stats, 0, sizeof(txq->stats));
}

/**
 * @brief Stop a TX queue and release associated resources.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id TX queue index to stop.
 *
 * @return 0 on success, negative errno on failure.
 */
int mce_tx_queue_stop(struct rte_eth_dev *dev, uint16_t queue_id)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_tx_queue *txq;
	uint16_t index = 0;

	PMD_INIT_FUNC_TRACE();

#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
	txq = dev->data->tx_queues[queue_id];
	if (!txq) {
		PMD_DRV_LOG(ERR, "TX queue %u is Null or Not setup\n",
			    queue_id);
		return -EINVAL;
	}
	if (dev->data->tx_queue_state[queue_id] ==
	    RTE_ETH_QUEUE_STATE_STARTED) {
		index = txq->attr.index;
		modify32(hw, MCE_DMA_TXQ_START(index), MCE_TXQ_START_EN, false);
		MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_TAIL(index), 0);
		mce_tx_queue_sw_reset(txq);
		mce_tx_queue_release_mbuf(txq);
		dev->data->tx_queue_state[queue_id] =
			RTE_ETH_QUEUE_STATE_STOPPED;
	}
#else
	if (queue_id < dev->data->nb_tx_queues) {
		txq = dev->data->tx_queues[queue_id];
		if (!txq) {
			PMD_DRV_LOG(ERR, "TX queue %u is Null or Not setup",
				    queue_id);
			return -EINVAL;
		}
		index = txq->attr.index;
		modify32(hw, MCE_DMA_TXQ_START(index), MCE_TXQ_START_EN, false);
		mce_tx_queue_sw_reset(txq);
		mce_tx_queue_release_mbuf(txq);
	} else {
		return -1;
	}
#endif
	return 0;
}

/**
 * @brief Release and free an RX queue object and its backing memory.
 *
 * This frees mbufs, software rings and memzones associated with the RX queue.
 *
 * @param _rxq Pointer to the RX queue object to release.
 */
void mce_rx_queue_release(void *_rxq)
{
	struct mce_rx_queue *rxq = _rxq;

	PMD_INIT_FUNC_TRACE();

	if (rxq) {
		mce_rx_queue_release_mbuf(rxq);
		if (rxq->rz)
			rte_memzone_free(rxq->rz);
		if (rxq->sw_ring)
			rte_free(rxq->sw_ring);
		rte_free(rxq);
	}
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
/**
 * @brief Wrapper helper to release an RX queue referenced by an ethernet device.
 *
 * @param dev Pointer to the Ethernet device.
 * @param queue_id RX queue index to release.
 */
void mce_dev_rx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	mce_rx_queue_release(dev->data->rx_queues[queue_id]);
}
#endif

static inline void mce_rxq_prepare_setup(struct mce_hw *hw,
					 struct mce_rx_queue *rxq)
{
	uint16_t index = rxq->attr.index;

	modify32(hw, MCE_DMA_RXQ_START(index), MCE_RXQ_START_EN, false);
}

static int mce_rx_queue_reset(struct rte_eth_dev *dev, struct mce_hw *hw,
			      struct mce_rx_queue *rxq)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(hw);
	RTE_SET_USED(rxq);

	return 0;
}

static int mce_alloc_rxq_mem(struct rte_eth_dev *dev, struct mce_rx_queue *rxq,
			     uint16_t nb_rx_desc, int socket_id)
{
	uint32_t size = 0;
	const struct rte_memzone *rz = NULL;

	size = (nb_rx_desc + 32) * sizeof(struct mce_rxsw_entry);
	rxq->sw_ring = rte_zmalloc_socket("rx_swring", size,
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq->sw_ring == NULL)
		return -ENOMEM;
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", rxq->attr.queue_id,
				      MCE_RX_MAX_RING_SZ, MCE_BD_RING_ALIGN,
				      socket_id);
#else
	rz = ring_dma_zone_reserve(dev, "rx_ring", rxq->attr.queue_id,
				   MCE_RX_MAX_RING_SZ, socket_id);
#endif
	if (rz == NULL) {
		rte_free(rxq->sw_ring);
		rxq->sw_ring = NULL;
		return -ENOMEM;
	}
	rxq->rz = rz;
	memset(rz->addr, 0, MCE_RX_MAX_RING_SZ);
	rxq->rx_bdr = (union mce_rx_desc *)rz->addr;
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#ifndef RTE_LIBRTE_XEN_DOM0
	rxq->ring_phys_addr = (uint64_t)rz->phys_addr;
#else
	rxq->ring_phys_addr = rte_mem_phy2mch((rz)->memseg_id, (rz)->phys_addr);
#endif
#else
	rxq->ring_phys_addr = rz->iova;
#endif
	rxq->rx_tail = 0;

	return 0;
}

static void mce_setup_rxbdr(struct rte_eth_dev *dev, struct mce_hw *hw,
			    struct mce_rx_queue *rxq,
			    struct rte_mempool *mb_pool)
{
	uint16_t max_desc = rxq->attr.nb_desc;
	uint16_t idx = rxq->attr.index;
	phys_addr_t bd_address;
	uint32_t dmah, dmal;

	mce_rxq_prepare_setup(hw, rxq);
	bd_address = (phys_addr_t)rxq->ring_phys_addr;
	dmah = upper_32_bits((uint64_t)bd_address);
	dmal = lower_32_bits((uint64_t)bd_address);
	MCE_E_REG_WRITE(hw, MCE_DMA_RXQ_BASE_ADDR_LO(idx), dmal);
	MCE_E_REG_WRITE(hw, MCE_DMA_RXQ_BASE_ADDR_HI(idx), dmah);
	MCE_E_REG_WRITE(hw, MCE_DMA_RXQ_LEN(idx), max_desc);
	rxq->mb_pool = mb_pool;
	rxq->rx_tailreg =
		(uint32_t *)(((u8 *)hw->nic_base) + MCE_DMA_RXQ_TAIL(idx));
	rxq->rx_headreg =
		(uint32_t *)(((u8 *)hw->nic_base) + MCE_DMA_RXQ_HEAD(idx));
	rxq->rx_tail = MCE_E_REG_READ(hw, MCE_DMA_RXQ_HEAD(idx));
	if (rxq->rx_tail)
		mce_rx_queue_reset(dev, hw, rxq);
	MCE_E_REG_WRITE(hw, MCE_DMA_RXQ_DESC_FETCH_CTRL(idx),
			(MCE_RX_DEFAULT_BURST << 16) |
				MCE_RX_DESC_HIGH_WATER_TH);
	MCE_E_REG_WRITE(hw, MCE_DMA_RXQ_DROP_TIMEOUT_TH(idx), 0);
}

static inline int mce_rxq_vec_setup_default(struct mce_rx_queue *rxq)
{
	struct rte_mbuf mb_def = { .buf_addr = 0 }; /* zeroed mbuf */
	uintptr_t p;

	mb_def.nb_segs = 1;
	mb_def.data_off = RTE_PKTMBUF_HEADROOM;
	mb_def.port = rxq->attr.rte_pid;
	rte_mbuf_refcnt_set(&mb_def, 1);

	/* prevent compiler reordering: rearm_data covers previous fields */
	rte_compiler_barrier();
	p = (uintptr_t)&mb_def.rearm_data;
	rxq->mbuf_initializer = *(uint64_t *)p;

	return 0;
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
#define RTE_MBUF_DYNFIELD_SPORT_NAME   "rte_dynfield_sport"
#define RTE_MBUF_DYNFIELD_ADMIN_NAME   "rte_dynfield_admin"
#define RTE_MBUF_DYNFLAG_RX_SPORT_NAME "rte_dynflag_rx_sport"
#define RTE_MBUF_DYNFLAG_TX_ADMIN_NAME "rte_dynflag_tx_admin"

static int mce_mbuf_dyn_sport_register(int *field_offset, uint64_t *flag,
				       const char *direction __rte_unused,
				       const char *flag_name)
{
	static const struct rte_mbuf_dynfield field_desc = {
		.name = RTE_MBUF_DYNFIELD_SPORT_NAME,
		.size = sizeof(uint16_t),
		.align = __alignof__(uint16_t),
	};
	struct rte_mbuf_dynflag flag_desc = {};
	int offset;

	offset = rte_mbuf_dynfield_register(&field_desc);
	if (offset < 0) {
		return -1;
	}
	if (field_offset != NULL)
		*field_offset = offset;

	strlcpy(flag_desc.name, flag_name, sizeof(flag_desc.name));
	offset = rte_mbuf_dynflag_register(&flag_desc);
	if (offset < 0) {
		return -1;
	}
	if (flag != NULL)
		*flag = RTE_BIT64(offset);

	return 0;
}

static int mce_mbuf_dyn_admin_register(int *field_offset, uint64_t *flag,
				       const char *direction __rte_unused,
				       const char *flag_name)
{
	static const struct rte_mbuf_dynfield field_desc = {
		.name = RTE_MBUF_DYNFIELD_ADMIN_NAME,
		.size = sizeof(uint16_t),
		.align = __alignof__(uint16_t),
	};
	struct rte_mbuf_dynflag flag_desc = {};
	int offset;

	offset = rte_mbuf_dynfield_register(&field_desc);
	if (offset < 0)
		return -1;

	if (field_offset != NULL)
		*field_offset = offset;

	strlcpy(flag_desc.name, flag_name, sizeof(flag_desc.name));
	offset = rte_mbuf_dynflag_register(&flag_desc);
	if (offset < 0)
		return -1;

	if (flag != NULL)
		*flag = RTE_BIT64(offset);

	return 0;
}
#endif

int mce_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
		       uint16_t nb_desc, unsigned int socket_id,
		       const struct rte_eth_rxconf *rx_conf,
		       struct rte_mempool *mp)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct rte_eth_dev_data *data = dev->data;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_rx_queue *rxq;
	uint16_t rx_buf_len = 0;
	uint64_t offloads;
	int err = 0;

	PMD_DRV_LOG(INFO, "RXQ[%d] setup nb-desc %d\n", queue_id, nb_desc);

	if (rte_is_power_of_2(nb_desc) == 0) {
		PMD_DRV_LOG(ERR, "Rxq Desc Num Must power of 2\n");
		return -EINVAL;
	}

	if (nb_desc > MCE_MAX_RX_BD)
		return -1;

	/* Check Whether Queue Has Been Create If So Release it */
	if (queue_id < dev->data->nb_tx_queues &&
	    dev->data->rx_queues[queue_id] != NULL) {
		mce_rx_queue_release(dev->data->rx_queues[queue_id]);
		dev->data->rx_queues[queue_id] = NULL;
	}
	rxq = (struct mce_rx_queue *)rte_zmalloc_socket(
		"mce_rxq", sizeof(struct mce_rx_queue), RTE_CACHE_LINE_SIZE,
		socket_id);
	if (rxq == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate RX ring memory");
		return -ENOMEM;
	}
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	offloads = rx_conf->offloads | dev->data->dev_conf.rxmode.offloads;
	if ((offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM) == RTE_ETH_RX_OFFLOAD_CHECKSUM)
		offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
			    RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
			    RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
			    RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
			    RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
			    RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM;
#else
	if (dev->data->dev_conf.rxmode.hw_ip_checksum)
		offloads = RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
			   RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
			   RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
			   RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
			   RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
			   RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM;
#endif
	rxq->attr.index = queue_id + vport->attr.qpair_base;
	rxq->attr.nb_desc = nb_desc;
	rxq->attr.nb_desc_mask = nb_desc - 1;
	rxq->attr.queue_id = queue_id;
	rxq->attr.lane_id = vport->attr.nr_port;
	rxq->attr.rte_pid = data->port_id;

	rxq->rx_offload_capa = offloads;
	rxq->rx_buf_len = (uint16_t)(rte_pktmbuf_data_room_size(mp) -
				     RTE_PKTMBUF_HEADROOM);
	err = mce_alloc_rxq_mem(dev, rxq, nb_desc, socket_id);
	if (err)
		goto fail;
	PMD_DRV_LOG(INFO,
		    "PF[%d] dev:[%d] hw-lane[%d] rx_qid[%d] "
		    "dma_idx %d socket %d\n",
		    0, rxq->attr.rte_pid, rxq->attr.lane_id, queue_id,
		    rxq->attr.index, socket_id);
	rxq->rx_free_thresh = (rx_conf->rx_free_thresh) ?
				      rx_conf->rx_free_thresh :
				      MCE_DEFAULT_RX_FREE_THRESH;
	rxq->rx_free_trigger = rxq->rx_free_thresh - 1;
	rxq->wthresh = rx_conf->rx_thresh.wthresh;
	rxq->pthresh = rx_conf->rx_thresh.pthresh;
	rxq->hthresh = rx_conf->rx_thresh.hthresh;
	mce_setup_rxbdr(dev, hw, rxq, mp);
	if (!rxq->rx_tail)
		rxq->nb_rx_free = rxq->attr.nb_desc_mask;
	else if (rxq->rx_tail == rxq->attr.nb_desc_mask)
		rxq->nb_rx_free = rxq->rx_tail;
	else
		rxq->nb_rx_free = nb_desc - 1;
	if (rxq->rx_buf_len % 64 == 0)
		rx_buf_len = rxq->rx_buf_len;
	else
		rx_buf_len = ((rxq->rx_buf_len / 64) + 1) * 64;
	MCE_E_REG_WRITE(hw, MCE_DMA_RXQ_SCATTER_BD_LEN(rxq->attr.index),
			(rx_buf_len) / MCE_SCATTER_PER_BIT_LEN);
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;
	rxq->mb_pool = mp;
	data->rx_queues[queue_id] = rxq;
	mce_rxq_vec_setup_default(rxq);
	if (hw->pf_rxfcs_en)
		rxq->strip_len = RTE_ETHER_CRC_LEN;
	else
		rxq->strip_len = 0;
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	rxq->mce_sport_dynfield_offset = -1;
	if (!vport->is_vf) {
		struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
		int ret = 0;

		if (pf->nr_repr_ports) {
			ret = mce_mbuf_dyn_sport_register(
				&rxq->mce_sport_dynfield_offset,
				&rxq->mce_sport_rx_dynflag, "rx",
				RTE_MBUF_DYNFLAG_RX_SPORT_NAME);
			if (ret < 0) {
				printf("sport dyn register failed is failed "
				       "%d\n",
				       ret);
				return ret;
			}
		}
	}
#endif
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	if (rxq->ts_flag == 0 && (rxq->rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
		/* Register mbuf field and flag for Rx timestamp */
		err = rte_mbuf_dyn_rx_timestamp_register(
				&rxq->ts_offset,
				&rxq->ts_flag);
		if (err) {
			PMD_DRV_LOG(ERR,
					"Cannot register mbuf field/flag for timestamp");
			return -EINVAL;
		}
	}
#endif /* RTE_VERSION > 20.11 */

	return 0;
fail:
	return -ENOMEM;
}

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
void mce_rx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			   struct rte_eth_rxq_info *qinfo)
{
	struct mce_rx_queue *rxq;

	rxq = dev->data->rx_queues[queue_id];
	if (!rxq)
		return;
	qinfo->mp = rxq->mb_pool;
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
	qinfo->rx_buf_size = rxq->rx_buf_len;
#endif
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = rxq->attr.nb_desc;
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
	qinfo->queue_state = dev->data->rx_queue_state[queue_id];
#endif
	qinfo->conf.rx_free_thresh = rxq->rx_free_thresh;
	qinfo->conf.rx_thresh.pthresh = MCE_RX_DESC_HIGH_WATER_TH;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	qinfo->conf.offloads = rxq->rx_offload_capa;
#endif
}

void mce_tx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			   struct rte_eth_txq_info *qinfo)
{
	struct mce_tx_queue *txq;

	txq = dev->data->tx_queues[queue_id];
	if (!txq)
		return;

	qinfo->nb_desc = txq->attr.nb_desc;
#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
	qinfo->queue_state = dev->data->tx_queue_state[queue_id];
#endif
	qinfo->conf.tx_free_thresh = txq->tx_free_thresh;
	qinfo->conf.tx_thresh.pthresh = MCE_TX_DESC_HIGH_WATER_TH;
	qinfo->conf.tx_rs_thresh = txq->tx_rs_thresh;
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
	qinfo->conf.txq_flags = txq->offloads;
#else
	qinfo->conf.offloads = txq->offloads;
#endif
}
#endif /* RTE_VERSION > 2.2.0 */

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
int mce_dev_rx_descriptor_done(void *rx_queue, uint16_t offset)
{
	struct mce_rx_queue *rxq = rx_queue;
	volatile union mce_rx_desc *rxbd;
	uint32_t rx_id;

	if (unlikely(offset >= rxq->attr.nb_desc))
		return 0;

	rx_id = (rxq->rx_tail + offset) & rxq->attr.nb_desc;
	rxbd = &rxq->rx_bdr[rx_id];

	return !!(rxbd->wb.cmd & MCE_CMD_DD);
}
#endif
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
uint32_t mce_dev_rx_queue_count(void *rx_queue)
{
	volatile union mce_rx_desc *rxbd;
	struct mce_rx_queue *rxq;
	uint16_t rx_count = 0;
	uint16_t rx_id;

	rxq = rx_queue;
	rxbd = &rxq->rx_bdr[rxq->rx_tail];

	while (rx_count < rxq->attr.nb_desc && (rxbd->wb.cmd & MCE_RX_DD)) {
		rx_count++;

		rx_id = (rxq->rx_tail + 1) & rxq->attr.nb_desc_mask;
		rxbd = &rxq->rx_bdr[rx_id];
	}

	return rx_count;
}
#else
uint32_t mce_dev_rx_queue_count(struct rte_eth_dev *dev, uint16_t q_id)
{
	volatile union mce_rx_desc *rxbd;
	struct mce_rx_queue *rxq;
	uint16_t rx_count = 0;
	uint16_t rx_id;

	rxq = dev->data->rx_queues[q_id];
	rxbd = &rxq->rx_bdr[rxq->rx_tail];

	while (rx_count < rxq->attr.nb_desc && (rxbd->wb.cmd & MCE_RX_DD)) {
		rx_count++;

		rx_id = (rxq->rx_tail + 1) & rxq->attr.nb_desc_mask;
		rxbd = &rxq->rx_bdr[rx_id];
	}

	return rx_count;
}
#endif

#if RTE_VERSION_NUM(17, 5, 0, 0) <= RTE_VERSION
int mce_dev_rx_descriptor_status(void *rx_queue, uint16_t offset)
{
	struct mce_rx_queue *rxq = rx_queue;
	volatile union mce_rx_desc *rxbd;
	uint16_t rx_id;

	if (unlikely(offset >= rxq->attr.nb_desc))
		return 0;

	if (offset >= rxq->rx_tail)
		return RTE_ETH_RX_DESC_UNAVAIL;

	rx_id = (rxq->rx_tail + offset) & rxq->attr.nb_desc_mask;
	rxbd = &rxq->rx_bdr[rx_id];
	if (rxbd->wb.cmd & MCE_CMD_DD)
		return RTE_ETH_RX_DESC_DONE;

	return RTE_ETH_RX_DESC_AVAIL;
}

int mce_dev_tx_descriptor_status(void *tx_queue, uint16_t offset)
{
	struct mce_tx_queue *txq = tx_queue;
	volatile union mce_tx_desc *txbd;
	uint16_t tx_id;

	if (unlikely(offset >= txq->attr.nb_desc))
		return -EINVAL;

	if (offset >= txq->tx_tail)
		return RTE_ETH_TX_DESC_UNAVAIL;

	tx_id = (txq->tx_tail + offset) & txq->attr.nb_desc_mask;
	txbd = &txq->tx_bdr[tx_id];

	if (txbd->d.qword6.cmd & MCE_CMD_DD)
		return RTE_ETH_TX_DESC_DONE;

	return RTE_ETH_TX_DESC_FULL;
}
#endif

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static const struct {
	eth_rx_burst_t pkt_burst;
	const char *info;
} mce_rx_burst_infos[] = {
	{ mce_scattered_rx, "Scalar Scattered" },
	{ mce_rx_recv_pkts, "Scalar Simple" },
#ifdef RTE_ARCH_X86
	{ mce_recv_pkts_vec, "Vector SSE" },
	{ mce_recv_scattered_pkts_vec, "Vector Rx Scatter SSE" },
#if 0
	{ mce_recv_pkts_vec_avx2, "Vector AVX2" },
	{ mce_recv_scattered_pkts_vec_avx2, "Vector Rx Scatter AVX2" },
#endif
#else
	{ mce_recv_pkts_vec, "Vector NEON" },
	{ mce_recv_scattered_pkts_vec, "Vector Rx Scatter NEON" },
#endif
};

int mce_rx_burst_mode_get(struct rte_eth_dev *dev,
			  __rte_unused uint16_t queue_id,
			  struct rte_eth_burst_mode *mode)
{
	eth_rx_burst_t pkt_burst = dev->rx_pkt_burst;
	int ret = -EINVAL;
	unsigned int i;

	for (i = 0; i < RTE_DIM(mce_rx_burst_infos); ++i) {
		if (pkt_burst == mce_rx_burst_infos[i].pkt_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
				 mce_rx_burst_infos[i].info);
			ret = 0;
			break;
		}
	}

	return ret;
}
#endif

#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
static const struct {
	eth_tx_burst_t pkt_burst;
	const char *info;
} mce_tx_burst_infos[] = {
	{ mce_xmit_simple, "Scalar Simple" },
	{ mce_tx_xmit_pkts, "Scalar" },
	{ mce_xmit_pkts_vec, "vector SSE" },
};

int mce_tx_burst_mode_get(struct rte_eth_dev *dev,
			  __rte_unused uint16_t queue_id,
			  struct rte_eth_burst_mode *mode)
{
	eth_tx_burst_t pkt_burst = dev->tx_pkt_burst;
	int ret = -EINVAL;
	unsigned int i;

	for (i = 0; i < RTE_DIM(mce_tx_burst_infos); ++i) {
		if (pkt_burst == mce_tx_burst_infos[i].pkt_burst) {
			snprintf(mode->info, sizeof(mode->info), "%s",
				 mce_tx_burst_infos[i].info);
			ret = 0;
			break;
		}
	}

	return ret;
}
#endif

void __rte_unused mce_tx_queue_release(void *_txq)
{
	struct mce_tx_queue *txq = _txq;

	PMD_INIT_FUNC_TRACE();

	if (txq) {
		mce_tx_queue_release_mbuf(txq);
		if (txq->sw_ring)
			rte_free(txq->sw_ring);
		rte_free(txq);
	}
}

static int mce_alloc_tx_mem(struct rte_eth_dev *dev, struct mce_tx_queue *txq,
			    uint16_t nb_tx_desc, int socket_id)
{
	const struct rte_memzone *rz = NULL;
	uint32_t size = 0;

	size = nb_tx_desc * sizeof(struct mce_txsw_entry);
	txq->sw_ring = rte_zmalloc_socket("tx_swring", size,
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (txq->sw_ring == NULL)
		return -ENOMEM;
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
	rz = rte_eth_dma_zone_reserve(dev, "tx_ring", txq->attr.queue_id,
				      MCE_RX_MAX_RING_SZ, MCE_BD_RING_ALIGN,
				      socket_id);
#else
	rz = ring_dma_zone_reserve(dev, "tx_ring", txq->attr.queue_id,
				   MCE_TX_MAX_RING_SZ, socket_id);
#endif
	if (rz == NULL) {
		rte_free(txq->sw_ring);
		txq->sw_ring = NULL;
		return -ENOMEM;
	}
	txq->rz = rz;
	memset(rz->addr, 0, MCE_TX_MAX_RING_SZ);
	txq->tx_bdr = (union mce_tx_desc *)rz->addr;
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#ifndef RTE_LIBRTE_XEN_DOM0
	txq->ring_phys_addr = (uint64_t)rz->phys_addr;
#else
	txq->ring_phys_addr = rte_mem_phy2mch((rz)->memseg_id, (rz)->phys_addr);
#endif
#else
	txq->ring_phys_addr = rz->iova;
#endif
	txq->tx_tail = 0;

	return 0;
}

static void mce_setup_txbdr(struct mce_hw *hw, struct mce_tx_queue *txq)
{
	uint16_t max_desc = txq->attr.nb_desc;
	uint16_t idx = txq->attr.index;
	phys_addr_t bd_address;
	uint32_t dmah, dmal;
	int v;

	bd_address = (phys_addr_t)txq->ring_phys_addr;
	dmah = upper_32_bits((uint64_t)bd_address);
	dmal = lower_32_bits((uint64_t)bd_address);
	modify32(hw, MCE_DMA_TXQ_START(idx), MCE_TXQ_START_EN, false);
	MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_BASE_ADDR_LO(idx), dmal);
	MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_BASE_ADDR_HI(idx), dmah);
	MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_DESC_FETCH_CTRL(idx),
			(MCE_TX_DEFAULT_BURST << 16) |
				MCE_TX_DESC_HIGH_WATER_TH);
	MCE_E_REG_WRITE(hw, MCE_DMA_INT_MASK(idx),
			MCE_TX_INT_MASK | MCE_RX_INT_MASK | RTE_BIT32(16) |
				RTE_BIT32(17));
	txq->tx_headreg =
		(void *)((char *)hw->nic_base + MCE_DMA_TXQ_HEAD(idx));
	txq->tx_tailreg =
		(void *)((char *)hw->nic_base + MCE_DMA_TXQ_TAIL(idx));
	txq->hw_head = (volatile uint32_t *)&txq->tx_bdr[txq->attr.nb_desc];
	v = MCE_E_REG_READ(hw, MCE_DMA_TXQ_HEAD(idx));
	if (v) {
		assert(0);
		v = txq->next_to_use;
	}
	MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_LEN(idx), max_desc);
	MCE_E_REG_WRITE(hw, MCE_DMA_TXQ_TAIL(idx), v);

	txq->tx_tail = MCE_E_REG_READ(hw, MCE_DMA_TXQ_HEAD(idx));
}

int mce_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_id,
		       uint16_t nb_desc, unsigned int socket_id,
		       const struct rte_eth_txconf *tx_conf)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	struct rte_eth_txmode *txmode = &dev->data->dev_conf.txmode;
#endif
	struct rte_eth_dev_data *data = dev->data;
	struct mce_txsw_entry *sw_ring;
	struct mce_tx_queue *txq;
	int i = 0, prev = 0;
	int err = 0;

	PMD_INIT_FUNC_TRACE();
	PMD_DRV_LOG(INFO, "TXQ[%d] setup nb-desc %d\n", queue_id, nb_desc);
	if (rte_is_power_of_2(nb_desc) == 0) {
		PMD_DRV_LOG(ERR, "Txq Desc Num Must power of 2\n");
		return -EINVAL;
	}

	/* Check Whether Queue Has Been Create If So Release it */
	if (queue_id < dev->data->nb_tx_queues &&
	    dev->data->tx_queues[queue_id]) {
		mce_tx_queue_release(dev->data->tx_queues[queue_id]);
		dev->data->tx_queues[queue_id] = NULL;
	}

	txq = rte_zmalloc_socket("mce_txq", sizeof(struct mce_tx_queue),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (!txq) {
		PMD_DRV_LOG(ERR, "Failed to allocate TX ring memory");
		return -ENOMEM;
	}
	txq->tx_rs_thresh = tx_conf->tx_rs_thresh ? tx_conf->tx_rs_thresh :
						    MCE_DEFAULT_TX_RS_THRESH;
	txq->tx_free_thresh = tx_conf->tx_free_thresh ?
				      tx_conf->tx_free_thresh :
				      MCE_DEFAULT_TX_FREE_THRESH;
	txq->tx_free_thresh = RTE_MIN(txq->tx_free_thresh, nb_desc - 3);
	if (txq->tx_rs_thresh > txq->tx_free_thresh) {
		PMD_INIT_LOG(ERR,
			     "tx_rs_thresh must be less than or "
			     "equal to tx_free_thresh. (tx_free_thresh=%u"
			     " tx_rs_thresh=%u port=%d queue=%d)",
			     (unsigned int)tx_conf->tx_free_thresh,
			     (unsigned int)tx_conf->tx_rs_thresh,
			     (int)dev->data->port_id, (int)queue_id);
		err = -EINVAL;
		goto fail;
	}
	/* We just Support Sriov One port per PF*/
	txq->attr.index = queue_id + vport->attr.qpair_offset;
	txq->attr.lane_id = vport->attr.nr_port;
	txq->attr.queue_id = queue_id;
	txq->attr.nb_desc = nb_desc;
	txq->attr.nb_desc_mask = nb_desc - 1;
	txq->attr.rte_pid = dev->data->port_id;

	/* When PF and VF all used that the PF must regards
	 * it as a VF Just For dma-ring resource divide
	 */
	err = mce_alloc_tx_mem(dev, txq, nb_desc, socket_id);
	if (err)
		goto fail;

	PMD_DRV_LOG(INFO,
		    "PF[%d] dev:[%d] txq queue_id[%d] "
		    "dma_idx %d socket %d\n",
		    hw->function, txq->attr.rte_pid, txq->attr.lane_id,
		    txq->attr.index, socket_id);

	mce_setup_txbdr(hw, txq);
	txq->nb_tx_free = nb_desc - 1;
	txq->tx_free_trigger = txq->tx_free_thresh + 1;
	txq->tx_next_dd = txq->tx_rs_thresh - 1;
	txq->tx_next_rs = txq->tx_rs_thresh - 1;
	txq->last_desc_cleaned = (uint16_t)(txq->attr.nb_desc_mask);
	txq->wthresh = tx_conf->tx_thresh.wthresh;
	txq->pthresh = tx_conf->tx_thresh.pthresh;
	txq->hthresh = tx_conf->tx_thresh.hthresh;

	prev = (uint16_t)(txq->attr.nb_desc_mask);
	sw_ring = txq->sw_ring;
	for (i = 0; i < txq->attr.nb_desc; i++) {
		sw_ring[i].mbuf = NULL;
		sw_ring[i].last_id = i;
		sw_ring[i].rs_bit_set = false;
		sw_ring[i].cur_id = i;
		sw_ring[i].prev_id = prev;
		sw_ring[prev].next_id = i;
		prev = i;
	}
	if (queue_id < data->nb_tx_queues)
		data->tx_queues[queue_id] = txq;

	txq->tx_deferred_start = tx_conf->tx_deferred_start;
#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
	txq->offloads = tx_conf->txq_flags;
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	txq->offloads |=
		((txmode->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) ?
			 RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE :
			 0);
	txq->offloads |= ((txmode->offloads & RTE_ETH_TX_OFFLOAD_VLAN_INSERT) ?
				  RTE_ETH_TX_OFFLOAD_VLAN_INSERT :
				  0);
	txq->offloads |= ((txmode->offloads & RTE_ETH_TX_OFFLOAD_QINQ_INSERT) ?
				  RTE_ETH_TX_OFFLOAD_QINQ_INSERT :
				  0);
#endif
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	if (!vport->is_vf) {
		struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
		int ret = 0;

		txq->mce_admin_dynfield_offset = -1;
		if (pf->nr_repr_ports) {
			ret = mce_mbuf_dyn_admin_register(
				&txq->mce_admin_dynfield_offset,
				&txq->mce_admin_dynflag, "adamin_tx",
				RTE_MBUF_DYNFLAG_TX_ADMIN_NAME);
			if (ret < 0) {
				printf("sport dyn register failed is failed "
				       "%d\n",
				       ret);
				return ret;
			}
		}
	}
#endif

	return 0;
fail:
	rte_free(txq);

	return err;
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
void mce_dev_tx_queue_release(struct rte_eth_dev *dev, uint16_t queue_id)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(queue_id);
}
#endif

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
int mce_fdir_setup_txq(struct mce_vport *vport)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
	const struct rte_memzone *rz = NULL;
	struct mce_tx_queue *txq;
	struct rte_eth_dev *dev;

	dev = vport->dev;
	txq = rte_zmalloc_socket("mce fdir tx queue",
				 sizeof(struct mce_tx_queue),
				 RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
	if (!txq) {
		PMD_DRV_LOG(ERR, "Failed to allocate memory for "
				 "tx queue structure.");
		return -ENOMEM;
	}
#define MCE_FDIR_NUM_TX_DESC (512)
#define MCE_FDIR_QUEUE_ID    (7)
	/* Allocate TX hardware ring descriptors. */
	txq->rz = rz;
	txq->attr.nb_desc = MCE_FDIR_NUM_TX_DESC;
	txq->attr.nb_desc_mask = MCE_FDIR_NUM_TX_DESC - 1;
	txq->attr.queue_id = MCE_FDIR_QUEUE_ID;
	txq->attr.index = MCE_FDIR_QUEUE_ID;
	txq->attr.nb_desc = MCE_FDIR_NUM_TX_DESC;
	mce_alloc_tx_mem(dev, txq, MCE_FDIR_NUM_TX_DESC, SOCKET_ID_ANY);
	mce_setup_txbdr(hw, txq);
	pf->commit.txq = txq;
	return 0;
}

int mce_fdir_tx_queue_start(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t dma_index;

	PMD_INIT_FUNC_TRACE();

	dma_index = MCE_FDIR_QUEUE_ID;
	/* Enable Tx Queue */
	modify32(hw, MCE_DMA_TXQ_START(dma_index), MCE_TXQ_START_EN, true);
	return 0;
}

int mce_fdir_tx_queue_stop(struct rte_eth_dev *dev)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t dma_index;

	PMD_INIT_FUNC_TRACE();

	dma_index = MCE_FDIR_QUEUE_ID;
	/* Enable Tx Queue */
	modify32(hw, MCE_DMA_TXQ_START(dma_index), MCE_TXQ_START_EN, false);
	return 0;
}
#else
int mce_fdir_setup_txq(struct mce_vport *vport)
{
	RTE_SET_USED(vport);
	return 0;
}
int mce_fdir_tx_queue_stop(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}
int mce_fdir_tx_queue_start(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}
#endif
int mce_enable_all_rx_queue(struct rte_eth_dev *dev)
{
	struct mce_rx_queue *rxq;
	uint16_t idx;
	int ret = 0;

	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = dev->data->rx_queues[idx];
		if (!rxq)
			continue;
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		if (dev->data->rx_queue_state[idx] ==
		    RTE_ETH_QUEUE_STATE_STOPPED) {
			ret = mce_rx_queue_start(dev, idx);
			if (ret < 0)
				return ret;
		}
#else
		ret = mce_rx_queue_start(dev, idx);
		if (ret < 0)
			return ret;
#endif
	}

	return ret;
}

int mce_enable_all_tx_queue(struct rte_eth_dev *dev)
{
	struct mce_tx_queue *txq;
	uint16_t idx;
	int ret = 0;

	for (idx = 0; idx < dev->data->nb_tx_queues; idx++) {
		txq = dev->data->tx_queues[idx];
		if (!txq)
			continue;
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		if (dev->data->tx_queue_state[idx] ==
		    RTE_ETH_QUEUE_STATE_STOPPED) {
			ret = mce_tx_queue_start(dev, idx);
			if (ret < 0)
				return ret;
		}
#else
		ret = mce_rx_queue_start(dev, idx);
		if (ret < 0)
			return ret;
#endif
	}
	return ret;
}

int mce_disable_all_rx_queue(struct rte_eth_dev *dev)
{
	struct mce_rx_queue *rxq;
	uint16_t idx;
	int ret = 0;

	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = dev->data->rx_queues[idx];
		if (!rxq)
			continue;
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		if (dev->data->rx_queue_state[idx] ==
		    RTE_ETH_QUEUE_STATE_STARTED) {
			ret = mce_rx_queue_stop(dev, idx);
			if (ret < 0)
				return ret;
		}
#else
		ret = mce_rx_queue_stop(dev, idx);
		if (ret < 0)
			return ret;
#endif
	}

	return ret;
}

int mce_disable_all_tx_queue(struct rte_eth_dev *dev)
{
	struct mce_tx_queue *txq;
	uint16_t idx;
	int ret = 0;

	for (idx = 0; idx < dev->data->nb_tx_queues; idx++) {
		txq = dev->data->tx_queues[idx];
		if (!txq)
			continue;
#if RTE_VERSION_NUM(16, 4, 0, 0) <= RTE_VERSION
		if (dev->data->tx_queue_state[idx] ==
		    RTE_ETH_QUEUE_STATE_STARTED) {
			ret = mce_tx_queue_stop(dev, idx);
			if (ret < 0)
				return ret;
		}
#else
		ret = mce_rx_queue_stop(dev, idx);
		if (ret < 0)
			return ret;
#endif
	}

	return ret;
}

int mce_fdir_programming(struct mce_fdir_fifo_commit *commit)
{
	struct mce_tx_queue *txq;
	volatile union mce_tx_desc *desc;
	uint16_t tx_tail = 0;
	uint16_t pkt_len = 0;
	int i = 0;

	txq = commit->txq;
#if 0
	for (i = 0; i < 60; i++) {
		commit->cmd_buf[0].data[60 - i] = 0xff;
	}
	for (i = 0; i < 60; i++) {
		commit->cmd_buf[1].data[60 - i] = i & (8 - 1);
	}
#endif
	tx_tail = txq->tx_tail;
	desc = &txq->tx_bdr[tx_tail];
	memset(commit->prg_pkt, 0, 512);
	pkt_len = sizeof(struct mce_fdir_prog_cmd) * commit->cmd_block;
	memcpy(commit->prg_pkt, &commit->cmd_buf, pkt_len);
	desc->d.pkt_addr = commit->dma_addr;
	desc->d.qword1.length = pkt_len;
	desc->d.qword6.cmd = MCE_CMD_EOP | MCE_CMD_RS;
	desc->d.qword5.mac_vlan_ctrl = MCE_TX_FD_PROGRAM;
	tx_tail = (tx_tail + 1) & txq->attr.nb_desc_mask;
	rte_wmb();
	MCE_REG_ADDR_WRITE(txq->tx_tailreg, 0, tx_tail);
	for (i = 0; i < commit->cmd_block; i++) {
		rte_hexdump(stdout, NULL, &commit->cmd_buf[i],
			    sizeof(struct mce_fdir_prog_cmd));
		printf("-------------------------------------------------------"
		       "-------\n");
	}
	do {
		if (txq->tx_bdr[txq->tx_tail].wb.cmd & MCE_CMD_DD)
			break;
	} while (1);
	txq->tx_bdr[txq->tx_tail].wb.cmd = 0;
	printf("fd program pkts send finish\n");
	txq->tx_tail = tx_tail;

	return 0;
}

static inline int mce_refill_rx_ring(struct mce_rx_queue *rxq)
{
	struct mce_rxsw_entry *rx_swbd;
	volatile union mce_rx_desc *rxbd;
	struct rte_mbuf *mb;
	uint16_t rx_id;
	uint16_t j, i;
	int ret;

	rxbd = rxq->rx_bdr + rxq->rxrearm_start;
	rx_swbd = &rxq->sw_ring[rxq->rxrearm_start];

	ret = rte_mempool_get_bulk(rxq->mb_pool, (void *)rx_swbd,
				   rxq->rx_free_thresh);

	if (unlikely(ret != 0)) {
		if (rxq->rxrearm_nb + rxq->rx_free_thresh >=
		    rxq->attr.nb_desc) {
			for (i = 0; i < CACHE_FETCH_RX; i++) {
				rx_swbd[i].mbuf = NULL;
				rxbd[i].d.pkt_addr = 0;
				rxbd[i].d.rsvd3 = 0;
			}
		}
		rte_eth_devices[rxq->attr.rte_pid].data->rx_mbuf_alloc_failed +=
			rxq->rx_free_thresh;
		return 0;
	}
	for (j = 0; j < rxq->rx_free_thresh; ++j) {
		mb = rx_swbd[j].mbuf;
		rte_mbuf_refcnt_set(mb, 1);
		mb->data_off = RTE_PKTMBUF_HEADROOM;
		mb->port = rxq->attr.rte_pid;
		rxbd[j].d.pkt_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova(mb));
		rxbd[j].d.rsvd3 = 0;
	}
	rxq->rxrearm_start += rxq->rx_free_thresh;
	if (rxq->rxrearm_start >= rxq->attr.nb_desc)
		rxq->rxrearm_start = 0;
	rxq->rxrearm_nb -= rxq->rx_free_thresh;

	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
				   (rxq->attr.nb_desc_mask) :
				   (rxq->rxrearm_start - 1));
	rte_wmb();
	MCE_REG_ADDR_WRITE(rxq->rx_tailreg, 0, rx_id);
	return j;
}

static void mce_dev_rx_cksum(struct rte_mbuf *m,
			     volatile union mce_rx_desc *rx_desc)
{
	uint32_t cksum_err;

	cksum_err = rx_desc->wb.err_cmd & MCE_RX_CKSUM_ERR_MASK;
	if (m->packet_type & RTE_PTYPE_TUNNEL_MASK) {
		if (cksum_err & MCE_RX_OUT_L4CKSUM_E)
			m->ol_flags |= RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD;
		else
			m->ol_flags |= RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD;
		if (cksum_err & MCE_RX_OUT_L3CKSUM_E)
			m->ol_flags |= RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD;
		if (cksum_err & MCE_RX_INNER_L3CKSUM_E)
			m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
		else
			m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_GOOD;
		if (cksum_err & MCE_RX_INNER_L4CKSUM_E)
			m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;
		else
			m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
	} else {
		if (cksum_err & MCE_RX_OUT_L4CKSUM_E)
			m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_BAD;
		else
			m->ol_flags |= RTE_MBUF_F_RX_L4_CKSUM_GOOD;
		if (cksum_err & MCE_RX_OUT_L3CKSUM_E)
			m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_BAD;
		else
			m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_GOOD;
	}
}
#ifdef MCE_DEBUG_RSS
#include <string.h>
extern uint8_t mce_rss_default_key;
static uint32_t toeplitz_hash(uint32_t keylen, const uint8_t *key,
			      uint32_t datalen, const uint8_t *data)
{
	uint32_t hash = 0, v;
	u_int i, b;

	/* XXXRW: Perhaps an assertion about key length vs. data length? */

	v = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
	for (i = 0; i < datalen; i++) {
		for (b = 0; b < 8; b++) {
			if (data[i] & (1 << (7 - b)))
				hash ^= v;
			v <<= 1;
			if ((i + 4) < keylen && (key[i + 4] & (1 << (7 - b))))
				v |= 1;
		}
	}
	return (hash);
}

static uint32_t mce_calc_rss(struct mce_rx_queue *rxq, struct rte_mbuf *mbuf)
{
	uint8_t data[sizeof(struct rte_ipv6_hdr) + 20 + 4] = { 0 };
	struct rte_eth_rss_conf rss_conf;
	uint16_t rte_port = rxq->attr.rte_pid;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr ipv4_hdr_tmp;
	struct rte_ipv6_hdr ipv6_hdr_tmp;
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_ipv6_hdr *ipv6_hdr = NULL;
	struct rte_esp_hdr *esp_hdr = NULL;
	struct rte_tcp_hdr *tcp_hdr = NULL;
	struct rte_tcp_hdr tcp_hdr_tmp;
	struct rte_udp_hdr *udp_hdr = NULL;
	struct rte_tcp_hdr udp_hdr_tmp;
	struct rte_sctp_hdr *sctp_hdr = NULL;
	struct rte_sctp_hdr sctp_hdr_tmp;
	struct rte_gtp_hdr *gtp_hdr = NULL;
	uint32_t rss_hash = 0;
	bool l3_used = false;
	bool l4_used = false;
	uint16_t datalen = 0;
	uint32_t temp0, temp1;
	int i = 0;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	memset(&rss_conf, 0, sizeof(rss_conf));
	memset(&tcp_hdr_tmp, 0, sizeof(tcp_hdr_tmp));
	memset(&udp_hdr_tmp, 0, sizeof(udp_hdr_tmp));
	memset(&sctp_hdr_tmp, 0, sizeof(sctp_hdr_tmp));
	memset(&ipv4_hdr_tmp, 0, sizeof(ipv4_hdr_tmp));
	memset(&ipv6_hdr_tmp, 0, sizeof(ipv6_hdr_tmp));
	rte_eth_dev_rss_hash_conf_get(rte_port, &rss_conf);
	if (rss_conf.rss_hf) {
		struct rte_gre_hdr *gre_hdr = NULL;
		uint16_t tunnel_len = 0;
		uint16_t l3_len = 0;
		uint16_t l2_len = 0;

		if (eth_hdr->ether_type != rte_cpu_to_be_16(0x0800) &&
		    eth_hdr->ether_type != rte_cpu_to_be_16(0x86dd)) {
			l2_len = sizeof(struct rte_ether_hdr) +
				 sizeof(struct rte_vlan_hdr);
		} else
			l2_len = sizeof(struct rte_ether_hdr);

		if ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
		    RTE_PTYPE_L3_IPV4_EXT_UNKNOWN)
			l3_len = sizeof(struct rte_ipv4_hdr);
		/* need to care extend l3 hdr */
		else if ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
			 RTE_PTYPE_L3_IPV6_EXT_UNKNOWN) {
			/* need to care extend l3 hdr */
			l3_len = sizeof(struct rte_ipv6_hdr);

			switch (mbuf->packet_type & RTE_PTYPE_TUNNEL_MASK) {
			case RTE_PTYPE_TUNNEL_MPLS_IN_UDP:
				tunnel_len = sizeof(struct rte_udp_hdr) +
					     sizeof(struct rte_mpls_hdr);
				break;
			case RTE_PTYPE_TUNNEL_VXLAN_GPE:
				tunnel_len = sizeof(struct rte_udp_hdr) +
					     sizeof(struct rte_vxlan_gpe_hdr);
				break;
			case RTE_PTYPE_TUNNEL_VXLAN:
				tunnel_len = sizeof(struct rte_udp_hdr) +
					     sizeof(struct rte_vxlan_hdr);
				break;
			case RTE_PTYPE_TUNNEL_GENEVE:
				tunnel_len = sizeof(struct rte_udp_hdr) +
					     sizeof(struct rte_geneve_hdr);
				break;
			case RTE_PTYPE_TUNNEL_GRE:
				gre_hdr = rte_pktmbuf_mtod_offset(
					mbuf, struct rte_gre_hdr *,
					l2_len + l3_len);
				tunnel_len = sizeof(struct rte_gre_hdr);
#define GRE_TUNNEL_KEY	 (4)
#define GRE_TUNNEL_SEQ	 (4)
#define GRE_TUNNEL_CKSUM (4)
				if (gre_hdr->k)
					tunnel_len += GRE_TUNNEL_KEY;
				if (gre_hdr->s)
					tunnel_len += GRE_TUNNEL_SEQ;
				if (gre_hdr->c)
					tunnel_len += GRE_TUNNEL_CKSUM;
				break;
			case RTE_PTYPE_TUNNEL_IP:
				tunnel_len = 0;
				break;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
			case RTE_PTYPE_TUNNEL_GTPU:
				tunnel_len = sizeof(struct rte_udp_hdr) +
					     sizeof(struct rte_gtp_hdr);
				break;
#endif
			}
			eth_hdr = rte_pktmbuf_mtod_offset(
				mbuf, struct rte_ether_hdr *,
				l2_len + l3_len + tunnel_len);
		}
		if ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
				RTE_PTYPE_L3_IPV4_EXT_UNKNOWN) {
			ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr +  sizeof(*eth_hdr));
			if (rss_conf.algorithm == RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
				ipv4_hdr_tmp.src_addr = ipv4_hdr->src_addr ^ ipv4_hdr->dst_addr;
				ipv4_hdr_tmp.dst_addr = ipv4_hdr->src_addr ^ ipv4_hdr->dst_addr;
			} else if (rss_conf.algorithm ==
				   RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ_SORT) {
				if (ipv4_hdr->src_addr > ipv4_hdr->dst_addr) {
					ipv4_hdr_tmp.src_addr = ipv4_hdr->dst_addr;
					ipv4_hdr_tmp.dst_addr = ipv4_hdr->src_addr;
				} else {
					ipv4_hdr_tmp.src_addr = ipv4_hdr->src_addr;
					ipv4_hdr_tmp.dst_addr = ipv4_hdr->dst_addr;
				}
				temp0 = ipv4_hdr_tmp.src_addr ^ ipv4_hdr_tmp.dst_addr;
				temp1 = ipv4_hdr_tmp.src_addr ^ ipv4_hdr_tmp.dst_addr;
				ipv4_hdr_tmp.src_addr = temp0;
				ipv4_hdr_tmp.dst_addr = temp1;
			} else {
				ipv4_hdr_tmp.src_addr = ipv4_hdr->src_addr;
				ipv4_hdr_tmp.dst_addr = ipv4_hdr->dst_addr;
			}
			if (rss_conf.rss_hf & RTE_ETH_RSS_IPV4) {
				bcopy(&ipv4_hdr_tmp.src_addr, &data[datalen],
				      4);
				datalen += 4;
				bcopy(&ipv4_hdr_tmp.dst_addr, &data[datalen],
				      4);
				datalen += 4;
				l3_used = true;
			}
			if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) ==
					RTE_PTYPE_L4_TCP) {
				tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr +
						sizeof(*ipv4_hdr));
				if (rss_conf.algorithm == RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					tcp_hdr_tmp.src_port = tcp_hdr->src_port ^ tcp_hdr->dst_port;
					tcp_hdr_tmp.dst_port = tcp_hdr->src_port ^ tcp_hdr->dst_port;
				} else if (rss_conf.algorithm ==
						RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					if (tcp_hdr->src_port > tcp_hdr->dst_port) {
						tcp_hdr_tmp.src_port = tcp_hdr->dst_port;
						tcp_hdr_tmp.dst_port = tcp_hdr->src_port;
					} else {
						tcp_hdr_tmp.src_port = tcp_hdr->src_port;
						tcp_hdr_tmp.dst_port = tcp_hdr->dst_port;
					}
					temp0 = tcp_hdr_tmp.src_port ^ tcp_hdr_tmp.dst_port;
					temp1 = tcp_hdr_tmp.src_port ^ tcp_hdr_tmp.dst_port;
					tcp_hdr_tmp.src_port = temp0;
					tcp_hdr_tmp.dst_port = temp1;
				} else {
					tcp_hdr_tmp.src_port = tcp_hdr->src_port;
					tcp_hdr_tmp.dst_port = tcp_hdr->dst_port;
				}
				if (rss_conf.rss_hf &
						RTE_ETH_RSS_NONFRAG_IPV4_TCP) {
					if (l3_used == 0) {
						bcopy(&ipv4_hdr_tmp.src_addr,
								&data[datalen], 4);
						datalen += 4;
						bcopy(&ipv4_hdr_tmp.dst_addr,
								&data[datalen], 4);
						datalen += 4;
					}
					bcopy(&tcp_hdr->src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&tcp_hdr->dst_port,
					      &data[datalen], 2);
					datalen += 2;
					l4_used = 1;
				}
			}
			if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) ==
			    RTE_PTYPE_L4_UDP) {
				udp_hdr = (struct rte_udp_hdr
						   *)((char *)ipv4_hdr +
						      sizeof(*ipv4_hdr));
				if (rss_conf.algorithm == RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					udp_hdr_tmp.src_port = udp_hdr->src_port ^ udp_hdr->dst_port;
					udp_hdr_tmp.dst_port = udp_hdr->src_port ^ udp_hdr->dst_port;
				} else if (rss_conf.algorithm ==
					   RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					if (udp_hdr->src_port > udp_hdr->dst_port) {
						udp_hdr_tmp.src_port = udp_hdr->dst_port;
						udp_hdr_tmp.dst_port = udp_hdr_tmp.src_port;
					} else {
						udp_hdr_tmp.src_port = udp_hdr->src_port;
						udp_hdr_tmp.dst_port = udp_hdr->dst_port;
					}
					temp0 = udp_hdr_tmp.src_port ^ udp_hdr_tmp.dst_port;
					temp1 = udp_hdr_tmp.src_port ^ udp_hdr_tmp.dst_port;
					udp_hdr_tmp.src_port = temp0;
					udp_hdr_tmp.dst_port = temp1;
				} else {
					udp_hdr_tmp.src_port = udp_hdr->src_port;
					udp_hdr_tmp.dst_port = udp_hdr->dst_port;
				}
				if (rss_conf.rss_hf &
				    RTE_ETH_RSS_NONFRAG_IPV4_UDP) {
					if (l3_used == 0) {
						bcopy(&ipv4_hdr_tmp.src_addr,
						      &data[datalen], 4);
						datalen += 4;
						bcopy(&ipv4_hdr_tmp.dst_addr,
						      &data[datalen], 4);
						datalen += 4;
					}
					bcopy(&udp_hdr_tmp.src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&udp_hdr_tmp.dst_port,
					      &data[datalen], 2);
					datalen += 2;
					l4_used = 1;
				}
			}
			if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) ==
			    RTE_PTYPE_L4_SCTP) {
				sctp_hdr = (struct rte_sctp_hdr
						    *)((char *)ipv4_hdr +
						       sizeof(*ipv4_hdr));
				if (rss_conf.algorithm ==
				    RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					sctp_hdr_tmp.src_port = sctp_hdr->src_port ^ sctp_hdr->dst_port;
					sctp_hdr_tmp.dst_port = sctp_hdr->src_port ^ sctp_hdr->dst_port;
				} else if (rss_conf.algorithm ==
					   RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ_SORT) {
					if (sctp_hdr->src_port > sctp_hdr->dst_port) {
						sctp_hdr_tmp.src_port = sctp_hdr->dst_port;
						sctp_hdr_tmp.dst_port = sctp_hdr_tmp.src_port;
					} else {
						sctp_hdr_tmp.src_port = sctp_hdr->src_port;
						sctp_hdr_tmp.dst_port = sctp_hdr->dst_port;
					}
					temp0 = sctp_hdr_tmp.src_port ^ sctp_hdr_tmp.dst_port;
					temp1 = sctp_hdr_tmp.src_port ^ sctp_hdr_tmp.dst_port;
					sctp_hdr_tmp.src_port = temp0;
					sctp_hdr_tmp.dst_port = temp1;
				} else {
					sctp_hdr_tmp.src_port = sctp_hdr->src_port;
					sctp_hdr_tmp.dst_port = sctp_hdr->dst_port;
				}
				if (rss_conf.rss_hf &
				    RTE_ETH_RSS_NONFRAG_IPV4_SCTP) {
					if (l3_used == 0) {
						bcopy(&ipv4_hdr_tmp.src_addr,
						      &data[datalen], 4);
						datalen += 4;
						bcopy(&ipv4_hdr_tmp.dst_addr,
						      &data[datalen], 4);
						datalen += 4;
					}
					bcopy(&sctp_hdr_tmp.src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&sctp_hdr_tmp.dst_port,
					      &data[datalen], 2);
					datalen += 2;
					l4_used = 1;
				}
			}
			if (mbuf->packet_type & RTE_PTYPE_TUNNEL_ESP &&
			    rss_conf.rss_hf & RTE_ETH_RSS_ESP) {
				if (l3_used == 0) {
					bcopy(&ipv4_hdr_tmp.src_addr,
					      &data[datalen], 4);
					datalen += 4;
					bcopy(&ipv4_hdr_tmp.dst_addr,
					      &data[datalen], 4);
					datalen += 4;
				}
				if (mbuf->packet_type & RTE_PTYPE_L4_UDP) {
					esp_hdr =
						(struct rte_esp_hdr
							 *)((char *)ipv4_hdr +
							    sizeof(*ipv4_hdr) +
							    sizeof(struct rte_udp_hdr));
					if (l4_used == 0) {
						bcopy(&udp_hdr_tmp.src_port,
						      &data[datalen], 2);
						datalen += 2;
						bcopy(&udp_hdr_tmp.dst_port,
						      &data[datalen], 2);
						datalen += 2;
					}
				} else {
					esp_hdr =
						(struct rte_esp_hdr
							 *)((char *)ipv4_hdr +
							    sizeof(*ipv4_hdr));
				}
				bcopy(&esp_hdr->spi, &data[datalen], 4);
				datalen += 4;
			}
			if ((mbuf->packet_type & RTE_PTYPE_TUNNEL_GTPU ||
			     mbuf->packet_type & RTE_PTYPE_TUNNEL_GTPC) &&
			    rss_conf.rss_hf & RTE_ETH_RSS_GTPU) {
				if (l3_used == 0) {
					bcopy(&ipv4_hdr_tmp.src_addr,
					      &data[datalen], 4);
					datalen += 4;
					bcopy(&ipv4_hdr_tmp.dst_addr,
					      &data[datalen], 4);
					datalen += 4;
				}
				if (l4_used == 0) {
					bcopy(&udp_hdr_tmp.src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&udp_hdr_tmp.dst_port,
					      &data[datalen], 2);
					datalen += 2;
				}
				gtp_hdr =
					(struct rte_gtp_hdr
						 *)((char *)ipv4_hdr +
						    sizeof(*ipv4_hdr) +
						    sizeof(struct rte_udp_hdr));
				bcopy(&gtp_hdr->teid, &data[datalen], 4);
				datalen += 4;
			}
			rss_hash = toeplitz_hash(52, &mce_rss_default_key,
					datalen, data);
			if (mbuf->ol_flags & RTE_MBUF_F_RX_RSS_HASH) {
				if (rss_hash != mbuf->hash.rss)
					printf("software hash != hardware ipv4 "
					       "sw hash "
					       "0x%.2x hw hash "
					       "0x%.2x\n",
					       rss_hash, mbuf->hash.rss);
#if 0
				else
					printf("software hash == hardware ipv4 "
					       "sw hash "
					       "0x%.2x hw hash "
					       "0x%.2x\n",
					       rss_hash, mbuf->hash.rss);
#endif
			}
		}
		if ((mbuf->packet_type & RTE_PTYPE_L3_MASK) ==
		    RTE_PTYPE_L3_IPV6_EXT_UNKNOWN) {
			uint64_t src_addr = 0;
			uint64_t dst_addr = 0;
			ipv6_hdr = (struct rte_ipv6_hdr *)((char *)eth_hdr +
							   sizeof(*eth_hdr));
			if (rss_conf.algorithm ==
			    RTE_ETH_HASH_FUNCTION_SIMPLE_XOR) {
				for (i = 0; i < 16; i++) {
					ipv6_hdr_tmp.src_addr[i] =
						ipv6_hdr->src_addr[i];
					ipv6_hdr_tmp.dst_addr[i] =
						ipv6_hdr->dst_addr[i];
				}
			} else if (rss_conf.algorithm ==
				   RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
				for (i = 0; i < 16; i++) {
					src_addr += ipv6_hdr->src_addr[i];
					dst_addr += ipv6_hdr->dst_addr[i];
				}
				if (src_addr > dst_addr) {
					for (i = 0; i < 16; i++) {
						ipv6_hdr_tmp.src_addr[i] =
							ipv6_hdr->dst_addr[i];
						ipv6_hdr_tmp.dst_addr[i] =
							ipv6_hdr->src_addr[i];
					}
				} else {
					for (i = 0; i < 16; i++) {
						ipv6_hdr_tmp.src_addr[i] =
							ipv6_hdr->src_addr[i];
						ipv6_hdr_tmp.dst_addr[i] =
							ipv6_hdr->dst_addr[i];
					}
				}
			} else {
				for (i = 0; i < 16; i++) {
					ipv6_hdr_tmp.src_addr[i] =
						ipv6_hdr->src_addr[i];

					ipv6_hdr_tmp.dst_addr[i] =
						ipv6_hdr->dst_addr[i];
				}
			}
			if (rss_conf.rss_hf & RTE_ETH_RSS_IPV6) {
				bcopy(&ipv6_hdr_tmp.src_addr, &data[datalen],
				      16);
				datalen += 16;
				bcopy(&ipv6_hdr_tmp.dst_addr, &data[datalen],
				      16);
				datalen += 16;
				l3_used = true;
			}
			if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) ==
			    RTE_PTYPE_L4_TCP) {
				tcp_hdr = (struct rte_tcp_hdr
						   *)((char *)ipv6_hdr +
						      sizeof(*ipv6_hdr));
				if (rss_conf.algorithm ==
				    RTE_ETH_HASH_FUNCTION_SIMPLE_XOR) {
					tcp_hdr_tmp.src_port = tcp_hdr->src_port;
					tcp_hdr_tmp.dst_port = tcp_hdr->dst_port;
				} else if (rss_conf.algorithm ==
					   RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					if (tcp_hdr->src_port >
					    tcp_hdr->dst_port) {
						tcp_hdr_tmp.src_port =
							tcp_hdr->dst_port;
						tcp_hdr_tmp.dst_port =
							tcp_hdr->src_port;
					} else {
						tcp_hdr_tmp.src_port =
							tcp_hdr->src_port;
						tcp_hdr_tmp.dst_port =
							tcp_hdr->dst_port;
					}
				} else {
					tcp_hdr_tmp.src_port =
						tcp_hdr->src_port;
					tcp_hdr_tmp.dst_port =
						tcp_hdr->dst_port;
				}
				if (rss_conf.rss_hf &
				    RTE_ETH_RSS_NONFRAG_IPV6_TCP) {
					if (l3_used == 0) {
						bcopy(&ipv6_hdr_tmp.src_addr,
						      &data[datalen], 16);
						datalen += 16;
						bcopy(&ipv6_hdr_tmp.dst_addr,
						      &data[datalen], 16);
						datalen += 16;
					}
					bcopy(&tcp_hdr->src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&tcp_hdr->dst_port,
					      &data[datalen], 2);
					datalen += 2;
					l4_used = 1;
				}
			}
			if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) ==
			    RTE_PTYPE_L4_UDP) {
				udp_hdr = (struct rte_udp_hdr
						   *)((char *)ipv6_hdr +
						      sizeof(*ipv6_hdr));
				if (rss_conf.algorithm ==
				    RTE_ETH_HASH_FUNCTION_SIMPLE_XOR) {
					udp_hdr_tmp.src_port = udp_hdr->src_port;
					udp_hdr_tmp.dst_port = udp_hdr->dst_port;
				} else if (rss_conf.algorithm ==
					   RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					if (udp_hdr->src_port >
					    udp_hdr->dst_port) {
						udp_hdr_tmp.src_port =
							udp_hdr->dst_port;
						udp_hdr_tmp.dst_port =
							udp_hdr_tmp.src_port;
					} else {
						udp_hdr_tmp.src_port =
							udp_hdr->src_port;
						udp_hdr_tmp.dst_port =
							udp_hdr->dst_port;
					}
				} else {
					udp_hdr_tmp.src_port =
						udp_hdr->src_port;
					udp_hdr_tmp.dst_port =
						udp_hdr->dst_port;
				}
				if (rss_conf.rss_hf &
				    RTE_ETH_RSS_NONFRAG_IPV6_UDP) {
					if (l3_used == 0) {
						bcopy(&ipv6_hdr_tmp.src_addr,
						      &data[datalen], 16);
						datalen += 16;
						bcopy(&ipv6_hdr_tmp.dst_addr,
						      &data[datalen], 16);
						datalen += 16;
					}
					bcopy(&udp_hdr_tmp.src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&udp_hdr_tmp.dst_port,
					      &data[datalen], 2);
					datalen += 2;
					l4_used = 1;
				}
			}
			if ((mbuf->packet_type & RTE_PTYPE_L4_MASK) ==
			    RTE_PTYPE_L4_SCTP) {
				sctp_hdr = (struct rte_sctp_hdr
						    *)((char *)ipv6_hdr +
						       sizeof(*ipv6_hdr));
				if (rss_conf.algorithm ==
				    RTE_ETH_HASH_FUNCTION_SIMPLE_XOR) {
					sctp_hdr_tmp.src_port =
						sctp_hdr->src_port;
					sctp_hdr_tmp.dst_port =
						sctp_hdr->dst_port;
				} else if (rss_conf.algorithm ==
					   RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ) {
					if (sctp_hdr->src_port >
					    sctp_hdr->dst_port) {
						sctp_hdr_tmp.src_port =
							sctp_hdr->dst_port;
						sctp_hdr_tmp.dst_port =
							sctp_hdr_tmp.src_port;
					} else {
						sctp_hdr_tmp.src_port =
							sctp_hdr->src_port;
						sctp_hdr_tmp.dst_port =
							sctp_hdr->dst_port;
					}
				} else {
					sctp_hdr_tmp.src_port =
						sctp_hdr->src_port;
					sctp_hdr_tmp.dst_port =
						sctp_hdr->dst_port;
				}
				if (rss_conf.rss_hf &
				    RTE_ETH_RSS_NONFRAG_IPV6_SCTP) {
					if (l3_used == 0) {
						bcopy(&ipv6_hdr_tmp.src_addr,
						      &data[datalen], 16);
						datalen += 16;
						bcopy(&ipv6_hdr_tmp.dst_addr,
						      &data[datalen], 16);
						datalen += 16;
					}
					bcopy(&sctp_hdr_tmp.src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&sctp_hdr_tmp.dst_port,
					      &data[datalen], 2);
					datalen += 2;
					l4_used = 1;
				}
			}
			if (mbuf->packet_type & RTE_PTYPE_TUNNEL_ESP &&
			    rss_conf.rss_hf & RTE_ETH_RSS_ESP) {
				if (l3_used == 0) {
					bcopy(&ipv6_hdr_tmp.src_addr,
					      &data[datalen], 16);
					datalen += 16;
					bcopy(&ipv6_hdr_tmp.dst_addr,
					      &data[datalen], 16);
					datalen += 16;
				}
				if (mbuf->packet_type & RTE_PTYPE_L4_UDP) {
					esp_hdr = (struct rte_esp_hdr *)
						((char *)ipv6_hdr + sizeof(*ipv6_hdr) +
						 sizeof(struct rte_udp_hdr));
					if (l4_used == 0) {
						bcopy(&udp_hdr_tmp.src_port,
						      &data[datalen], 2);
						datalen += 2;
						bcopy(&udp_hdr_tmp.dst_port,
						      &data[datalen], 2);
						datalen += 2;
					}
				} else {
					esp_hdr = (struct rte_esp_hdr *)
						((char *)ipv4_hdr + sizeof(*ipv4_hdr));
				}
				bcopy(&esp_hdr->spi, &data[datalen], 4);
				datalen += 4;
			}
			if ((mbuf->packet_type & RTE_PTYPE_TUNNEL_GTPU ||
			     mbuf->packet_type & RTE_PTYPE_TUNNEL_GTPC) &&
			    rss_conf.rss_hf & RTE_ETH_RSS_GTPU) {
				if (l3_used == 0) {
					bcopy(&ipv6_hdr_tmp.src_addr,
					      &data[datalen], 16);
					datalen += 16;
					bcopy(&ipv6_hdr_tmp.dst_addr,
					      &data[datalen], 16);
					datalen += 16;
				}
				if (l4_used == 0) {
					bcopy(&udp_hdr_tmp.src_port,
					      &data[datalen], 2);
					datalen += 2;
					bcopy(&udp_hdr_tmp.dst_port,
					      &data[datalen], 2);
					datalen += 2;
				}
				gtp_hdr =
					(struct rte_gtp_hdr
						 *)((char *)ipv6_hdr +
						    sizeof(*ipv6_hdr) +
						    sizeof(struct rte_udp_hdr));
				bcopy(&gtp_hdr->teid, &data[datalen], 4);
				datalen += 4;
			}
			rss_hash = toeplitz_hash(52, &mce_rss_default_key,
						 datalen, data);
			if (mbuf->ol_flags & RTE_MBUF_F_RX_RSS_HASH)
				if (rss_hash != mbuf->hash.rss) {
					printf("software hash != hardware ipv6 "
					       "sw hash "
					       "0x%.2x hw hash "
					       "0x%.2x\n",
					       rss_hash, mbuf->hash.rss);
				}
		}
	}
	mbuf->dynfield1[0] = rss_hash;
	char buf[256] = { 0 };
	rte_get_ptype_name(mbuf->packet_type, buf, sizeof(buf));
	printf("hw %s\n", buf);
	printf("RSS algorithm:\n  %s\n",
			rte_eth_dev_rss_algo_name(rss_conf.algorithm));
	return rss_hash;
}
#endif

#ifdef MCE_DEBUG_RX_DESC
static void print_packet_info(struct rte_mbuf *m)
{
	char *data = rte_pktmbuf_mtod(m, char *);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(m);

	/* print basic info */
	printf("Packet Length: %u bytes\n", pkt_len);
	printf("----------------------------------------\n");
	/* Ethernet Header */
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;
	printf("[L2] Ethernet Header:\n");
	printf("  SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
	       eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
	       eth_hdr->src_addr.addr_bytes[4],
	       eth_hdr->src_addr.addr_bytes[5]);
	printf("  DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
	       eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
	       eth_hdr->dst_addr.addr_bytes[4],
	       eth_hdr->dst_addr.addr_bytes[5]);
	printf("  EtherType: 0x%04x\n", rte_be_to_cpu_16(eth_hdr->ether_type));
	if (m->packet_type & RTE_PTYPE_L3_IPV4 ||
		rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
		struct rte_ipv4_hdr *ipv4_hdr =
			(struct rte_ipv4_hdr *)(data +
						sizeof(struct rte_ether_hdr));
		printf("[L3] IPv4 Header:\n");
		printf("  SRC IP: %u.%u.%u.%u\n", ipv4_hdr->src_addr & 0xFF,
		       (ipv4_hdr->src_addr >> 8) & 0xFF,
		       (ipv4_hdr->src_addr >> 16) & 0xFF,
		       (ipv4_hdr->src_addr >> 24) & 0xFF);
		printf("  DST IP: %u.%u.%u.%u\n", ipv4_hdr->dst_addr & 0xFF,
		       (ipv4_hdr->dst_addr >> 8) & 0xFF,
		       (ipv4_hdr->dst_addr >> 16) & 0xFF,
		       (ipv4_hdr->dst_addr >> 24) & 0xFF);
		printf("  Version_ihl: %x\n", ipv4_hdr->version_ihl);
		printf("  Fragment_offset:%u\n", ipv4_hdr->fragment_offset);
		printf("  Checksum: 0x%.4x\n", ipv4_hdr->hdr_checksum);
		printf("  Total_length: %u\n", rte_be_to_cpu_16(ipv4_hdr->total_length));
		printf("  Protocol: %u\n", ipv4_hdr->next_proto_id);
		if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP ||
		    ipv4_hdr->next_proto_id == IPPROTO_TCP){
			struct rte_tcp_hdr *tcp_hdr =
				(struct rte_tcp_hdr
					 *)(data +
					    sizeof(struct rte_ether_hdr) +
					    sizeof(struct rte_ipv4_hdr));
			printf("[L4] TCP Header:\n");
			printf("  SRC Port: %u\n",
			       rte_be_to_cpu_16(tcp_hdr->src_port));
			printf("  DST Port: %u\n",
			       rte_be_to_cpu_16(tcp_hdr->dst_port));
		} else if ((m->packet_type & RTE_PTYPE_L4_MASK) ==
			   RTE_PTYPE_L4_UDP ||
			   ipv4_hdr->next_proto_id == IPPROTO_UDP) {
			struct rte_udp_hdr *udp_hdr =
				(struct rte_udp_hdr
					 *)(data +
					    sizeof(struct rte_ether_hdr) +
					    sizeof(struct rte_ipv4_hdr));
			printf("[L4] UDP Header:\n");
			printf("  SRC Port: %u\n",
			       rte_be_to_cpu_16(udp_hdr->src_port));
			printf("  DST Port: %u\n",
			       rte_be_to_cpu_16(udp_hdr->dst_port));
		} else if ((m->packet_type & RTE_PTYPE_L4_MASK) ==
			   RTE_PTYPE_L4_ICMP ||
			   ipv4_hdr->next_proto_id == IPPROTO_ICMP) {
			struct rte_icmp_hdr *icmp =
				(struct rte_icmp_hdr
					 *)(data +
					    sizeof(struct rte_ether_hdr) +
					    sizeof(struct rte_ipv6_hdr));
			printf("[L4] ICMP: Type=%u, Code=%u\n", icmp->icmp_type,
			       icmp->icmp_code);
		}
	}
	if (m->packet_type & RTE_PTYPE_L3_IPV6 ||
	    rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV6) {
		struct rte_ipv6_hdr *ipv6 =
			(struct rte_ipv6_hdr *)(data +
						sizeof(struct rte_ether_hdr));
		printf("[L3] IPv6 Header:\n");
		printf("[L3] IPv6: SRC=");
#if 0
		int i = 0;
		for (i = 0; i < 4; i++)
			printf("%04X:", rte_be_to_cpu_16(ipv6->src_addr[i]));
		printf("\b, DST=");
		for (i = 0; i < 4; i++)
			printf("%04X:", rte_be_to_cpu_16(ipv6->dst_addr[i]));
#else
		printf(RTE_IPV6_ADDR_FMT, RTE_IPV6_ADDR_SPLIT(&ipv6->src_addr));
		printf("\b, DST=");
		printf(RTE_IPV6_ADDR_FMT, RTE_IPV6_ADDR_SPLIT(&ipv6->dst_addr));
#endif
		printf("\n");
		if ((m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {
			struct rte_tcp_hdr *tcp_hdr =
				(struct rte_tcp_hdr
					 *)(data +
					    sizeof(struct rte_ether_hdr) +
					    sizeof(struct rte_ipv6_hdr));
			printf("[L4] TCP Header:\n");
			printf("  SRC Port: %u\n",
			       rte_be_to_cpu_16(tcp_hdr->src_port));
			printf("  DST Port: %u\n",
			       rte_be_to_cpu_16(tcp_hdr->dst_port));
		} else if ((m->packet_type & RTE_PTYPE_L4_MASK) ==
			   RTE_PTYPE_L4_UDP) {
			struct rte_udp_hdr *udp_hdr =
				(struct rte_udp_hdr
					 *)(data +
					    sizeof(struct rte_ether_hdr) +
					    sizeof(struct rte_ipv6_hdr));
			printf("[L4] UDP Header:\n");
			printf("  SRC Port: %u\n",
			       rte_be_to_cpu_16(udp_hdr->src_port));
			printf("  DST Port: %u\n",
			       rte_be_to_cpu_16(udp_hdr->dst_port));
		} else if ((m->packet_type & RTE_PTYPE_L4_MASK) ==
			   RTE_PTYPE_L4_ICMP) {
			struct rte_icmp_hdr *icmp =
				(struct rte_icmp_hdr
					 *)(data +
					    sizeof(struct rte_ether_hdr) +
					    sizeof(struct rte_ipv6_hdr));
			printf("[L4] ICMP: Type=%u, Code=%u\n", icmp->icmp_type,
			       icmp->icmp_code);
		}
	}
}
#endif

static void mce_dev_rx_parse(struct mce_rx_queue *rxq __rte_unused,
			     volatile union mce_rx_desc *rx_desc,
			     struct rte_mbuf *m)
{
	uint32_t vlan_strip = 0;

	m->packet_type = 0;
	m->ol_flags = 0;
	if (rx_desc->wb.err_cmd & MCE_RX_RSS_VALID) {
		m->hash.rss = rte_le_to_cpu_32(rx_desc->wb.rss_hash);
		m->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
	}
	if (rx_desc->wb.err_cmd & MCE_RX_MARK_VALID) {
		m->hash.fdir.hi = rx_desc->wb.mark_id;
		m->ol_flags |= RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_FDIR_ID;
	}
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	uint16_t sport = (rx_desc->wb.rsvd & GENMASK_U32(15, 9)) >> 9;

	if (sport != 127 && rxq->mce_sport_dynfield_offset > 0) {
		*RTE_MBUF_DYNFIELD(m, (rxq->mce_sport_dynfield_offset),
				   uint16_t *) = sport;
		m->ol_flags |= rxq->mce_sport_rx_dynflag;
	}
#endif
	/* deal rx_cksum err */
	if (rx_desc->wb.cmd & MCE_RX_PTP) {
		m->packet_type |= RTE_PTYPE_L2_ETHER_TIMESYNC;
		m->ol_flags |= RTE_MBUF_F_RX_IEEE1588_PTP |
			       RTE_MBUF_F_RX_IEEE1588_TMST;
	}
	vlan_strip = (rx_desc->wb.err_cmd & MCE_RX_STRIP_VLAN) >>
		     MCE_RX_STRIP_VLAN_S;
	if (vlan_strip) {
		switch (vlan_strip) {
		case 1:
			m->ol_flags |= RTE_MBUF_F_RX_VLAN |
				       RTE_MBUF_F_RX_VLAN_STRIPPED;
			m->vlan_tci = rx_desc->wb.vlan_tag1;
			break;
		case 2:
			m->ol_flags |= RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_QINQ;
			m->ol_flags |= RTE_MBUF_F_RX_VLAN_STRIPPED |
				       RTE_MBUF_F_RX_QINQ_STRIPPED;
			m->vlan_tci = rx_desc->wb.vlan_tag2;
			m->vlan_tci_outer = rx_desc->wb.vlan_tag1;
			break;
		}
	}
#if 0
	uint16_t l3type = 0, inner_l3type;
	uint16_t l4type = 0, inner_l4type;
	uint16_t l2type = 0;
	bool vlan_valid = 0;
	uint16_t tun_type = 0;

	l2type = (rx_desc->wb.cmd & MCE_RX_OUT_L2TYPE_MASK) >>
		 MCE_RX_OUT_L2TYPE_S;
	switch (l2type) {
	case MCE_RX_L2_802_3:
		m->packet_type |= RTE_PTYPE_UNKNOWN;
		break;
	case MCE_RX_L2_UC_MPLS:
	case MCE_RX_L2_MC_MPLS:
		m->packet_type |= RTE_PTYPE_L2_ETHER_MPLS;
		break;
	case MCE_RX_L2_NSH:
		m->packet_type |= RTE_PTYPE_L2_ETHER_NSH;
		break;
	case MCE_RX_L2_QINQ:
		m->packet_type |= RTE_PTYPE_L2_ETHER_QINQ;
		break;
	case MCE_RX_L2_FCOE:
		m->packet_type |= RTE_PTYPE_L2_ETHER_FCOE;
		break;
	};
	vlan_valid = rx_desc->wb.cmd & MCE_RX_L2TYPE_VLAN ? 1 : 0;
	if (!(m->packet_type & RTE_PTYPE_L2_MASK) && vlan_valid)
		m->packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
	inner_l3type = (rx_desc->wb.cmd & MCE_RX_INNER_L3TYPE_MASK) >>
		       MCE_RX_INNER_L3TYPE_S;
	l3type = (rx_desc->wb.cmd & MCE_RX_OUT_L3TYPE_MASK) >>
		 MCE_RX_OUT_L3TYPE_S;
	if (inner_l3type) {
		switch (inner_l3type) {
		case MCE_RX_L3_IPV4:
			m->packet_type |= RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN;
			break;
		case MCE_RX_L3_IPV6:
			m->packet_type |= RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN;
			break;
		case MCE_RX_L3_ARP:
			m->packet_type |= RTE_PTYPE_L2_ETHER_ARP;
			break;
		default:
			break;
		}
	}
	if (l3type) {
		switch (l3type) {
		case MCE_RX_L3_IPV4:
			m->packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
			break;
		case MCE_RX_L3_IPV6:
			m->packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
			break;
		case MCE_RX_L3_ARP:
			m->packet_type |= RTE_PTYPE_L2_ETHER_ARP;
			break;
		}
		if (!(m->packet_type & RTE_PTYPE_L2_MASK))
			m->packet_type |= RTE_PTYPE_L2_ETHER;
	}
	inner_l4type = (rx_desc->wb.cmd & MCE_RX_INNER_L4TYPE_MASK) >>
		       MCE_RX_INNER_L4TYPE_S;
	l4type = (rx_desc->wb.cmd & MCE_RX_OUT_L4TYPE_MASK) >>
		 MCE_RX_OUT_L4TYPE_S;

	if (inner_l4type) {
		switch (inner_l4type) {
		case MCE_RX_L4_FRAG:
			m->packet_type |= RTE_PTYPE_INNER_L4_FRAG;
			break;
		case MCE_RX_L4_UDP:
			m->packet_type |= RTE_PTYPE_INNER_L4_UDP;
			break;
		case MCE_RX_L4_TCP:
			m->packet_type |= RTE_PTYPE_INNER_L4_TCP;
			break;
		case MCE_RX_L4_SCTP:
			m->packet_type |= RTE_PTYPE_INNER_L4_SCTP;
			break;
		case MCE_RX_L4_ICMP:
			m->packet_type |= RTE_PTYPE_INNER_L4_ICMP;
			break;
		case MCE_RX_L4_PAY:
			m->packet_type |= RTE_PTYPE_INNER_L4_NONFRAG;
			break;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		case MCE_RX_L4_UDP_ESP:
			m->packet_type |= RTE_PTYPE_INNER_L4_UDP;
			m->packet_type |= RTE_PTYPE_TUNNEL_ESP;
			break;
		case MCE_RX_L4_ESP:
			m->packet_type |= RTE_PTYPE_TUNNEL_ESP;
			break;
#endif
		default:
			break;
		}
	}
	if (l4type) {
		switch (l4type) {
		case MCE_RX_L4_FRAG:
			m->packet_type |= RTE_PTYPE_L4_FRAG;
			break;
		case MCE_RX_L4_UDP:
			m->packet_type |= RTE_PTYPE_L4_UDP;
			break;
		case MCE_RX_L4_TCP:
			m->packet_type |= RTE_PTYPE_L4_TCP;
			break;
		case MCE_RX_L4_SCTP:
			m->packet_type |= RTE_PTYPE_L4_SCTP;
			break;
		case MCE_RX_L4_ICMP:
			m->packet_type |= RTE_PTYPE_L4_ICMP;
			break;
		case MCE_RX_L4_PAY:
			m->packet_type |= RTE_PTYPE_L4_NONFRAG;
			break;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		case MCE_RX_L4_UDP_ESP:
			m->packet_type |= RTE_PTYPE_L4_UDP;
			m->packet_type |= RTE_PTYPE_TUNNEL_ESP;
			break;
		case MCE_RX_L4_ESP:
			m->packet_type |= RTE_PTYPE_TUNNEL_ESP;
			break;
#endif
		}
	}
	tun_type = (rx_desc->wb.cmd & MCE_RX_TUNNEL_TYPE_MASK) >>
		   MCE_RX_TUNNEL_TYPE_S;
	if (tun_type) {
		switch (tun_type) {
		case MCE_RX_TUN_VXLAN:
			m->packet_type |= RTE_PTYPE_TUNNEL_VXLAN;
			break;
		case MCE_RX_TUN_GRE:
			if (rx_desc->wb.cmd & MCE_RX_INNER_L2_ETHER)
				m->packet_type |= RTE_PTYPE_TUNNEL_NVGRE;
			else
				m->packet_type |= RTE_PTYPE_TUNNEL_GRE;
			break;
		case MCE_RX_TUN_GENEVE:
			m->packet_type |= RTE_PTYPE_TUNNEL_GENEVE;
			break;
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		case MCE_RX_TUN_GTP_U:
			m->packet_type |= RTE_PTYPE_TUNNEL_GTPU;
			break;
		case MCE_RX_TUN_GTP_C:
			m->packet_type |= RTE_PTYPE_TUNNEL_GTPC;
			break;
#endif
		case MCE_RX_TUN_IPINIP:
			m->packet_type |= RTE_PTYPE_TUNNEL_IP;
			break;
		case MCE_RX_TUN_MPLS_UDP:
			m->packet_type |= RTE_PTYPE_TUNNEL_MPLS_IN_UDP;
			break;
		default:
			break;
		}
	}
#else
	uint32_t ptypes = (rx_desc->wb.cmd & 0xFFFFFC);

	m->packet_type = mce_get_rx_parse_ptype(ptypes >> 2);
#endif
	mce_dev_rx_cksum(m, rx_desc);
	if (rx_desc->wb.cmd & MCE_RX_PTP) {

		rxq->time_low = rx_desc->wb.stamp.timestamp_l;
		rxq->time_high = rx_desc->wb.stamp.timestamp_h;
		m->timesync = rxq->attr.queue_id;
		m->ol_flags |= RTE_MBUF_F_RX_IEEE1588_PTP;
		m->ol_flags |= RTE_MBUF_F_RX_IEEE1588_TMST;
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		if (rxq->ts_flag > 0) {
			uint64_t ts_ns;
			ts_ns = ((uint64_t)rxq->time_high << 32) | rxq->time_low;
			*RTE_MBUF_DYNFIELD(m, rxq->ts_offset,
					rte_mbuf_timestamp_t *) = ts_ns;
		}
#endif
	}
#ifdef MCE_DEBUG_RX_DESC
	printf("rx_desc->rss_hash 0x%.2x\n", rx_desc->wb.rss_hash);
	printf("RX_DESC-cmd 0x%.2x\n", rx_desc->wb.cmd);

	printf("rx_desc->vlan_tag1 0x%.2x\n", rx_desc->wb.vlan_tag1);
	printf("rx_desc->vlan_tag2 0x%.2x\n", rx_desc->wb.vlan_tag2);
	printf("rx_desc->vlan_tag3 0x%.2x\n", rx_desc->wb.stamp.timestamp_l);
	printf("rx_desc->mark_id 0x%.2x\n", rx_desc->wb.mark_id);
	printf("rx_desc->err_cmd 0x%.2x\n", rx_desc->wb.err_cmd);
	print_packet_info(m);
	rte_pktmbuf_dump(stdout, m, 128);
#endif
}

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static int mce_repr_rxq_enqueue(struct mce_rx_queue *rxq, struct rte_mbuf *rxm)
{
	struct mce_vf_representor *repr;
	struct mce_repr_rxq *rep_rxq;
	struct mce_pf *pf = NULL;
	struct rte_mbuf *pkts[32];
	struct rte_eth_dev *dev;
	uint16_t repr_id = 0;
	int burst = 0;

	repr_id = *RTE_MBUF_DYNFIELD(rxm, rxq->mce_sport_dynfield_offset,
				     uint16_t *);
	dev = &rte_eth_devices[rxq->attr.rte_pid];
	pf = MCE_DEV_TO_PF(dev);
	repr = pf->vf_reprs[repr_id];
	rep_rxq = repr->rxqs[0];
	rxm->port = repr->port_id;
	rxm->ol_flags &= ~rxq->mce_sport_rx_dynflag;

	pkts[0] = rxm;

	burst = rte_ring_mp_enqueue_burst(rep_rxq->ring, (void **)(&pkts), 1,
					  NULL);
	if (burst != 1) {
		rxq->rep_stats.rx_missed += 1;
		rte_pktmbuf_free_bulk(pkts, 1);
	} else {
		rxq->rep_stats.ipackets += 1;
		rxq->rep_stats.ibytes += rxm->pkt_len;
	}

	return 0;
}
#endif

static uint16_t mce_scattered_rx(void *rx_queue, struct rte_mbuf **rx_pkts,
				 uint16_t nb_pkts)
{
	/* 1.Recv first pkts */
	/* 2.According the EOP flag to know segment pkts
	 * We dno't let segment pkts point to rx_pkts[n]
	 * We will store it into mbuf->next with multitle descriptor
	 * so we must manage the segment abort the descriptor
	 */
	/* 3.point the segment mbuf to rx_pkts[0], multitle segment pkt
	 * just regard as one pkt 4.clean the segment-descriptor manage
	 * entry
	 */
	/* 5* update rx-tail judge by the free-threshold */
	struct mce_rx_queue *rxq = (struct mce_rx_queue *)rx_queue;
	volatile union mce_rx_desc *bd_ring = rxq->rx_bdr;
	struct mce_rxsw_entry *sw_ring = rxq->sw_ring;
	struct rte_mbuf *first_seg = rxq->pkt_first_seg;
	struct rte_mbuf *last_seg = rxq->pkt_last_seg;
	volatile union mce_rx_desc *rxbd;
	volatile union mce_rx_desc rxd;
	struct mce_rxsw_entry *rxe;
	struct rte_mbuf *rxm;
	uint16_t rx_id;
	uint16_t nb_rx = 0;
	uint16_t nb_hold = 0;
	uint16_t rx_pkt_len;
	uint32_t rx_status;

	rx_id = rxq->rx_tail;
	if (rxq->rxrearm_nb > rxq->rx_free_thresh)
		mce_refill_rx_ring(rxq);
	while (nb_rx < nb_pkts) {
		rxbd = &bd_ring[rx_id];
		rx_status = rxbd->wb.cmd;
		if (!(rx_status & MCE_RX_DD))
			break;
		rxd = *rxbd;

		nb_hold++;
		rxe = &sw_ring[rx_id];

		rx_id = (rx_id + 1) & rxq->attr.nb_desc_mask;
		rte_prefetch0(sw_ring[rx_id].mbuf);

		if ((rx_id & 0x3) == 0) {
			rte_prefetch0(&bd_ring[rx_id]);
			rte_prefetch0(&sw_ring[rx_id]);
		}
		rxm = rxe->mbuf;
		rxe->mbuf = NULL;
		rx_pkt_len = rxd.wb.len_pad;
		rxm->data_len = rx_pkt_len;
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxbd->wb.cmd &= ~MCE_RX_DD;
		if (!first_seg) {
			/* first segment pkt */
			first_seg = rxm;
			first_seg->nb_segs = 1;
			first_seg->pkt_len = rx_pkt_len;
		} else {
			/* follow-up segment pkt */
			first_seg->pkt_len =
				(uint16_t)(first_seg->pkt_len + rx_pkt_len);
			first_seg->nb_segs++;
			last_seg->next = rxm;
		}
		if (!(rx_status & MCE_RX_EOP)) {
			last_seg = rxm;
			continue;
		}
		rxm->next = NULL;
		first_seg->port = rxq->attr.rte_pid;
		first_seg->pkt_len -= rxq->strip_len;
		mce_dev_rx_parse(rxq, &rxd, first_seg);
		if (first_seg->nb_segs > 5) {
			struct rte_mbuf *seg = NULL;
			struct rte_mbuf *next_seg = NULL;
			uint16_t nb_segs = first_seg->nb_segs;
			int i = 0;

			seg = first_seg;
			for (i = 0; i < nb_segs; i++) {
				next_seg = seg->next;
				rte_pktmbuf_free_seg(seg);
				seg = next_seg;
			}
			rxq->rx_desc_drop += 2;
			first_seg = NULL;
			last_seg = NULL;
			continue;
		}
#ifdef MCE_DEBUG_PCAP
		if (rxbd->wb.err_cmd & MCE_RX_CKSUM_ERR_MASK || first_seg->ol_flags & (RTE_MBUF_F_RX_IP_CKSUM_BAD || RTE_MBUF_F_RX_L4_CKSUM_BAD)) {
			struct rte_mbuf *mbuf_clones[32];
			struct rte_mbuf *mbuf = NULL;
			int i = 0;

			printf("cksum bad\n");
			for (i = 0; i < 1; i++) {
				struct rte_mbuf *mc = NULL;
				char name[128] = "";

				mbuf = (struct rte_mbuf *)first_seg;
				snprintf(name, 128, "n20-debug-rxq%d",
						rxq->attr.rte_pid);
				mc = rte_pcapng_copy(mbuf->port, 0, mbuf, n20_pkt_mp,
						mbuf->pkt_len,
						RTE_PCAPNG_DIRECTION_IN,
						(const char *)name);
				if (mc == NULL)
					break;
				mbuf_clones[i] = mc;
			}
			rte_pcapng_write_packets(n20_pcapng_fd, mbuf_clones, i);
			rte_pktmbuf_free_bulk(mbuf_clones, i);
	}
#endif
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
		if (rxq->mce_sport_rx_dynflag & first_seg->ol_flags) {
			mce_repr_rxq_enqueue(rxq, first_seg);
		} else {
			rx_pkts[nb_rx++] = first_seg;
		}
#else
		rx_pkts[nb_rx++] = first_seg;
#endif
#ifdef MCE_DEBUG_RSS
		mce_calc_rss(rxq, first_seg);
#endif
		rte_prefetch0(
			RTE_PTR_ADD(first_seg->buf_addr, first_seg->data_off));
		first_seg = NULL;
	}
	/* update sw record point */
	rxq->rx_tail = rx_id;
	rxq->pkt_first_seg = first_seg;
	rxq->pkt_last_seg = last_seg;

	rxq->rxrearm_nb = rxq->rxrearm_nb + nb_hold;

	return nb_rx;
}

/**
 * @brief Receive packets from an RX queue into an array of mbufs.
 *
 * This function polls the RX descriptor ring, converts completed descriptors
 * into `rte_mbuf` entries and returns the number of packets received.
 *
 * @param rx_queue Pointer to the RX queue context (struct mce_rx_queue).
 * @param rx_pkts Array to be filled with received `rte_mbuf` pointers.
 * @param nb_pkts Maximum number of packets to receive (will be aligned).
 *
 * @return Number of packets actually received.
 */
uint16_t mce_rx_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
			  uint16_t nb_pkts)
{
	struct mce_rxsw_entry *rx_swbd;
	struct mce_rx_queue *rxq = (struct mce_rx_queue *)rx_queue;
	uint32_t state_cmd[CACHE_FETCH_RX];
	uint32_t pkt_len[CACHE_FETCH_RX] = { 0 };
	volatile union mce_rx_desc *rxbd;
	struct rte_mbuf *nmb;
	int nb_dd, nb_rx = 0;
	int i, j;

	rxbd = &rxq->rx_bdr[rxq->rx_tail];
	rte_prefetch0(rxbd);
	if (rxq->rxrearm_nb > rxq->rx_free_thresh)
		mce_refill_rx_ring(rxq);
	if (!(rxbd->wb.cmd & rte_cpu_to_le_32(MCE_CMD_DD)))
		return 0;
	nb_pkts = RTE_MIN(nb_pkts, MCE_RX_MAX_BURST_SIZE);
	rx_swbd = &rxq->sw_ring[rxq->rx_tail];
	for (i = 0; i < nb_pkts; i += CACHE_FETCH_RX, rxbd += CACHE_FETCH_RX,
	    rx_swbd += CACHE_FETCH_RX) {
		for (j = 0; j < CACHE_FETCH_RX; j++)
			state_cmd[j] = rxbd[j].wb.cmd;
		rte_smp_rmb();

		for (nb_dd = 0;
		     nb_dd < CACHE_FETCH_RX &&
		     (state_cmd[nb_dd] & rte_cpu_to_le_32(MCE_CMD_DD));
		     nb_dd++)
			;
		for (j = 0; j < nb_dd; j++)
			pkt_len[j] = rxbd[j].wb.len_pad;
		for (j = 0; j < nb_dd; ++j) {
			nmb = rx_swbd[j].mbuf;
			nmb->data_len = pkt_len[j];
			nmb->pkt_len = pkt_len[j];
			nmb->nb_segs = 1;
			nmb->packet_type = 0;
			nmb->ol_flags = 0;
			nmb->data_off = RTE_PKTMBUF_HEADROOM;
			nmb->port = rxq->attr.rte_pid;
			mce_dev_rx_parse(rxq, &rxbd[j], nmb);
#ifdef MCE_DEBUG_RSS
			mce_calc_rss(rxq, nmb);
#endif
		}
		for (j = 0; j < nb_dd; ++j) {
			rx_pkts[i + j] = rx_swbd[j].mbuf;
			rx_pkts[i + j]->hash.rss =
				rte_le_to_cpu_32(rxbd[j].wb.rss_hash);
			rx_pkts[i + j]->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
		}
		nb_rx += nb_dd;
		rxq->nb_rx_free -= nb_dd;
		if (nb_dd != CACHE_FETCH_RX)
			break;
	}
	rxq->rx_tail = (rxq->rx_tail + nb_rx) & rxq->attr.nb_desc_mask;
	rxq->rxrearm_nb = rxq->rxrearm_nb + nb_rx;

	return nb_rx;
}

static __rte_always_inline int mce_clean_tx_ring(struct mce_tx_queue *txq)
{
#define MCE_TX_BURST_FREE (32)
	struct rte_mbuf *free[MCE_TX_BURST_FREE];
	struct mce_txsw_entry *tx_swbd;
	uint16_t clean_id = 0;
	uint16_t nb_free = 0;
	struct rte_mbuf *m;
	uint16_t clean = 0;
	uint32_t hw_head;
	uint16_t j;
	uint16_t ntc, ntu;
	uint32_t can_clean;
	bool cycle_back = 1;
	uint16_t head = 0;
	int flag = 0;

	hw_head = *txq->hw_head;
	cycle_back = (hw_head & RTE_BIT32(16)) ? 1 : 0;
	head = hw_head & txq->attr.nb_desc_mask;
	ntc = txq->next_to_clean;
	ntu = txq->tx_tail;
	if (ntc > ntu) {
		/* software rollback */
		if (head == ntu && cycle_back) {
			can_clean = head + txq->attr.nb_desc - ntc - 1;
			if (can_clean == 0)
				flag = 3;
		} else {
			if (head > ntu) {
				can_clean = head - ntc;
				if (can_clean == 0)
					flag = 4;
			} else {
				can_clean = head + txq->attr.nb_desc - ntc - 1;
				if (can_clean == 0)
					flag = 2;
			}
		}
	} else {
		can_clean = head - ntc;
		if (can_clean == 0)
			flag = 1;
	}
	RTE_SET_USED(flag);
	uint32_t fff = 0;
	fff = can_clean;
	can_clean = RTE_ALIGN_FLOOR(can_clean, 4);
	if (can_clean == 0) {
		if (fff) {
			tx_swbd = &txq->sw_ring[txq->next_to_clean];
			clean_id = txq->next_to_clean;
			for (j = 0; j < fff; j++) {
				m = tx_swbd->mbuf;
				tx_swbd->mbuf = NULL;
				rte_pktmbuf_free_seg(m);
				clean_id = (clean_id + 1) &
					   txq->attr.nb_desc_mask;
				tx_swbd = &txq->sw_ring[clean_id];
			}
			txq->nb_tx_free = (txq->nb_tx_free + fff);
			txq->next_to_clean = clean_id;
			return fff;
		}
		return 0;
	}
#if 0
	if (can_clean > txq->tx_free_thresh)
		printf("can_caln max %d\n", can_clean);
	clean = RTE_MIN(can_clean, txq->tx_free_thresh);
#endif
	clean = can_clean;
	clean_id = txq->next_to_clean;
	tx_swbd = &txq->sw_ring[txq->next_to_clean];
	for (j = 0; j < clean; j++) {
		m = rte_pktmbuf_prefree_seg(tx_swbd->mbuf);
		tx_swbd->mbuf = NULL;
		if (unlikely(m == NULL))
			continue;
		if (nb_free >= MCE_TX_BURST_FREE ||
		    (nb_free > 0 && m->pool != free[0]->pool)) {
			rte_mempool_put_bulk(free[0]->pool, (void **)free,
					     nb_free);
			nb_free = 0;
		}
		clean_id = (clean_id + 1) & txq->attr.nb_desc_mask;
		tx_swbd = &txq->sw_ring[clean_id];
		free[nb_free++] = m;
	}
	if (nb_free)
		rte_mempool_put_bulk(free[0]->pool, (void **)free, nb_free);
	txq->nb_tx_free = (txq->nb_tx_free + clean);
	txq->next_to_clean = clean_id;

	return clean;
}

/**
 * @brief Transmit packets on a TX queue using the simple scalar path.
 *
 * Populates TX descriptors for the provided `rte_mbuf` array and notifies
 * the hardware by updating the tail register. Handles basic resource checks
 * and updates transmit statistics.
 *
 * @param tx_queue Pointer to the TX queue context (struct mce_tx_queue).
 * @param tx_pkts Array of `rte_mbuf` pointers to transmit.
 * @param nb_pkts Number of packets to attempt to transmit.
 *
 * @return Number of packets actually queued for transmission.
 */
uint16_t mce_xmit_simple(void *tx_queue, struct rte_mbuf **tx_pkts,
			 uint16_t nb_pkts)
{
	struct mce_tx_queue *txq = (struct mce_tx_queue *)tx_queue;
	volatile union mce_tx_desc *txbd;
	struct mce_txsw_entry *tx_swbd;
	uint64_t phy;
	uint16_t start;
	int retry = 0;
	int ret = 0;
	uint16_t i;

#ifdef RX_PERFORMANCE_DEBUG
	rte_mempool_put_bulk(tx_pkts[0]->pool, (void **)tx_pkts, nb_pkts);

	return nb_pkts;
#endif
	if (txq->nb_tx_free < txq->tx_free_thresh) {
try_gain:
		ret = mce_clean_tx_ring(txq);
		if (ret == 0 && retry < 10000) {
			retry++;
			goto try_gain;
		}
	}
	nb_pkts = RTE_MIN(txq->nb_tx_free, nb_pkts);
	if (!nb_pkts) {
		txq->stats.tx_ring_full++;
		return 0;
	}

	start = nb_pkts;
	i = txq->tx_tail;

	while (nb_pkts--) {
		txbd = &txq->tx_bdr[i];
		tx_swbd = &txq->sw_ring[i];
		tx_swbd->mbuf = *tx_pkts++;
		phy = rte_cpu_to_le_64(rte_mbuf_data_iova(tx_swbd->mbuf));
		txbd->d.pkt_addr = phy;

		txbd->d.qword1.length = tx_swbd->mbuf->data_len;
		txbd->d.qword6.cmd = MCE_CMD_EOP;
		txq->stats.obytes += tx_swbd->mbuf->data_len;

		i = (i + 1) & txq->attr.nb_desc_mask;
	}
	txq->nb_tx_free -= start;
	txq->tx_tail = i;

	rte_wmb();
	MCE_REG_ADDR_WRITE(txq->tx_tailreg, 0, i);

	return start;
}

static __rte_always_inline uint16_t
mce_xmit_simple_burst(void *_txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint16_t nb_tx = 0;
	uint32_t tx_burst;
	uint16_t retry = 0;
	uint32_t idx = 0;
	struct mce_tx_queue *txq = (struct mce_tx_queue *)_txq;

	if (unlikely(!txq))
		return 0;
	while (nb_tx < nb_pkts) {
		tx_burst = (uint16_t)RTE_MIN(nb_pkts - nb_tx, txq->nb_tx_free);
		idx = mce_xmit_simple(_txq, &tx_pkts[nb_tx], tx_burst);
		nb_tx += idx;
		retry++;
		if (retry >= 32) {
			txq->stats.tx_full_drop += nb_pkts - nb_tx;
			break;
		}
	}
	if (retry > 4)
		printf("return %d\n", retry);

	return nb_tx;
}

static inline bool mce_valid_tx_offload(uint64_t flags)
{
	static uint64_t mask =
		RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG |
		RTE_MBUF_F_TX_QINQ | RTE_MBUF_F_TX_VLAN |
		RTE_MBUF_F_TX_TUNNEL_VXLAN | RTE_MBUF_F_TX_TUNNEL_GRE |
		RTE_MBUF_F_TX_TUNNEL_GENEVE | RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE |
		RTE_MBUF_F_TX_L4_MASK | RTE_MBUF_F_TX_IP_CKSUM |
		RTE_MBUF_F_TX_OUTER_IP_CKSUM | RTE_MBUF_F_TX_OUTER_UDP_CKSUM |
		RTE_MBUF_F_TX_IEEE1588_TMST;
	return (flags & mask) ? 1 : 0;
}

static __rte_always_inline uint16_t mce_clean_txq(struct mce_tx_queue *txq)
{
	uint16_t last_desc_cleaned = txq->last_desc_cleaned;
	struct mce_txsw_entry *sw_ring = txq->sw_ring;
	volatile union mce_tx_desc *txbd;
	uint16_t desc_to_clean_to;
	uint16_t nb_tx_to_clean;

	desc_to_clean_to = (uint16_t)(last_desc_cleaned + txq->tx_rs_thresh);
	desc_to_clean_to = desc_to_clean_to & txq->attr.nb_desc_mask;

	desc_to_clean_to = sw_ring[desc_to_clean_to].last_id;
	txbd = &txq->tx_bdr[desc_to_clean_to];
	if (!(txbd->d.qword6.cmd & MCE_CMD_DD))
		return txq->nb_tx_free;

	if (last_desc_cleaned > desc_to_clean_to)
		nb_tx_to_clean =
			(uint16_t)((txq->attr.nb_desc - last_desc_cleaned) +
				   desc_to_clean_to);
	else
		nb_tx_to_clean =
			(uint16_t)(desc_to_clean_to - last_desc_cleaned);

	txbd->d.qword6.cmd = 0;

	txq->last_desc_cleaned = desc_to_clean_to;
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + nb_tx_to_clean);

	return txq->nb_tx_free;
}

static inline uint32_t mce_cal_tso_seg(struct rte_mbuf *mbuf)
{
	uint32_t hdr_len;

	hdr_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;

	hdr_len += (mbuf->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) ?
			   mbuf->outer_l2_len + mbuf->outer_l3_len :
			   0;

	return (mbuf->tso_segsz) ? mbuf->tso_segsz : hdr_len;
}

#ifdef MCE_DEBUG_TX_DESC
static void mce_dump_tx_desc(volatile union mce_tx_desc *tx_desc)
{
	uint32_t o_l4_type, l4_type;
	uint32_t o_l3_type, l3_type;
	uint32_t tunnel_type = 0;
	uint32_t in_l3l4_type;
	uint32_t vlan_inset = 0;
	uint32_t cmd;

	cmd = tx_desc->d.qword6.cmd;
	printf("#######################################################"
	       "########"
	       "####"
	       "########\n");
	printf("sizoeof tx_desc len %" PRIu64 "\n", sizeof(*tx_desc));
	printf("tx_desc->d.pkt_addr 0x%.2lx\n", tx_desc->d.pkt_addr);
	printf("tx_desc->d.qword1 0x%.2x\n",
	       *((uint32_t *)((uintptr_t)(&tx_desc->d.qword1))));
	printf("tx_desc->d.qword2 0x%.2x\n",
	       *((uint32_t *)((uintptr_t)(&tx_desc->d.qword2))));
	printf("tx_desc->d.qword3 0x%.2x\n",
	       *((uint32_t *)((uintptr_t)(&tx_desc->d.qword3))));
	printf("tx_desc->d.qword4 0x%.2x\n",
	       *((uint32_t *)((uintptr_t)(&tx_desc->d.qword4))));
	printf("tx_desc->d.qword5 0x%.2x\n",
	       *((uint32_t *)((uintptr_t)(&tx_desc->d.qword5))));
	printf("tx_desc->d.qword6 0x%.2x\n",
	       *((uint32_t *)((uintptr_t)(&tx_desc->d.qword6))));
	if (cmd & MCE_TX_TSO_EN) {
		printf("tx_desc tso en\n");
		printf("mss is %d\n", tx_desc->d.qword4.mss);
	}
	if (cmd & MCE_TX_O_L4_TYPE) {
		o_l4_type = (cmd & MCE_TX_O_L4_TYPE) >> MCE_TX_O_L4_TYPE_S;
		switch (o_l4_type) {
		case MCE_TX_L4_SCTP:
			printf("tx_desc O_l4_type SCTP\n");
			break;
		case MCE_TX_L4_TCP:
			printf("tx_desc O_l4_type TCP\n");
			break;
		case MCE_TX_L4_UDP:
			printf("tx_desc O_l4_type UDP\n");
			break;
		}
	}
	if (cmd & MCE_TX_O_L3_TYPE) {
		o_l3_type = (cmd & MCE_TX_O_L3_TYPE) >> MCE_TX_O_L3_TYPE_S;
		switch (o_l3_type) {
		case MCE_TX_L3_IPV4:
			printf("tx_desc O_l3_type ipv4\n");
			break;
		case MCE_TX_L3_IPV6:
			printf("tx_desc O_l3_type ipv6\n");
			break;
		}
	}
	in_l3l4_type = tx_desc->d.qword5.in_l3l4_type;
	printf("in_l3l4_type 0x%.2x\n", in_l3l4_type);

	if (in_l3l4_type & MCE_TX_I_L4_TYPE) {
		l4_type = (in_l3l4_type & MCE_TX_I_L4_TYPE) >>
			  MCE_TX_I_L4_TYP_S;
		switch (l4_type) {
		case MCE_TX_L4_SCTP:
			printf("tx_desc I_l4_type SCTP\n");
			break;
		case MCE_TX_L4_TCP:
			printf("tx_desc I_l4_type TCP\n");
			break;
		case MCE_TX_L4_UDP:
			printf("tx_desc I_l4_type UDP\n");
			break;
		}
	}
	if (in_l3l4_type & MCE_TX_I_L3_TYPE) {
		l3_type = (in_l3l4_type & MCE_TX_I_L3_TYPE);
		switch (l3_type) {
		case MCE_TX_L3_IPV4:
			printf("tx_desc I_l3_type ipv4\n");
			break;
		case MCE_TX_L3_IPV6:
			printf("tx_desc I_l3_type ipv6\n");
			break;
		}
	}
	if (cmd & MCE_TX_CKSUM_OF) {
		if (cmd & MCE_TX_I_L4_CK_EN)
			printf("tx_desc_cksum hw_i_l4_offload_en\n");
		if (cmd & MCE_TX_I_L3_CK_EN)
			printf("tx_desc_cksum hw_i_l3_offload_en\n");
		if (cmd & MCE_TX_O_L4_CK_EN)
			printf("tx_desc_cksum hw_o_l4_offload_en\n");
		if (cmd & MCE_TX_O_L3_CK_EN)
			printf("tx_desc_cksum hw_o_l3_offload_en\n");
	}
	if (cmd & MCE_TX_TUN_TYPE) {
		tunnel_type = (cmd & MCE_TX_TUN_TYPE) >> MCE_TX_TUN_TYPE_S;
		switch (tunnel_type) {
		case MCE_TX_TUN_VXLAN:
			printf("tx_desc tunnel type is vxlan\n");
			break;
		case MCE_TX_TUN_GRE:
			printf("tx_desc tunnel type is gre\n");
			break;
		case MCE_TX_TUN_GENEVE:
			printf("tx_desc tunnel type is geneve\n");
			break;
		case MCE_TX_TUN_GTP_U:
			printf("tx_desc tunnel type is gtp_u\n");
			break;
		case MCE_TX_TUN_GTP_C:
			printf("tx_desc tunnel type is gtp_c\n");
			break;
		case MCE_TX_TUN_ESP:
			printf("tx_desc tunnel type is esp\n");
			break;
		case MCE_TX_TUN_UDP_ESP:
			printf("tx_desc tunnel type is udp-esp\n");
			break;
		}
	}
	if (cmd & MCE_TX_VLAN_INSET) {
		vlan_inset = (cmd & MCE_TX_VLAN_INSET) >> MCE_TX_VLAN_INSET_S;
		printf("tx_desc inset vlan %d\n", vlan_inset);
	}
	if (cmd & MCE_TX_VLAN_O_EN)
		printf("tx_desc vlan inset qword6 cmd en\n");
	printf("tx_desc packet length %d\n", tx_desc->d.qword1.length);
	printf("tx_desc out_maclen %d ip_len %ld\n",
	       tx_desc->d.qword1.macip_len >> MCE_MAC_LEN_S,
	       tx_desc->d.qword1.macip_len & GENMASK_U32(8, 0));
	printf("tx_desc inner_maclen %d ip_len %ld\n",
	       tx_desc->d.qword2.in_macip_len >> MCE_MAC_LEN_S,
	       tx_desc->d.qword2.in_macip_len & GENMASK_U32(8, 0));
	printf("tx_desc qword4 l4_tun_len  0x%.2x\n",
	       tx_desc->d.qword4.l4_tun_len);
	printf("tx_desc qword4  tunnel_len %d l4_len %ld\n",
	       tx_desc->d.qword4.l4_tun_len >> MCE_TX_TUN_LEN_S,
	       tx_desc->d.qword4.l4_tun_len & GENMASK_U32(7, 0));
	printf("tx_desc insert vlan0 %d vlan1 %d vlan2 %d\n",
	       tx_desc->d.qword2.vlan0, tx_desc->d.qword3.vlan1,
	       tx_desc->d.qword3.vlan2);
	printf("#######################################################"
	       "########"
	       "####"
	       "########\n");
}
#endif

__attribute__((hot)) static inline void
mce_setup_csum_offload(struct rte_mbuf *m, volatile union mce_tx_desc *tx_desc)
{
	uint64_t flags = m->ol_flags;
	struct rte_gre_hdr *gre_hdr;
	uint32_t tunnel_hdr_len = 0;
	uint32_t tunnel_len = 0;
	uint32_t cksum_offload = 0;
	uint32_t tunnel_type = 0;
	uint32_t l4_type, o_l4_type;
	uint32_t l3_type, o_l3_type;
	bool tso = false;
#define MCE_TX_L3_MASK	   (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IPV6)
#define MCE_TX_OUT_L3_MASK (RTE_MBUF_F_TX_OUTER_IPV4 | RTE_MBUF_F_TX_OUTER_IPV6)
/* Ethernet over GRE */
#define MCE_GRE_TUN_ETH_BR (0x6558)
#define MCE_ETH_HDR_LEN	   (14)
#define GRE_TUNNEL_KEY	   (4)
#define GRE_TUNNEL_SEQ	   (4)
#define GRE_TUNNEL_CKSUM   (4)
	switch (flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
	case RTE_MBUF_F_TX_TUNNEL_VXLAN:
		tunnel_hdr_len = sizeof(struct rte_udp_hdr) +
				 sizeof(struct rte_vxlan_hdr);
		tunnel_len = tunnel_hdr_len + m->outer_l2_len + m->outer_l3_len;
		tunnel_type = MCE_TX_TUN_VXLAN;
		break;
	case RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE:
		tunnel_hdr_len = sizeof(struct rte_udp_hdr) +
				 sizeof(struct rte_vxlan_gpe_hdr);
		tunnel_len = tunnel_hdr_len + m->outer_l2_len + m->outer_l3_len;
		tunnel_type = MCE_TX_TUN_VXLAN;
		break;
	case RTE_MBUF_F_TX_TUNNEL_GRE:
		gre_hdr = rte_pktmbuf_mtod_offset(m, struct rte_gre_hdr *,
						  m->outer_l2_len +
							  m->outer_l3_len);
		tunnel_hdr_len = sizeof(struct rte_gre_hdr);
		if (gre_hdr->k)
			tunnel_hdr_len += GRE_TUNNEL_KEY;
		if (gre_hdr->s)
			tunnel_hdr_len += GRE_TUNNEL_SEQ;
		if (gre_hdr->c)
			tunnel_hdr_len += GRE_TUNNEL_CKSUM;
		tunnel_len = tunnel_hdr_len + m->outer_l2_len + m->outer_l3_len;
		tunnel_type = MCE_TX_TUN_GRE;
		break;
	case RTE_MBUF_F_TX_TUNNEL_GENEVE:
		tunnel_hdr_len = sizeof(struct rte_udp_hdr) +
				 sizeof(struct rte_geneve_hdr);
		tunnel_len = tunnel_hdr_len + m->outer_l2_len + m->outer_l3_len;
		tunnel_type = MCE_TX_TUN_GENEVE;
		break;
	case RTE_MBUF_F_TX_TUNNEL_GTP:
		tunnel_hdr_len =
			sizeof(struct rte_udp_hdr) + sizeof(struct rte_gtp_hdr);
		tunnel_len = tunnel_hdr_len + m->outer_l2_len + m->outer_l3_len;
		tunnel_type = MCE_TX_TUN_GTP_U;
		break;
	case RTE_MBUF_F_TX_TUNNEL_ESP:
		tunnel_hdr_len =
			sizeof(struct rte_udp_hdr) + sizeof(struct rte_esp_hdr);
		tunnel_len = tunnel_hdr_len + m->outer_l2_len + m->outer_l3_len;
		tunnel_type = MCE_TX_TUN_ESP;
		break;
	default:
		tunnel_len = 0;
	}

	switch (flags & RTE_MBUF_F_TX_L4_MASK) {
	case RTE_MBUF_F_TX_TCP_CKSUM:
		l4_type = MCE_TX_L4_TCP;
		break;
	case RTE_MBUF_F_TX_UDP_CKSUM:
		l4_type = MCE_TX_L4_UDP;
		break;
	case RTE_MBUF_F_TX_SCTP_CKSUM:
		l4_type = MCE_TX_L4_SCTP;
		break;
	default:
		l4_type = 0;
	}
	switch (flags & MCE_TX_L3_MASK) {
	case RTE_MBUF_F_TX_IPV4:
		l3_type = MCE_TX_L3_IPV4;
		break;
	case RTE_MBUF_F_TX_IPV6:
		l3_type = MCE_TX_L3_IPV6;
		break;
	default:
		l3_type = 0;
	}
	if (flags & RTE_MBUF_F_TX_TCP_SEG || flags & RTE_MBUF_F_TX_UDP_SEG) {
		tx_desc->d.qword4.mss = mce_cal_tso_seg(m);
		tx_desc->d.qword6.cmd |= MCE_TX_TSO_EN;
		if (flags & RTE_MBUF_F_TX_TCP_SEG)
			l4_type = MCE_TX_L4_TCP;
		else
			l4_type = MCE_TX_L4_UDP;
		tso = true;
	}
	if (tunnel_type) {
		tx_desc->d.qword5.in_l3l4_type = (l4_type << MCE_TX_I_L4_TYP_S);
		tx_desc->d.qword5.in_l3l4_type |= (l3_type);
		tx_desc->d.qword2.in_macip_len = (m->l2_len - tunnel_hdr_len)
						 << MCE_MAC_LEN_S;
		tx_desc->d.qword2.in_macip_len |= m->l3_len;
		tx_desc->d.qword4.l4_tun_len |=
			((tunnel_len << MCE_TX_TUN_LEN_S) / 2);
		tx_desc->d.qword4.l4_tun_len |= m->l4_len;
		tx_desc->d.qword6.cmd |= (tunnel_type << MCE_TX_TUN_TYPE_S);
		if (l4_type)
			cksum_offload |= MCE_TX_I_L4_CK_EN;
		if (l3_type && (flags & RTE_MBUF_F_TX_IP_CKSUM))
			cksum_offload |= MCE_TX_I_L3_CK_EN;
		switch (flags & MCE_TX_OUT_L3_MASK) {
		case RTE_MBUF_F_TX_OUTER_IPV4:
			o_l3_type = MCE_TX_L3_IPV4;
			break;
		case RTE_MBUF_F_TX_OUTER_IPV6:
			o_l3_type = MCE_TX_L3_IPV6;
			break;
		default:
			o_l3_type = 0;
		}
		if (tso) {
			cksum_offload |= MCE_TX_O_L4_CK_EN;
			cksum_offload |= MCE_TX_O_L3_CK_EN;
			cksum_offload |= MCE_TX_I_L4_CK_EN;
			cksum_offload |= MCE_TX_I_L3_CK_EN;
			o_l4_type = MCE_TX_L4_UDP;
		} else {
			if (o_l3_type && (flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM))
				cksum_offload |= MCE_TX_O_L3_CK_EN;
			if (flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM) {
				o_l4_type = MCE_TX_L4_UDP;
				cksum_offload |= MCE_TX_O_L4_CK_EN;
			}
		}
		/* need to upload out tunnel l3/l4 type ? */
		tx_desc->d.qword6.cmd |= (o_l4_type << MCE_TX_O_L4_TYPE_S);
		tx_desc->d.qword6.cmd |= (o_l3_type << MCE_TX_O_L3_TYPE_S);

		tx_desc->d.qword1.macip_len =
			(m->outer_l2_len << MCE_MAC_LEN_S);
		tx_desc->d.qword1.macip_len |= m->outer_l3_len;
	} else {
		tx_desc->d.qword6.cmd |= (l4_type << MCE_TX_O_L4_TYPE_S);
		tx_desc->d.qword6.cmd |= (l3_type << MCE_TX_O_L3_TYPE_S);
		tx_desc->d.qword1.macip_len = (m->l2_len << MCE_MAC_LEN_S);
		tx_desc->d.qword1.macip_len |= m->l3_len;
		if (l4_type)
			cksum_offload |= MCE_TX_O_L4_CK_EN;
		if (l3_type && (flags & RTE_MBUF_F_TX_IP_CKSUM))
			cksum_offload |= MCE_TX_O_L3_CK_EN;
		if (tso) {
			tx_desc->d.qword4.l4_tun_len = m->l4_len;
			cksum_offload |= MCE_TX_O_L4_CK_EN;
			cksum_offload |= MCE_TX_O_L3_CK_EN;
		}
	}
	tx_desc->d.qword6.cmd |= cksum_offload;
}

static void mce_setup_tx_offload(struct mce_tx_queue *txq,
				 volatile union mce_tx_desc *tx_desc,
				 struct rte_mbuf *m)
{
	if (m->ol_flags == 0)
		return;
	if (m->ol_flags & RTE_MBUF_F_TX_TCP_SEG ||
	    m->ol_flags & RTE_MBUF_F_TX_UDP_SEG)
		txq->stats.tx_tso_pkts++;
	if (m->ol_flags & RTE_MBUF_F_TX_L4_MASK ||
	    m->ol_flags & RTE_MBUF_F_TX_TCP_SEG ||
	    m->ol_flags & RTE_MBUF_F_TX_UDP_SEG ||
	    m->ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
		mce_setup_csum_offload(m, tx_desc);
	if (m->ol_flags & (RTE_MBUF_F_TX_VLAN | RTE_MBUF_F_TX_QINQ)) {
		uint16_t inset_vlan = 0;

		tx_desc->d.qword6.cmd |= MCE_TX_VLAN_O_EN;
		/* use fpga insert no mac insert */
		if (m->ol_flags & RTE_MBUF_F_TX_QINQ) {
			tx_desc->d.qword2.vlan0 = m->vlan_tci_outer;
			inset_vlan++;
			tx_desc->d.qword3.vlan1 = m->vlan_tci;
			inset_vlan++;
		} else if (m->ol_flags & RTE_MBUF_F_TX_VLAN) {
			tx_desc->d.qword2.vlan0 = m->vlan_tci;
			inset_vlan++;
		}
		if (txq->vlan3_insert_en) {
			tx_desc->d.qword3.vlan2 = txq->vlan_id;
			inset_vlan++;
		}
		/* single vlan just send 8100 vlan tpid */
		if (inset_vlan > 1)
			tx_desc->d.qword6.cmd |= (1 << MCE_TX_O_VLAN_TYPE_S);
		tx_desc->d.qword6.cmd |= (inset_vlan << MCE_TX_VLAN_INSET_S);
	}
	if (m->ol_flags & RTE_MBUF_F_TX_IEEE1588_TMST)
		tx_desc->d.qword6.cmd |= MCE_TX_PTP_EN;
}

#define MCE_MAX_DATA_PER_TXD (4096)
static uint16_t mce_calc_desc(struct rte_mbuf *m)
{
	struct rte_mbuf *m_seg = m;
	uint16_t nb_desc = 0;

	do {
		nb_desc += DIV_ROUND_UP(m_seg->data_len, MCE_MAX_DATA_PER_TXD);
		m_seg = m_seg->next;
	} while (m_seg);

	return nb_desc;
}

static uint16_t mce_tx_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
				 uint16_t nb_pkts)
{
	struct mce_tx_queue *txq = (struct mce_tx_queue *)tx_queue;
	volatile union mce_tx_desc *txbd;
	struct mce_txsw_entry *txe, *txn;
	struct rte_mbuf *tx_pkt, *m_seg;
	bool tx_offload_en = false;
	uint64_t dma_phy_addr = 0;
	uint64_t ol_flags = 0;
	uint16_t seg_len = 0;
	int remain_len;
	uint16_t nb_used_bd;
	uint8_t first_seg;
	uint16_t tx_last;
	uint16_t nb_tx;
	uint16_t tx_id;

	if (txq->nb_tx_free < txq->tx_free_thresh)
		mce_clean_txq(txq);
	tx_id = txq->tx_tail;
	txbd = &txq->tx_bdr[tx_id];
	txe = &txq->sw_ring[tx_id];
	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		tx_pkt = tx_pkts[nb_tx];
		ol_flags = tx_pkt->ol_flags;
		tx_offload_en = mce_valid_tx_offload(ol_flags);
		if (ol_flags & (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG))
			nb_used_bd = mce_calc_desc(tx_pkt);
		else
			nb_used_bd = tx_pkt->nb_segs;
		tx_last = (uint16_t)(tx_id + nb_used_bd - 1);
		if (tx_last >= txq->attr.nb_desc)
			tx_last = (uint16_t)(tx_last - txq->attr.nb_desc);
		if (nb_used_bd > txq->nb_tx_free)
			if (nb_used_bd > mce_clean_txq(txq)) {
				if (txq->nb_tx_free == 0)
					txq->stats.tx_ring_full++;
				break;
			}
		m_seg = tx_pkt;
		first_seg = 1;
		remain_len = tx_pkt->pkt_len;
		do {
			ol_flags = m_seg->ol_flags;
			txbd = &txq->tx_bdr[tx_id];
			txn = &txq->sw_ring[txe->next_id];
			txbd->d.qword6.cmd = 0;
			memset((void *)((uintptr_t)txbd), 0, sizeof(*txbd));
			if (first_seg && tx_offload_en)
				mce_setup_tx_offload(txq, txbd, m_seg);
			if (txe->mbuf) {
				rte_pktmbuf_free_seg(txe->mbuf);
				txe->mbuf = NULL;
			}

			txe->mbuf = m_seg;
			seg_len = m_seg->data_len;
			remain_len -= seg_len;
			dma_phy_addr =
				rte_cpu_to_le_64(rte_mbuf_data_iova(m_seg));
			if (txq->mce_admin_dynflag & m_seg->ol_flags) {
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
				uint16_t vport_id = 0;

				vport_id = *RTE_MBUF_DYNFIELD(
					m_seg, txq->mce_admin_dynfield_offset,
					uint16_t *);
				txbd->d.qword4.vfr = vport_id;
				txbd->d.qword6.cmd |= 15 << 10;
				txq->rep_stats.opackets++;
				txq->rep_stats.obytes += m_seg->pkt_len;
#endif
			} else {
				while ((ol_flags & (RTE_MBUF_F_TX_TCP_SEG |
						    RTE_MBUF_F_TX_UDP_SEG)) &&
				       unlikely(seg_len >
						MCE_MAX_DATA_PER_TXD)) {
					txbd->d.pkt_addr = dma_phy_addr;
					txbd->d.qword1.length =
						MCE_MAX_DATA_PER_TXD;
					txbd->d.qword6.cmd &= ~MCE_CMD_EOP;

					seg_len -= MCE_MAX_DATA_PER_TXD;
					dma_phy_addr += MCE_MAX_DATA_PER_TXD;

					txe->last_id = tx_last;
					tx_id = txe->next_id;
					txe = txn;
					txbd = &txq->tx_bdr[tx_id];
					txn = &txq->sw_ring[txe->next_id];
				}
			}
			first_seg = 0;
			txe->last_id = tx_last;
			txbd->d.pkt_addr =
				rte_cpu_to_le_64(rte_mbuf_data_iova(m_seg));
			txbd->d.qword1.length = seg_len;
			txq->stats.obytes += m_seg->data_len;
			txbd->d.qword6.cmd &= ~MCE_CMD_EOP;
#ifdef MCE_DEBUG_TX_DESC
			mce_dump_tx_desc(txbd);
			rte_pktmbuf_dump(stdout, m_seg, m_seg->data_len);
#endif
			tx_id = txe->next_id;
			txe = txn;
			m_seg = m_seg->next;
		} while (m_seg != NULL && remain_len > 0);
		txbd->d.qword6.cmd |= MCE_CMD_EOP;
		txq->nb_tx_used = txq->nb_tx_used + nb_used_bd;
		txq->nb_tx_free = txq->nb_tx_free - nb_used_bd;

		if (txq->nb_tx_used >= txq->tx_rs_thresh) {
			txq->nb_tx_used = 0;
			txbd->d.qword6.cmd |= MCE_CMD_RS;
		}
	}
	if (!nb_tx) {
		return 0;
	}
#if 0
extern	rte_pcapng_t *n20_pcapng_fd;
extern struct rte_mempool *n20_pkt_mp;
	static int dump_count;
	if (txq->attr.queue_id == 0 && dump_count < 10) {
		struct rte_mbuf *mbuf_clones[32];
		struct rte_mbuf *mbuf = NULL;
		int len = 0;
		int i = 0;

		for (i = 0; i < nb_tx; i++) {
			struct rte_mbuf *mc;
			mbuf = (struct rte_mbuf *)tx_pkts[i];
			mc = rte_pcapng_copy(mbuf->port, 0, mbuf, n20_pkt_mp, mbuf->pkt_len,
					0, "n20-debug-rxq0");
			if (mc == NULL)
				break;

			mbuf_clones[i] = mc;
		}
		printf("123123\n");
		dump_count += nb_tx;
		len = rte_pcapng_write_packets(n20_pcapng_fd, mbuf_clones, i);
		rte_pktmbuf_free_bulk(mbuf_clones, i);
	}
#endif
	txq->stats.opackets += nb_tx;
	txq->tx_tail = tx_id;

	rte_wmb();
	MCE_REG_ADDR_WRITE(txq->tx_tailreg, 0, tx_id);

	return nb_tx;
}

static inline bool mce_check_tx_vaild_offload(struct rte_mbuf *m __rte_unused)
{
	uint16_t max_seg = m->nb_segs;
	uint32_t remain_len = 0;
	struct rte_mbuf *m_seg;
	uint32_t total_len = 0;
	uint32_t limit_len = 0;
	uint32_t tso = 0;
	if (likely(!(m->ol_flags & (RTE_MBUF_F_TX_TCP_SEG |
				    RTE_MBUF_F_TX_UDP_SEG)))) {
		/* non tso mode */
		if (unlikely(m->pkt_len > MCE_MAX_SEG_LEN && m->nb_segs == 1)) {
			return false;
		} else {
			m_seg = m;
			do {
				total_len += m_seg->data_len;
				m_seg = m_seg->next;
			} while (m_seg != NULL);
			if (total_len > MCE_M_MAX_JUMBO)
				return false;
			return true;
		}
	} else {
		tso = mce_cal_tso_seg(m);
		m_seg = m;
		do {
			remain_len = RTE_MAX(remain_len, m_seg->data_len % tso);
			m_seg = m_seg->next;
		} while (m_seg != NULL);
		/* TSO Will remain bytes because of tso
		 * in this situation must refer the worst condition
		 */
		limit_len = remain_len * max_seg + tso;
		if (limit_len > MCE_MAX_TSO_PKT)
			return false;
	}
	m_seg = m;
	if (m_seg->nb_segs > 1) {
		do {
			if (m_seg->data_len == 0)
				return false;
			m_seg = m_seg->next;
		} while (m_seg != NULL);
	}

	return true;
}

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
static inline int mce_net_cksum_flags_prepare(struct rte_mbuf *m,
					      uint64_t ol_flags)
{
	/* Initialise ipv4_hdr to avoid false positive compiler
	 * warnings. */
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_sctp_hdr *sctp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint64_t inner_l3_offset = m->l2_len;

	/*
	 * Does packet set any of available offloads?
	 * Mainly it is required to avoid fragmented headers check if
	 * no offloads are requested.
	 */
	if (!(ol_flags & (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_L4_MASK |
			  RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG)))
		return 0;

	if (ol_flags & (RTE_MBUF_F_TX_OUTER_IPV4 | RTE_MBUF_F_TX_OUTER_IPV6)) {
		if (ol_flags &
		    (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG)) {
			/* Hardware Must require Out-IP Cksum Is Zero
			 * When VXLAN-TSO Enable
			 */
			if (ol_flags & RTE_MBUF_F_TX_OUTER_IPV4) {
				ipv4_hdr = rte_pktmbuf_mtod_offset(
					m, struct rte_ipv4_hdr *,
					m->outer_l2_len);
				ipv4_hdr->hdr_checksum = 0;
				udp_hdr =
					(struct rte_udp_hdr *)((char *)ipv4_hdr +
							       m->outer_l3_len);
				udp_hdr->dgram_cksum =
					rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
			} else {
				ipv6_hdr = rte_pktmbuf_mtod_offset(
					m, struct rte_ipv6_hdr *,
					m->outer_l2_len);
				udp_hdr =
					(struct rte_udp_hdr *)((char *)ipv6_hdr +
							       m->outer_l3_len);
				udp_hdr->dgram_cksum =
					rte_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
			}
		} else {
			if (ol_flags & RTE_MBUF_F_TX_OUTER_IPV4) {
				ipv4_hdr = rte_pktmbuf_mtod_offset(
					m, struct rte_ipv4_hdr *,
					m->outer_l2_len);
				if (ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM)
					ipv4_hdr->hdr_checksum = 0;
				if (ol_flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM) {
					udp_hdr = (struct rte_udp_hdr
							   *)((char *)ipv4_hdr +
							      m->outer_l3_len);
					udp_hdr->dgram_cksum =
						rte_ipv4_phdr_cksum(ipv4_hdr,
								    ol_flags);
				}
			} else {
				ipv6_hdr = rte_pktmbuf_mtod_offset(
					m, struct rte_ipv6_hdr *,
					m->outer_l2_len);
				if (ol_flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM) {
					udp_hdr = (struct rte_udp_hdr
							   *)((char *)ipv6_hdr +
							      m->outer_l3_len);
					udp_hdr->dgram_cksum =
						rte_ipv6_phdr_cksum(ipv6_hdr,
								    ol_flags);
				}
			}
		}
		inner_l3_offset += m->outer_l2_len + m->outer_l3_len;
	}
	/*
	 * Check if headers are fragmented.
	 * The check could be less strict depending on which offloads
	 * are requested and headers to be used, but let's keep it
	 * simple.
	 */
	if (unlikely(rte_pktmbuf_data_len(m) <
		     inner_l3_offset + m->l3_len + m->l4_len))
		return -ENOTSUP;

	if (ol_flags & RTE_MBUF_F_TX_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
						   inner_l3_offset);
		if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
			ipv4_hdr->hdr_checksum = 0;
	}
	if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) == RTE_MBUF_F_TX_UDP_CKSUM ||
	    (ol_flags & RTE_MBUF_F_TX_UDP_SEG)) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr +
							 m->l3_len);
			udp_hdr->dgram_cksum =
				rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);

		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_ipv6_hdr *, inner_l3_offset);
			/* non-TSO udp */
			udp_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_udp_hdr *,
				inner_l3_offset + m->l3_len);
			udp_hdr->dgram_cksum =
				rte_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
		}
	} else if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) ==
			   RTE_MBUF_F_TX_TCP_CKSUM ||
		   (ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			/* non-TSO tcp or TSO */
			tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr +
							 m->l3_len);
			tcp_hdr->cksum =
				rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_ipv6_hdr *, inner_l3_offset);
			/* non-TSO tcp or TSO */
			tcp_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_tcp_hdr *,
				inner_l3_offset + m->l3_len);
			tcp_hdr->cksum =
				rte_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
		}
	} else if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) ==
		   RTE_MBUF_F_TX_SCTP_CKSUM) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			sctp_hdr = (struct rte_sctp_hdr *)((char *)ipv4_hdr +
							   m->l3_len);
			/* SCTP-cksm implement CRC32 */
			sctp_hdr->cksum = 0;
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_ipv6_hdr *, inner_l3_offset);
			/* NON-TSO SCTP */
			sctp_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_sctp_hdr *,
				inner_l3_offset + m->l3_len);
			sctp_hdr->cksum = 0;
		}
	}

	if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM &&
	    !(ol_flags & RTE_MBUF_F_TX_L4_MASK)) {
		/* Workaround For Hardware Fault Of CKSUM OFFLOAD
		 * The Hardware L4 is follow on L3 CKSUM.
		 * When ol_flags set HW L3, SW L4 CKSUM Offload,
		 * We Must Prepare Pseudo Header To avoid
		 * The L4 CKSUM ERROR
		 */
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_ipv4_hdr *, inner_l3_offset);
			switch (ipv4_hdr->next_proto_id) {
			case IPPROTO_UDP:
				udp_hdr =
					(struct rte_udp_hdr *)((char *)ipv4_hdr +
							       m->l3_len);
				udp_hdr->dgram_cksum =
					rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
				break;
			case IPPROTO_TCP:
				tcp_hdr =
					(struct rte_tcp_hdr *)((char *)ipv4_hdr +
							       m->l3_len);
				tcp_hdr->cksum =
					rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
				break;
			default:
				break;
			}
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(
				m, struct rte_ipv6_hdr *, inner_l3_offset);
			switch (ipv6_hdr->proto) {
			case IPPROTO_UDP:
				udp_hdr =
					(struct rte_udp_hdr *)((char *)ipv6_hdr +
							       m->l3_len);
				udp_hdr->dgram_cksum =
					rte_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
				break;
			case IPPROTO_TCP:
				tcp_hdr =
					(struct rte_tcp_hdr *)((char *)ipv6_hdr +
							       m->l3_len);
				tcp_hdr->cksum =
					rte_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
				break;
			default:
				break;
			}
		}
	}

	return 0;
}

uint16_t mce_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		       uint16_t nb_pkts)
{
	struct mce_tx_queue *txq = (struct mce_tx_queue *)tx_queue;
	struct rte_mbuf *m;
	int i, ret;

	for (i = 0; i < nb_pkts; i++) {
		m = tx_pkts[i];
		if (unlikely(!mce_check_tx_vaild_offload(m))) {
			txq->stats.errors++;
			rte_errno = EINVAL;
			return i;
		}
		if (m->nb_segs > 10) {
			rte_errno = EINVAL;
			return i;
		}

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
		ret = rte_validate_tx_offload(m);
		if (ret != 0) {
			rte_errno = -ret;
			return i;
		}
#endif
		ret = mce_net_cksum_flags_prepare(m, m->ol_flags);

		if (ret != 0) {
			rte_errno = -ret;
			return i;
		}
	}

	return i;
}
#endif

static int mce_check_rx_vec_valid(struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	uint64_t rx_offloads = dev->data->dev_conf.rxmode.offloads;
#else
	RTE_SET_USED(dev);
#endif
#ifdef RTE_LIBRTE_IEEE1588
	bool timestamp_en = true;
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rx_offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP)
		return -ENOTSUP;
#endif
#ifdef RTE_LIBRTE_IEEE1588
	if (timestamp_en)
		return -ENOTSUP;
#endif
	return 0;
}

static bool mce_get_vec_support_info(void)
{
#ifdef RTE_ARCH_X86
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE))
		return true;
#elif defined(RTE_ARCH_ARM64)
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_NEON))
		return true;
#endif

	return false;
}

static bool
mce_get_smid_bitwidth(struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	RTE_SET_USED(dev);
	if (rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_128)
		return 1;
#else
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);

	if (vport->attr.smid_force_en)
		return 1;
#endif
	return 0;
}

void mce_setup_rx_function(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_select_func_attr *rx;

	rx = &vport->attr.rx;
	dev->rx_pkt_burst = NULL;
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		rx->cpu_support = mce_get_vec_support_info();
		rx->simple_allowed = mce_check_rx_vec_valid(dev) == 0;
		rx->vec_options = rx->cpu_support && rx->simple_allowed;
		rx->simd_en = mce_get_smid_bitwidth(dev);
		rx->scatter = dev->data->scattered_rx;
	}
	if (rx->vec_options && rx->simd_en) {
#if 0
		if (rte_vect_get_max_simd_bitwidth() >= RTE_VECT_SIMD_256) {
			if (rx->scatter)
				dev->rx_pkt_burst = mce_recv_scattered_pkts_vec_avx2;
			else
				dev->rx_pkt_burst = mce_recv_pkts_vec_avx2;
		} else {
			if (rx->scatter)
				dev->rx_pkt_burst = mce_recv_scattered_pkts_vec;
			else
				dev->rx_pkt_burst = mce_recv_pkts_vec;
		}
#else
		if (rx->scatter)
			dev->rx_pkt_burst = mce_recv_scattered_pkts_vec;
		else
			dev->rx_pkt_burst = mce_recv_pkts_vec;
#endif
	} else {
		if (rx->scatter)
			dev->rx_pkt_burst = mce_scattered_rx;
		else
			dev->rx_pkt_burst = mce_rx_recv_pkts;
	}
#ifdef MCE_DEBUG_PCAP
	dev->rx_pkt_burst = mce_scattered_rx;
#endif
}

static void mce_init_l3l4_cksum_flag(struct mce_rx_queue *rxq)
{
	/* Determine the checksum flags to include based on offload flags */
	uint32_t outer_ip_good = 0, outer_ip_bad = 0;
	uint32_t outer_l4_good = 0, outer_l4_bad = 0;
	uint32_t ip_good = 0, ip_bad = 0;
	uint32_t l4_good = 0, l4_bad = 0;
	int i = 0;

	/* Check each offload flag, only set corresponding flags for enabled offloads */
	if (rxq->rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) {
		ip_good = RTE_MBUF_F_RX_IP_CKSUM_GOOD;
		ip_bad = RTE_MBUF_F_RX_IP_CKSUM_BAD;
	}
	if (rxq->rx_offload_capa & (RTE_ETH_RX_OFFLOAD_UDP_CKSUM |
				RTE_ETH_RX_OFFLOAD_TCP_CKSUM |
				RTE_ETH_RX_OFFLOAD_SCTP_CKSUM)) {
		l4_good = RTE_MBUF_F_RX_L4_CKSUM_GOOD;
		l4_bad = RTE_MBUF_F_RX_L4_CKSUM_BAD;
	}
	if (rxq->rx_offload_capa & RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM) {
		/* Currently only BAD flag is used for outer IP checksum */
		outer_ip_bad = RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD;
		/* Note: RTE_MBUF_F_RX_OUTER_IP_CKSUM_GOOD may be available in newer DPDK versions */
	}
	if (rxq->rx_offload_capa & RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM) {
		outer_l4_good = RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD;
		outer_l4_bad = RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD;
	}
	/* Generate 16 state combinations (4 checksum types, each with 2 states) */
	for (i = 0; i < 16; i++) {
		uint32_t value = 0;

		/* Set corresponding flags based on the binary bits of state index i */
		/* Bit 0: Outer IP state (0=GOOD, 1=BAD) - following inverted value rule */
		if (i & 0x01)
			value |= outer_ip_bad;
		else
			value |= outer_ip_good;
		/* Bit 1: Outer L4 state (0=GOOD, 1=BAD) */
		if (i & 0x02)
			value |= (outer_l4_bad >> 20);
		else
			value |= (outer_l4_good >> 20);

		/* Bit 2: Inner IP state (0=GOOD, 1=BAD) */
		if (i & 0x04)
			value |= ip_bad;
		else
			value |= ip_good;
		/* Bit 3: Inner L4 state (0=GOOD, 1=BAD) */
		if (i & 0x08)
			value |= l4_bad;
		else
			value |= l4_good;
		/* Apply right shift by 1 bit to maintain consistency with original code */
		rxq->l3_l4_cksum[i] = (value >> 1) & 0xFF;
	}
}

void mce_rx_vec_cksum_db_init(struct rte_eth_dev *dev)
{
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	struct rte_eth_rxmode *rxmode = &dev_conf->rxmode;
	int i = 0;

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	if (rxmode->offloads & MCE_RX_CHECKSUM_SUPPORT) {
#else
	if (rxmode->hw_ip_checksum) {
#endif
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			struct mce_rx_queue *rxq = dev->data->rx_queues[i];

			if (rxq == NULL)
				continue;
			mce_init_l3l4_cksum_flag(rxq);
		}
	}
}

static int mce_check_tx_vec_valid(struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
	uint64_t tx_offloads = dev->data->dev_conf.txmode.offloads;
	uint64_t rx_offloads = dev->data->dev_conf.rxmode.offloads;
#else
	uint64_t tx_offloads = 0;
	uint64_t rx_offloads = 0;
#endif
	/* 1588 ptp feature will be enabled
	 * The tx side may need timestamps of ptp event
	 */
	if (rx_offloads & RTE_ETH_RX_OFFLOAD_TIMESTAMP)
		return -ENOTSUP;
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	/* vector mode must be int fast_free mbuf mode */
	if (tx_offloads != RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
#else
#define MCE_TX_SIMPLE_FLAGS \
	((uint32_t)ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS)
	/* no multsegs and no tx offload feature enabled */
	if (!tx_offloads ||
	    (tx_offloads & MCE_TX_SIMPLE_FLAGS) != MCE_TX_SIMPLE_FLAGS)
#endif
		return -ENOTSUP;
	if (dev->data->scattered_rx)
		return -ENOTSUP;
#ifdef RTE_LIBRTE_IEEE1588
	bool timestamp_en = true;
#endif
#ifdef RTE_LIBRTE_IEEE1588
	if (timestamp_en)
		return -ENOTSUP;
#endif
	return 0;
}

static uint16_t __attribute__((unused))
rte_eth_pkt_prepare_dummy(void *queue __rte_unused,
			  struct rte_mbuf **pkts __rte_unused,
			  uint16_t nb_pkts __rte_unused)
{
	return nb_pkts;
}

void mce_setup_tx_function(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_pf *pf = MCE_DEV_TO_PF(dev);
	struct mce_select_func_attr *tx;

	dev->tx_pkt_burst = NULL;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	dev->tx_pkt_prepare = NULL;
#endif
	tx = &vport->attr.tx;
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		tx->cpu_support = mce_get_vec_support_info();
		tx->simple_allowed = mce_check_tx_vec_valid(dev) == 0;
		tx->vec_options = tx->cpu_support && tx->simple_allowed;
		tx->simd_en = mce_get_smid_bitwidth(dev);
	}
	if (tx->vec_options && tx->simd_en) {
		dev->tx_pkt_burst = mce_xmit_pkts_vec;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
		dev->tx_pkt_prepare = rte_eth_pkt_prepare_dummy;
#endif
	} else {
		dev->tx_pkt_burst = mce_tx_xmit_pkts;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
		dev->tx_pkt_prepare = mce_prep_pkts;
#endif
	}
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		if (pf->is_switchdev) {
			dev->tx_pkt_burst = mce_tx_xmit_pkts;
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
			dev->tx_pkt_prepare = mce_prep_pkts;
#endif
		}
		if (vport->combined_tx)
			dev->tx_pkt_burst = mce_xmit_simple_burst;
	}
}
