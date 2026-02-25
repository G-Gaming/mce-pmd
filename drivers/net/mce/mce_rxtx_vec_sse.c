#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <rte_version.h>
#include <rte_malloc.h>
#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION
#include <rte_mbuf.h>
#include <rte_net.h>
#endif
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_common.h>
#include <rte_mbuf.h>

#include "base/mce_hw.h"
#include "base/mce_ptype.h"
#include "mce.h"
#include "mce_rxtx.h"
#include "mce_logs.h"
#include "mce_rxtx_vec.h"
#include "mce_compat.h"

#include <tmmintrin.h>
#include <emmintrin.h>

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

#define RTE_MCE_DESCS_PER_LOOP (4)
static inline void mce_rxq_rearm(struct mce_rx_queue *rxq);

static inline void vtx1(struct mce_tx_queue *txq __rte_unused,
			volatile union mce_tx_desc *txdp, struct rte_mbuf *pkt,
			uint64_t flags)
{
	uint64_t high_qw = (uint64_t)pkt->data_len;

	__m128i descriptor = _mm_set_epi64x(high_qw,
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
					    pkt->buf_physaddr + pkt->data_off);
#else
					    pkt->buf_iova + pkt->data_off);
#endif
	_mm_store_si128((__m128i *)txdp, descriptor);
	txdp->d.qword6.cmd = flags;
}

static inline void vtx(struct mce_tx_queue *txq,
		       volatile union mce_tx_desc *txdp, struct rte_mbuf **pkt,
		       uint16_t nb_pkts, uint64_t flags)
{
	int i;

	for (i = 0; i < nb_pkts; ++i, ++txdp, ++pkt)
		vtx1(txq, txdp, *pkt, flags);
}

static __rte_always_inline int mce_tx_free_bufs(struct mce_tx_queue *txq)
{
	struct mce_txsw_entry *txep;
	uint32_t n;
	uint32_t i;
	int nb_free = 0;
	struct rte_mbuf *m, *free[64];

	/* check DD bits on threshold descriptor */
	if (!(txq->tx_bdr[txq->tx_next_dd].d.qword6.cmd & MCE_CMD_DD))
		return 0;

	n = txq->tx_rs_thresh;

	/* first buffer to free from S/W ring is at index
	 * tx_next_dd - (tx_rs_thresh-1)
	 */
	txep = &txq->sw_ring[txq->tx_next_dd - (n - 1)];

#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
	if (txq->offloads & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
		for (i = 0; i < n; i++) {
			free[i] = txep[i].mbuf;
			txep[i].mbuf = NULL;
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, n);
		goto done;
	}
#endif
	m = rte_pktmbuf_prefree_seg(txep[0].mbuf);
	if (likely(m != NULL)) {
		free[0] = m;
		nb_free = 1;
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (likely(m != NULL)) {
				if (likely(m->pool == free[0]->pool)) {
					free[nb_free++] = m;
				} else {
					rte_mempool_put_bulk(free[0]->pool,
							     (void *)free,
							     nb_free);
					free[0] = m;
					nb_free = 1;
				}
			}
		}
		rte_mempool_put_bulk(free[0]->pool, (void **)free, nb_free);
	} else {
		for (i = 1; i < n; i++) {
			m = rte_pktmbuf_prefree_seg(txep[i].mbuf);
			if (m != NULL)
				rte_mempool_put(m->pool, m);
		}
	}
#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
done:
#endif
	/* buffers were freed, update counters */
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + txq->tx_rs_thresh);
	txq->tx_next_dd = (uint16_t)(txq->tx_next_dd + txq->tx_rs_thresh);
	if (txq->tx_next_dd >= txq->attr.nb_desc)
		txq->tx_next_dd = (uint16_t)(txq->tx_rs_thresh - 1);

	return txq->tx_rs_thresh;
}

static __rte_always_inline uint64_t tx_backlog_entry(
	struct mce_tx_queue *txq __rte_unused, struct mce_txsw_entry *txep,
	struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	int i;

	for (i = 0; i < (int)nb_pkts; ++i) {
		txep[i].mbuf = tx_pkts[i];
		if (txep[i].mbuf->data_len > 16 * 1024)
			txep[i].mbuf->data_len = 0;
	}

	return 0;
}

/**
 * @brief SSE-accelerated TX burst transmission (fixed size).
 *
 * Transmits up to `nb_pkts` mbufs from `tx_pkts` array using SIMD
 * operations. Number of packets is capped at `tx_rs_thresh` to respect
 * hardware descriptor ring boundaries.
 *
 * @param tx_queue
 *   Pointer to the TX queue.
 * @param tx_pkts
 *   Array of mbufs to transmit.
 * @param nb_pkts
 *   Number of mbufs to transmit.
 * @return
 *   Number of mbufs transmitted.
 */
uint16_t mce_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
				  uint16_t nb_pkts)
{
	struct mce_tx_queue *txq = (struct mce_tx_queue *)tx_queue;
	uint64_t rs = MCE_CMD_RS | MCE_CMD_EOP;
	volatile union mce_tx_desc *txdp;
	uint16_t n, nb_commit, tx_id;
	uint64_t flags = MCE_CMD_EOP;
	uint64_t tx_bytes_record = 0;
	struct mce_txsw_entry *txep;
	int i;

	/* cross rx_thresh boundary is not allowed */
	nb_pkts = RTE_MIN(nb_pkts, txq->tx_rs_thresh);

	if (txq->nb_tx_free < txq->tx_free_thresh)
		mce_tx_free_bufs(txq);
	nb_commit = nb_pkts = (uint16_t)RTE_MIN(txq->nb_tx_free, nb_pkts);
	if (unlikely(nb_pkts == 0)) {
		txq->stats.tx_ring_full++;
		return 0;
	}
	tx_id = txq->tx_tail;
	txdp = &txq->tx_bdr[tx_id];
	txep = &txq->sw_ring[tx_id];

	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free - nb_pkts);

	n = (uint16_t)(txq->attr.nb_desc - tx_id);
	if (nb_commit >= n) {
		tx_backlog_entry(txq, txep, tx_pkts, n);
		for (i = 0; i < n - 1; ++i, ++tx_pkts, ++txdp)
			vtx1(txq, txdp, *tx_pkts, flags);
		vtx1(txq, txdp, *tx_pkts++, rs);

		nb_commit = (uint16_t)(nb_commit - n);

		tx_id = 0;
		txq->tx_next_rs = (uint16_t)(txq->tx_rs_thresh - 1);

		/* avoid reach the end of ring */
		txdp = &txq->tx_bdr[tx_id];
		txep = &txq->sw_ring[tx_id];
	}

	tx_bytes_record += tx_backlog_entry(txq, txep, tx_pkts, nb_commit);

	vtx(txq, txdp, tx_pkts, nb_commit, flags);

	tx_id = (uint16_t)(tx_id + nb_commit);
	if (tx_id > txq->tx_next_rs) {
		txq->tx_bdr[txq->tx_next_rs].d.qword6.cmd |= MCE_CMD_RS;

		txq->tx_next_rs =
			(uint16_t)(txq->tx_next_rs + txq->tx_rs_thresh);
	}
	txq->tx_tail = tx_id;
	rte_wmb();
	/* Update the tail pointer on the NIC */
	MCE_REG_ADDR_WRITE(txq->tx_tailreg, 0, tx_id);

	return nb_pkts;
}

#define PKTLEN_SHIFT		 (0)
#define RTE_MCE_RXQ_REARM_THRESH (32)

static inline void mce_rxq_rearm(struct mce_rx_queue *rxq)
{
	struct mce_rxsw_entry *rxep = &rxq->sw_ring[rxq->rxrearm_start];
	volatile union mce_rx_desc *rxdp;
	struct rte_mbuf *mb0, *mb1;
	uint16_t rx_id;
	int i;

	__m128i dma_addr0;
	rxdp = rxq->rx_bdr + rxq->rxrearm_start;
	/* Pull 'n' more MBUFs into the software ring */
	if (rte_mempool_get_bulk(rxq->mb_pool, (void **)rxep,
				 RTE_MCE_RXQ_REARM_THRESH) < 0) {
		if (rxq->rxrearm_nb + RTE_MCE_RXQ_REARM_THRESH >=
		    rxq->attr.nb_desc) {
			dma_addr0 = _mm_setzero_si128();
			for (i = 0; i < RTE_MCE_DESCS_PER_LOOP; i++) {
				rxep[i].mbuf = &rxq->fake_mbuf;
				_mm_store_si128((__m128i *)&rxdp[i].d.rsvd2,
						dma_addr0);
			}
		}
		rte_eth_devices[rxq->attr.rte_pid].data->rx_mbuf_alloc_failed +=
			RTE_MCE_RXQ_REARM_THRESH;
		return;
	}
	/* Initialize the mbufs in vector, process 2 mbufs in one loop */
	for (i = 0; i < RTE_MCE_RXQ_REARM_THRESH; i += 2, rxep += 2) {
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
		uintptr_t p0, p1;
#endif
		mb0 = rxep[0].mbuf;
		mb1 = rxep[1].mbuf;
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
		/*
		 * Flush mbuf with pkt template.
		 * Data to be rearmed is 6 bytes long.
		 * Though, RX will overwrite ol_flags that are coming next
		 * anyway. So overwrite whole 8 bytes with one load:
		 * 6 bytes of rearm_data plus first 2 bytes of ol_flags.
		 */
		p0 = (uintptr_t)&mb0->rearm_data;
		*(uint64_t *)p0 = rxq->mbuf_initializer;
		p1 = (uintptr_t)&mb1->rearm_data;
		*(uint64_t *)p1 = rxq->mbuf_initializer;
#endif
		/* load buf_addr(lo 64bit) and buf_iova(hi 64bit) */

#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
		RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, buf_iova) !=
				 offsetof(struct rte_mbuf, buf_addr) + 8);
#else
		RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, buf_physaddr) !=
				 offsetof(struct rte_mbuf, buf_addr) + 8);
#endif
		rxdp->wb.cmd = 0;
		rxdp++->d.pkt_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova(mb0));
		rxdp->wb.cmd = 0;
		rxdp++->d.pkt_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova(mb1));
#if 0
		vaddr0 = _mm_loadu_si128((__m128i *)&mb0->buf_addr);
		vaddr1 = _mm_loadu_si128((__m128i *)&mb1->buf_addr);
		/* convert pa to dma_addr hdr/data */
		dma_addr0 = _mm_unpackhi_epi64(vaddr0, vaddr0);
		dma_addr1 = _mm_unpackhi_epi64(vaddr1, vaddr1);

		/* add headroom to pa values */
		dma_addr0 = _mm_add_epi64(dma_addr0, hdr_room);
		dma_addr1 = _mm_add_epi64(dma_addr1, hdr_room);
		_mm_store_si128((__m128i *)&rxdp++->d.pkt_addr, dma_addr0);
		_mm_store_si128((__m128i *)&rxdp->d.rsvd2, bzero);
		_mm_store_si128((__m128i *)&rxdp++->d.pkt_addr, dma_addr1);
		_mm_store_si128((__m128i *)&rxdp->d.rsvd2, bzero);
#endif
	}

	rxq->rxrearm_start += RTE_MCE_RXQ_REARM_THRESH;

	if (rxq->rxrearm_start >= rxq->attr.nb_desc)
		rxq->rxrearm_start = 0;

	rxq->rxrearm_nb -= RTE_MCE_RXQ_REARM_THRESH;

	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
				   (rxq->attr.nb_desc - 1) :
				   (rxq->rxrearm_start - 1));

	rte_wmb();
	/* Update the tail pointer on the NIC */
	MCE_REG_ADDR_WRITE(rxq->rx_tailreg, 0, rx_id);
}

#ifdef DEBUG_VECTOR
static void print128_num(__m128i var)
{
	/* can also use uint32_t instead of 16_t */
	uint16_t *val = (uint16_t *)&var;
	printf("Numerical: %i %i %i %i %i %i %i %i \n", val[0], val[1], val[2],
	       val[3], val[4], val[5], val[6], val[7]);
}

static void print128_u8_num(__m128i var)
{
	/* can also use uint32_t instead of 16_t */
	uint8_t *val = (uint8_t *)&var;
	printf("Numerical: %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i \n",
	       val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
	       val[8], val[9], val[10], val[11], val[12], val[13], val[14],
	       val[15]);
}

static void print128_u16_num(__m128i var)
{
	/* can also use uint32_t instead of 16_t */
	uint16_t *val = (uint16_t *)&var;
	printf("Numerical u 16: %i %i %i %i %i %i %i %i \n", val[0], val[1],
	       val[2], val[3], val[4], val[5], val[6], val[7]);
}

static bool mce_vec_is_equal(__m128i a, __m128i b) {
	__m128i cmp = _mm_cmpeq_epi8(a, b);
	int mask = _mm_movemask_epi8(cmp);
	return mask == 0xFFFF;
}
#endif

static __m128i
desc_to_mark(__m128i descs[4], struct rte_mbuf **rx_pkts)
{
	const __m128i mark_msk = _mm_set_epi32(
		0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF);
	__m128i combine0, combine1;
	__m128i mark_turn;
	__m128i fd_id_mask;
	__m128i and_result;
	__m128i cmp_eq_zero;
	uint32_t val[4] = {0};
	__m128i mark;

	combine0 = _mm_unpacklo_epi32(descs[0], descs[1]);
	combine1 = _mm_unpacklo_epi32(descs[2], descs[3]);
	mark = _mm_unpackhi_epi32(combine0, combine1);
	mark = _mm_and_si128(mark, mark_msk);

	mark_turn = mark;
	val[0] = _mm_extract_epi16(mark, 0);
	val[1] = _mm_extract_epi16(mark, 2);
	val[2] = _mm_extract_epi16(mark, 4);
	val[3] = _mm_extract_epi16(mark, 6);

	RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR_ID != (1 << 13));
	and_result = _mm_and_si128(mark_turn, mark_msk);
	cmp_eq_zero = _mm_cmpeq_epi32(and_result, _mm_setzero_si128());
	fd_id_mask = _mm_xor_si128(cmp_eq_zero, _mm_set1_epi32(-1));
	fd_id_mask = _mm_srli_epi32(fd_id_mask, 31);
	fd_id_mask = _mm_slli_epi32(fd_id_mask, 13);

	rx_pkts[0]->hash.fdir.hi = val[0];
	rx_pkts[1]->hash.fdir.hi = val[1];
	rx_pkts[2]->hash.fdir.hi = val[2];
	rx_pkts[3]->hash.fdir.hi = val[3];

	return fd_id_mask;
}

static __m128i mce_generate_l3_l4_flag(struct mce_rx_queue *rxq)
{
	uint8_t *bytes = rxq->l3_l4_cksum;

	return _mm_set_epi8(
			bytes[15], bytes[14], bytes[13], bytes[12],
			bytes[11], bytes[10], bytes[9],  bytes[8],
			bytes[7],  bytes[6],  bytes[5],  bytes[4],
			bytes[3],  bytes[2],  bytes[1],  bytes[0]
			);
}

static inline void mce_rx_desc_parse_field(struct mce_rx_queue *rxq,
					   __m128i descs[4],
					   struct rte_mbuf **rx_pkts)
{
	__m128i err_cmd, rss_vlan, l3_l4e;
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	union {
		uint16_t e[4];
		uint64_t dword;
	} vol;
	RTE_SET_USED(rxq);
#else
	const __m128i mbuf_init = _mm_set_epi64x(0, rxq->mbuf_initializer);
	__m128i rearm[4];
#endif
	__m128i flags = _mm_setzero_si128();
	__m128i combine0, combine1;
	__m128i csum_msk = _mm_set_epi32(0x7F0000, 0x7F0000, 0x7F0000, 0x7F0000);

	const __m128i cksum_mask = _mm_set_epi32(
			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD,

			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD,

			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD,

			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD);
	const __m128i rss_vlan_mk = _mm_set_epi32(
		0xF000000, 0xF000000, 0xF000000, 0xF000000);
	const __m128i rss_vlan_flag = _mm_set_epi8(RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_RSS_HASH,
			(RTE_MBUF_F_RX_RSS_HASH), /* 14 */
			(RTE_MBUF_F_RX_FDIR), /* 13 */
			0,/* 12 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13 | RTE_MBUF_F_RX_FDIR |
			RTE_MBUF_F_RX_RSS_HASH, /* 11 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13 | RTE_MBUF_F_RX_RSS_HASH, /* 10 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13 | RTE_MBUF_F_RX_FDIR, /* 9 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13, /* 8 */
			RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 7 */
			RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 6*/
			RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_FDIR |
			RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 5 */
			RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 4 */
			(RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_RSS_HASH),
			RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_FDIR, 0);
	/*
	 * #define RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD        (1ULL << 21)
	 * #define RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD       (1ULL << 22)
	 * #define RTE_MBUF_F_RX_L4_CKSUM_BAD               (1ULL << 3)
	 * #define RTE_MBUF_F_RX_L4_CKSUM_GOOD             (1ULL << 8)
	 * #define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD        (1ULL << 5)
	 */
	/* outer_l4 needt right 20 bit conpose 3,5,8,1,2
	 * so the value after (3,5,8,1,2) >> 1 can store in uint8_t
	 */
#if 0
	const __m128i l3_l4e_flags_a = _mm_set_epi8(
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
			(RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20) >> 1
			);
	const __m128i l3_l4e_flags = mce_generate_l3_l4_flag(rxq);

	if (!mce_vec_is_equal(l3_l4e_flags, l3_l4e_flags_a)) {
		print128_u8_num(l3_l4e_flags_a);
		print128_u8_num(l3_l4e_flags);
	}
#else
	const __m128i l3_l4e_flags = mce_generate_l3_l4_flag(rxq);
#endif
	combine0 = _mm_unpackhi_epi32(descs[0], descs[1]);
	combine1 = _mm_unpackhi_epi32(descs[2], descs[3]);

	err_cmd = _mm_unpacklo_epi32(combine0, combine1);
	rss_vlan = _mm_and_si128(err_cmd, rss_vlan_mk);
	rss_vlan = _mm_srli_epi32(rss_vlan, 24);
	rss_vlan = _mm_shuffle_epi8(rss_vlan_flag, rss_vlan);
	flags = rss_vlan;

	if (rxq->rx_offload_capa & (RTE_ETH_RX_OFFLOAD_CHECKSUM |
				RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
				RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
				RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM)) {
		const __m128i l3_l4_flag_mask = _mm_set_epi32(~0x00000006, ~0x00000006,
							~0x00000006, ~0x00000006);
		const __m128i l4_outer_mask = _mm_set_epi32(
				0x00000006, 0x00000006,
				0x00000006, 0x00000006);
		const __m128i tunnel_msk = _mm_set_epi32(0x7, 0x7, 0x7, 0x7);
		const __m128i tunnel_mask_val = _mm_set_epi32(
				0x0000e000, 0x0000e000,
				0x0000e000, 0x0000e000);
		__m128i tunnel_flag = _mm_unpackhi_epi64(combine0, combine1);
		tunnel_flag = _mm_and_si128(tunnel_flag, tunnel_mask_val);
		tunnel_flag = _mm_srli_epi32(tunnel_flag, 13);
		__m128i and_result = _mm_and_si128(tunnel_flag, tunnel_msk);
		__m128i zero = _mm_setzero_si128();
		__m128i outer_l4_flags;
		__m128i l3_l4e_shifted;
		__m128i part2, part1;
		__m128i l3_l4_flags;

		__m128i cmp_mask_temp = _mm_and_si128(and_result, tunnel_msk);
		__m128i cmp_mask = _mm_cmpeq_epi32(cmp_mask_temp, zero);

		l3_l4e = _mm_and_si128(err_cmd, csum_msk);
		l3_l4e = _mm_srli_epi32(l3_l4e, 16 + 2);
		/* according tunnel_flag to select cksum is inner or outer */
		l3_l4e_shifted = _mm_slli_epi32(l3_l4e, 2);
		part1 = _mm_and_si128(cmp_mask, l3_l4e_shifted);
		part2 = _mm_andnot_si128(cmp_mask, l3_l4e);
		l3_l4e = _mm_or_si128(part1, part2);
		l3_l4e = _mm_shuffle_epi8(l3_l4e_flags, l3_l4e);
		/* then we shift left 1 bit */
		l3_l4e = _mm_slli_epi32(l3_l4e, 1);
		/* extract the outer l4 bit 21 chksum err*/
		outer_l4_flags = _mm_and_si128(l3_l4e, l4_outer_mask);
		outer_l4_flags = _mm_slli_epi32(outer_l4_flags, 20);
		l3_l4_flags = _mm_and_si128(l3_l4e, l3_l4_flag_mask);
		l3_l4e = _mm_or_si128(l3_l4_flags, outer_l4_flags);
		 /* we need to mask out the redundant bits */
		l3_l4e = _mm_and_si128(l3_l4e, cksum_mask);
		flags = _mm_or_si128(flags, l3_l4e);
	}
	flags = _mm_or_si128(flags, desc_to_mark(descs, rx_pkts));
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	vol.e[0] = _mm_extract_epi16(flags, 0);
	vol.e[1] = _mm_extract_epi16(flags, 2);
	vol.e[2] = _mm_extract_epi16(flags, 4);
	vol.e[3] = _mm_extract_epi16(flags, 6);

	rx_pkts[0]->ol_flags = vol.e[0];
	rx_pkts[1]->ol_flags = vol.e[1];
	rx_pkts[2]->ol_flags = vol.e[2];
	rx_pkts[3]->ol_flags = vol.e[3];
#else
	rearm[0] = _mm_blend_epi16(mbuf_init, _mm_slli_si128(flags, 8), 0x30);
	rearm[1] = _mm_blend_epi16(mbuf_init, _mm_slli_si128(flags, 4), 0x30);
	rearm[2] = _mm_blend_epi16(mbuf_init, flags, 0x30);
	rearm[3] = _mm_blend_epi16(mbuf_init, _mm_srli_si128(flags, 4), 0x30);

	/* write the rearm data and the olflags in one write */
	_mm_store_si128((__m128i *)&rx_pkts[0]->rearm_data, rearm[0]);
	_mm_store_si128((__m128i *)&rx_pkts[1]->rearm_data, rearm[1]);
	_mm_store_si128((__m128i *)&rx_pkts[2]->rearm_data, rearm[2]);
	_mm_store_si128((__m128i *)&rx_pkts[3]->rearm_data, rearm[3]);

#endif
}

static inline void mce_desc_to_ptype(__m128i descs[4],
				     struct rte_mbuf **rx_pkts)
{
	__m128i ptype0 = _mm_unpackhi_epi32(descs[0], descs[1]);
	__m128i ptype1 = _mm_unpackhi_epi32(descs[2], descs[3]);
	__m128i ptypes = _mm_unpackhi_epi64(ptype0, ptype1);
	const __m128i ptype_msk = _mm_set_epi32(0xFFFFFC, 0xFFFFFC, 0xFFFFFC, 0xFFFFFC);
	uint32_t ptype[4];

	ptype0 = _mm_and_si128(ptypes, ptype_msk);
	ptype1 = _mm_srli_epi32(ptype0, 2);
	ptype[0] = _mm_extract_epi32(ptype1, 0);
	ptype[1] = _mm_extract_epi32(ptype1, 1);
	ptype[2] = _mm_extract_epi32(ptype1, 2);
	ptype[3] = _mm_extract_epi32(ptype1, 3);

	rx_pkts[0]->packet_type = mce_get_rx_parse_ptype(ptype[0]);
	rx_pkts[1]->packet_type = mce_get_rx_parse_ptype(ptype[1]);
	rx_pkts[2]->packet_type = mce_get_rx_parse_ptype(ptype[2]);
	rx_pkts[3]->packet_type = mce_get_rx_parse_ptype(ptype[3]);
}

static inline uint16_t _recv_raw_pkts_vec(struct mce_rx_queue *rxq,
					  struct rte_mbuf **rx_pkts,
					  uint16_t nb_pkts,
					  uint8_t *split_packet)
{
	volatile union mce_rx_desc *rxdp;
	struct mce_rxsw_entry *sw_ring;
	uint16_t nb_pkts_recd = 0;
	uint64_t var;
	int pos;

	__m128i shuf_msk, pad_msk;
	__m128i eop_check;
	__m128i zero;

	__m128i crc_adjust = _mm_set_epi16
				(0, 0, 0,       /* ignore non-length fields */
				 -rxq->strip_len, /* sub crc on data_len */
				 0,          /* ignore high-16bits of pkt_len */
				 -rxq->strip_len, /* sub crc on pkt_len */
				 0, 0           /* ignore pkt_type field */
				);
	eop_check = _mm_set_epi64x(0x0000000100000001LL, 0x0000000100000001LL);
	/*
	 * compile-time check the above crc_adjust layout is correct.
	 * NOTE: the first field (lowest address) is given last in set_epi16
	 * call above.
	 */

	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	__m128i dd_check;

	/* nb_pkts has to be floor-aligned to RTE_MCE_DESCS_PER_LOOP */
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, RTE_MCE_DESCS_PER_LOOP);

	/* Just the act of getting into the function from the application is
	 * going to cost about 7 cycles
	 */
	rxdp = rxq->rx_bdr + rxq->rx_tail;

	rte_prefetch0(rxdp);
	rte_prefetch0(rxdp + 2);
	/* HW Desc Write-Back May Slow Than Expect
	 * In Order To Avoid Just Recv 1 or 2 Pkts
	 * To Delay A Cycle
	 */
	if (rxq->rxrearm_nb > RTE_MCE_RXQ_REARM_THRESH)
		mce_rxq_rearm(rxq);
	/* Before we start moving massive data around, check to see if
	 * there is actually a packet available
	 */
	if (!(rxdp->wb.cmd & MCE_CMD_DD))
		return 0;
	/* 4 packets DD mask */
	dd_check = _mm_set_epi64x(0x200000002LL, 0x200000002LL);

	/* mask to shuffle from desc. to mbuf */
	shuf_msk = _mm_set_epi8(3, 2, 1, 0, /* octet 0~3, 32bits rss */
				9, 8, /* octet 2~3, low 16 bits vlan_macip */
				5, 4, /* octet 15~14, 16 bits data_len */
				0xFF,
				0xFF, /* skip high 16 bits pkt_len, zero out */
				5, 4, /* octet 15~14, low 16 bits pkt_len */
				0xFF, 0xFF, /* pkt_type set as unknown */
				0xFF, 0xFF /*pkt_type set as unknown */
	);
	pad_msk = _mm_set_epi8(0xFF, 0xFF, 0xFF, 0xFF, 11, 10, 11, 10, 0xff,
			       0xff, 0xff, 0xff, 0xFF, 0xFF, 0xFF, 0xff);
	/*
	 * Compile-time verify the shuffle mask
	 * NOTE: some field positions already verified above, but duplicated
	 * here for completeness in case of future modifications.
	 */
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, vlan_tci) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 10);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, hash) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 12);

	/* Cache is empty -> need to scan the buffer rings, but first move
	 * the next 'n' mbufs into the cache
	 */
	sw_ring = &rxq->sw_ring[rxq->rx_tail];
	/* A. load 4 packet in one loop
	 * [A*. mask out 4 unused dirty field in desc]
	 * B. copy 4 mbuf point from swring to rx_pkts
	 * C. calc the number of DD bits among the 4 packets
	 * [C*. extract the end-of-packet bit, if requested]
	 * D. fill info. from desc to mbuf
	 */

	zero = _mm_xor_si128(dd_check, dd_check);
	for (pos = 0, nb_pkts_recd = 0; pos < nb_pkts;
	     pos += RTE_MCE_DESCS_PER_LOOP, rxdp += RTE_MCE_DESCS_PER_LOOP) {
		__m128i descs_hi[RTE_MCE_DESCS_PER_LOOP];
		__m128i descs_lo[RTE_MCE_DESCS_PER_LOOP];
		__m128i pkt_mb4, pkt_mb3, pkt_mb2, pkt_mb1;
		__m128i pad_len4, pad_len3, pad_len2, pad_len1;
		__m128i staterr, sterr_tmp1, sterr_tmp2;
		__m128i eop_flags;
		/* 2 64 bit or 4 32 bit mbuf pointers in one XMM reg. */
		__m128i mbp1;
#if defined(RTE_ARCH_X86_64)
		__m128i mbp2;
#endif
		/* B.1 load 2 (64 bit) or 4 (32 bit) mbuf points */
		mbp1 = _mm_loadu_si128((__m128i *)&sw_ring[pos]);
		/* Read desc statuses backwards to avoid race condition */
		/* A.1 load desc[3] */
		descs_lo[3] = _mm_loadu_si128(
			(__m128i *)&(rxdp + 3)->wb.stamp.timestamp_h);
		rte_compiler_barrier();
		/* B.2 copy 2 64 bit or 4 32 bit mbuf point into rx_pkts */
		_mm_storeu_si128((__m128i *)&rx_pkts[pos], mbp1);
#if defined(RTE_ARCH_X86_64)
		/* B.1 load 2 64 bit mbuf points */
		mbp2 = _mm_loadu_si128((__m128i *)&sw_ring[pos + 2]);
#endif
		/* A.1 load desc[2-0] */
		descs_lo[2] = _mm_loadu_si128(
			(__m128i *)&(rxdp + 2)->wb.stamp.timestamp_h);
		rte_compiler_barrier();
		descs_lo[1] = _mm_loadu_si128(
			(__m128i *)&(rxdp + 1)->wb.stamp.timestamp_h);
		rte_compiler_barrier();
		descs_lo[0] =
			_mm_loadu_si128((__m128i *)&(rxdp->wb.stamp.timestamp_h));
#if defined(RTE_ARCH_X86_64)
		/* B.2 copy 2 mbuf point into rx_pkts  */
		_mm_storeu_si128((__m128i *)&rx_pkts[pos + 2], mbp2);
#endif
		if (rxq->pad_len) {
			pad_len4 = _mm_shuffle_epi8(descs_hi[3], pad_msk);
			pad_len3 = _mm_shuffle_epi8(descs_hi[2], pad_msk);
			pad_len2 = _mm_shuffle_epi8(descs_hi[1], pad_msk);
			pad_len1 = _mm_shuffle_epi8(descs_hi[0], pad_msk);
			descs_hi[3] = _mm_sub_epi16(descs_hi[3], pad_len4);
			descs_hi[2] = _mm_sub_epi16(descs_hi[2], pad_len3);
			descs_hi[1] = _mm_sub_epi16(descs_hi[1], pad_len2);
			descs_hi[0] = _mm_sub_epi16(descs_hi[0], pad_len1);
		}
		if (split_packet) {
			rte_mbuf_prefetch_part2(rx_pkts[pos]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 1]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 2]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 3]);
		}
		rte_compiler_barrier();

		descs_hi[3] = _mm_loadu_si128((__m128i *)(rxdp + 3));
		descs_hi[2] = _mm_loadu_si128((__m128i *)(rxdp + 2));
		descs_hi[1] = _mm_loadu_si128((__m128i *)(rxdp + 1));
		descs_hi[0] = _mm_loadu_si128((__m128i *)(rxdp));

		sterr_tmp2 = _mm_unpackhi_epi32(descs_lo[3], descs_lo[2]);
		sterr_tmp1 = _mm_unpackhi_epi32(descs_lo[1], descs_lo[0]);
		pkt_mb4 = _mm_shuffle_epi8(descs_hi[3], shuf_msk);
		pkt_mb3 = _mm_shuffle_epi8(descs_hi[2], shuf_msk);
		pkt_mb2 = _mm_shuffle_epi8(descs_hi[1], shuf_msk);
		pkt_mb1 = _mm_shuffle_epi8(descs_hi[0], shuf_msk);
		staterr = _mm_unpackhi_epi32(sterr_tmp1, sterr_tmp2);
		eop_flags = staterr;
		staterr = _mm_and_si128(staterr, dd_check);

		pkt_mb4 = _mm_add_epi16(pkt_mb4, crc_adjust);
		pkt_mb3 = _mm_add_epi16(pkt_mb3, crc_adjust);

		pkt_mb2 = _mm_add_epi16(pkt_mb2, crc_adjust);
		pkt_mb1 = _mm_add_epi16(pkt_mb1, crc_adjust);

		if (split_packet) {
			__m128i eop_shuf_mask = _mm_set_epi8(
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0x04, 0x0C, 0x00, 0x08);
			__m128i eop_bits = _mm_andnot_si128(eop_flags, eop_check);
			eop_bits = _mm_shuffle_epi8(eop_bits, eop_shuf_mask);
			*(int *)split_packet = _mm_cvtsi128_si32(eop_bits);
			split_packet += RTE_MCE_DESCS_PER_LOOP;
			/* zero-out next pointers */
			rx_pkts[pos]->next = NULL;
			rx_pkts[pos + 1]->next = NULL;
			rx_pkts[pos + 2]->next = NULL;
			rx_pkts[pos + 3]->next = NULL;
		}
		staterr = _mm_packs_epi32(staterr, zero);
		var = __builtin_popcountll(_mm_cvtsi128_si64(staterr));
		_mm_storeu_si128(
			(void *)&rx_pkts[pos + 3]->rx_descriptor_fields1,
			pkt_mb4);
		_mm_storeu_si128(
			(void *)&rx_pkts[pos + 2]->rx_descriptor_fields1,
			pkt_mb3);
		_mm_storeu_si128(
			(void *)&rx_pkts[pos + 1]->rx_descriptor_fields1,
			pkt_mb2);
		_mm_storeu_si128(
			(void *)&rx_pkts[pos + 0]->rx_descriptor_fields1,
			pkt_mb1);
		mce_rx_desc_parse_field(rxq, descs_lo, &rx_pkts[pos]);
		mce_desc_to_ptype(descs_lo, &rx_pkts[pos]);
		nb_pkts_recd += var;
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 0].mbuf);
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 1].mbuf);
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 2].mbuf);
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 3].mbuf);
		if (likely(var != RTE_MCE_DESCS_PER_LOOP))
			break;
	}
	/* Update our internal tail pointer */
	rxq->rx_tail = (uint16_t)(rxq->rx_tail + nb_pkts_recd);
	rxq->rx_tail = (uint16_t)(rxq->rx_tail & (rxq->attr.nb_desc - 1));
	rxq->rxrearm_nb = (uint16_t)(rxq->rxrearm_nb + nb_pkts_recd);

	return nb_pkts_recd;
}

uint16_t mce_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts)
{
	struct mce_rx_queue *rxq = (struct mce_rx_queue *)rx_queue;
	uint16_t nb_rx = 0, n, ret;

	if (unlikely(!rx_queue))
		return 0;

	if (likely(nb_pkts <= MCE_RX_MAX_BURST_SIZE))
		return _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts, NULL);

	while (nb_pkts) {
		n = RTE_MIN(nb_pkts, MCE_RX_MAX_BURST_SIZE);
		/* Avoid Cache-Miss Cause Tx HardFault TODO Analyze This
		 * Problem
		 */
		ret = _recv_raw_pkts_vec(rxq, &rx_pkts[nb_rx], n, NULL);
		nb_rx = (uint16_t)(nb_rx + ret);
		nb_pkts = (uint16_t)(nb_pkts - ret);
		if (ret < n)
			break;
	}

	return nb_rx;
}

static uint16_t
mce_recv_scattered_burst_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			     uint16_t nb_pkts)
{
	struct mce_rx_queue *rxq = rx_queue;
	uint8_t split_flags[32] = {0};

	/* get some new buffers */
	uint16_t nb_bufs = _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts, split_flags);
	if (nb_bufs == 0)
		return 0;

	/* happy day case, full burst + no packets to be joined */
	const uint64_t *split_fl64 = (uint64_t *)split_flags;

	if (!rxq->pkt_first_seg &&
			split_fl64[0] == 0 && split_fl64[1] == 0 &&
			split_fl64[2] == 0 && split_fl64[3] == 0)
		return nb_bufs;

	/* reassemble any packets that need reassembly*/
	unsigned int i = 0;

	if (!rxq->pkt_first_seg) {
		/* find the first split flag, and only reassemble then*/
		while (i < nb_bufs && !split_flags[i])
			i++;
		if (i == nb_bufs)
			return nb_bufs;
		rxq->pkt_first_seg = rx_pkts[i];
	}
	return i + mce_rx_reassemble_packets(rxq, &rx_pkts[i], nb_bufs - i, &split_flags[i]);
}

/**
 * vPMD receive routine that reassembles scattered packets.
 */
uint16_t
mce_recv_scattered_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			    uint16_t nb_pkts)
{
	uint16_t retval = 0;

	while (nb_pkts > 32) {
		uint16_t burst;

		burst = mce_recv_scattered_burst_vec(rx_queue,
				rx_pkts + retval,
				32);
		retval += burst;
		nb_pkts -= burst;
		if (burst < 32)
			return retval;
	}

	return retval + mce_recv_scattered_burst_vec(rx_queue,
			rx_pkts + retval,
			nb_pkts);
}
