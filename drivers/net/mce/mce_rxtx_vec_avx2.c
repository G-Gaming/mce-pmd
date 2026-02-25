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

#include <rte_vect.h>

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

#define RTE_MCE_DESCS_PER_LOOP (8)
static inline void mce_rxq_rearm(struct mce_rx_queue *rxq);

#if 0
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
#endif

#define PKTLEN_SHIFT		 (0)
#define RTE_MCE_RXQ_REARM_THRESH (32)

static inline void mce_rxq_rearm(struct mce_rx_queue *rxq)
{
	struct mce_rxsw_entry *rxep = &rxq->sw_ring[rxq->rxrearm_start];
	volatile union mce_rx_desc *rxdp;
	struct rte_mbuf *mb0, *mb1;
	uint16_t rx_id;
	int i;

	__m256i dma_addr0;
	rxdp = rxq->rx_bdr + rxq->rxrearm_start;
	/* Pull 'n' more MBUFs into the software ring */
	if (rte_mempool_get_bulk(rxq->mb_pool, (void **)rxep,
				 RTE_MCE_RXQ_REARM_THRESH) < 0) {
		if (rxq->rxrearm_nb + RTE_MCE_RXQ_REARM_THRESH >=
		    rxq->attr.nb_desc) {
			dma_addr0 = _mm256_set1_epi32(0);
			for (i = 0; i < RTE_MCE_DESCS_PER_LOOP; i++) {
				rxep[i].mbuf = &rxq->fake_mbuf;
				_mm256_store_si256((__m256i *)&rxdp[i].d.pkt_addr,
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

static void print256_num(__m256i var)
{
        /* can also use uint32_t instead of 16_t */
        uint32_t *val = (uint32_t *)&var;
        printf("Numerical: 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x 0x%.2x \n", val[0], val[1], val[2],
               val[3], val[4], val[5], val[6], val[7]);
}

static __m256i
mce_desc_to_mark(__m256i raw_6_7, __m256i raw_4_5,
	     __m256i raw_2_3, __m256i raw_0_1)
{
	__m256i idx_a_only = _mm256_setr_epi32(1, 3, 5, 7, 0x80, 0x80, 0x80, 0x80);
	const __m256i mark_msk = _mm256_set1_epi32(0x0000FFFF);
	__m256i combine1, combine0;
	__m256i result_a, result_b;
	__m256i mark;

	combine1 = _mm256_unpacklo_epi64(raw_4_5, raw_6_7);
	combine0 = _mm256_unpacklo_epi64(raw_0_1, raw_2_3);
	result_b = _mm256_permutevar8x32_epi32(combine1, idx_a_only);
	result_a = _mm256_permutevar8x32_epi32(combine0, idx_a_only);

	mark = _mm256_permute2x128_si256(result_a, result_b, 0x20);
	mark = _mm256_and_si256(mark, mark_msk);

	return mark;
}

static __rte_always_inline __m256i
mce_rxd_to_fdir_flags_vec_avx2(const __m256i fdir_marks)
{
        RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR != (1 << 2));
        RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR_ID != (1 << 13));
        const __m256i pkt_fdir_bit = _mm256_set1_epi32(RTE_MBUF_F_RX_FDIR |
                        RTE_MBUF_F_RX_FDIR_ID);
        /* desc->flow_id field == 0xFFFFFFFF means fdir mismatch */
        const __m256i fdir_mis_mask = _mm256_set1_epi32(0x0000FFFF);
        __m256i fdir_mask = _mm256_cmpeq_epi32(fdir_marks,
                        fdir_mis_mask);
        /* this XOR op results to bit-reverse the fdir_mask */
        fdir_mask = _mm256_xor_si256(fdir_mask, fdir_mis_mask);
        const __m256i fdir_flags = _mm256_and_si256(fdir_mask, pkt_fdir_bit);

        return fdir_flags;
}

static __m256i mce_generate_l3_l4_flag(struct mce_rx_queue *rxq)
{
	uint8_t *bytes = rxq->l3_l4_cksum;

	return _mm256_set_epi8(
			bytes[15], bytes[14], bytes[13], bytes[12],
			bytes[11], bytes[10], bytes[9],  bytes[8],
			bytes[7],  bytes[6],  bytes[5],  bytes[4],
			bytes[3],  bytes[2],  bytes[1],  bytes[0],
			/* second descriptor*/
			bytes[15], bytes[14], bytes[13], bytes[12],
			bytes[11], bytes[10], bytes[9],  bytes[8],
			bytes[7],  bytes[6],  bytes[5],  bytes[4],
			bytes[3],  bytes[2],  bytes[1],  bytes[0]
			);
}

static inline __m256i
mce_rx_desc_parse_field(struct mce_rx_queue *rxq,
			__m256i raw_6_7, __m256i raw_4_5,
			__m256i raw_2_3, __m256i raw_0_1)
{
	__m256i err_cmd, rss_vlan, l3_l4e;
	__m256i flags = _mm256_set1_epi32(0);
	__m256i combine0, combine1, combines;
	__m256i csum_msk = _mm256_set1_epi32(0x3c0000);
	__m256i result;
	const __m256i permute_mask = _mm256_set_epi32(6, 2, 4, 0, 7, 3, 5, 1);
	const __m256i cksum_mask = _mm256_set1_epi32(
			RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_L4_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD |
			RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD
			);
	const __m256i rss_vlan_mk = _mm256_set1_epi32(0xF000000);
	const __m256i rss_vlan_flag = _mm256_set_epi8(
			RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_RSS_HASH,
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
			RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_FDIR, 0,
			/* secondary descriptor */
			RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_RSS_HASH,
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
			RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_FDIR, 0
			);
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
	const __m256i l3_l4e_flags = mce_generate_l3_l4_flag(rxq);

	combine1 = _mm256_unpackhi_epi64(raw_4_5, raw_6_7);
	combine0 = _mm256_unpackhi_epi64(raw_0_1, raw_2_3);

	__m256i idx_b_only = _mm256_setr_epi32(0, 2, 4, 6, 0x80, 0x80, 0x80, 0x80);
	__m256i idx_a_only = _mm256_setr_epi32(1, 3, 5, 7, 0x80, 0x80, 0x80, 0x80);

	__m256i result_b = _mm256_permutevar8x32_epi32(combine1, idx_b_only);
	__m256i result_a = _mm256_permutevar8x32_epi32(combine0, idx_b_only);
	__m256i combined = _mm256_permute2x128_si256(result_a, result_b, 0x20); // 调整控制字以达到正确顺序

	err_cmd = combined;
	rss_vlan = _mm256_and_si256(err_cmd, rss_vlan_mk);
	rss_vlan = _mm256_srli_epi64(rss_vlan, 24);
	rss_vlan = _mm256_shuffle_epi8(rss_vlan_flag, rss_vlan);
	flags = rss_vlan;
	if (rxq->rx_offload_capa & (RTE_ETH_RX_OFFLOAD_CHECKSUM |
				RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
				RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM |
				RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM)) {
		const __m256i l3_l4_flag_mask = _mm256_set1_epi32(~0x00000006);
		const __m256i l4_outer_mask = _mm256_set1_epi32(0x00000006);
		const __m256i tunnel_msk = _mm256_set1_epi32(0x7);
		const __m256i tunnel_mask_val = _mm256_set1_epi32(0x0000e000);
		__m256i tunnel_flag;
		result_b = _mm256_permutevar8x32_epi32(combine1, idx_a_only);
		result_a = _mm256_permutevar8x32_epi32(combine0, idx_a_only);

		tunnel_flag = _mm256_permute2x128_si256(result_a, result_b, 0x20);
		tunnel_flag = _mm256_srli_epi32(tunnel_flag, 13);
		__m256i and_result = _mm256_and_si256(tunnel_flag, tunnel_msk);
		__m256i zero = _mm256_set1_epi32(0);
		__m256i outer_l4_flags;
		__m256i l3_l4e_shifted;
		__m256i part2, part1;
		__m256i l3_l4_flags;

		__m256i cmp_mask_temp = _mm256_and_si256(and_result, tunnel_msk);
		__m256i cmp_mask = _mm256_cmpeq_epi32(cmp_mask_temp, zero);

		l3_l4e = _mm256_and_si256(err_cmd, csum_msk);
		l3_l4e = _mm256_srli_epi32(l3_l4e, 16 + 2);
		/* according tunnel_flag to select cksum is inner or outer */
		l3_l4e_shifted = _mm256_slli_epi32(l3_l4e, 2);
		part1 = _mm256_and_si256(cmp_mask, l3_l4e_shifted);
		part2 = _mm256_andnot_si256(cmp_mask, l3_l4e);
		l3_l4e = _mm256_or_si256(part1, part2);
		l3_l4_flags = _mm256_shuffle_epi8(l3_l4e_flags, l3_l4e);
		l3_l4_flags = _mm256_slli_epi32(l3_l4_flags, 1);
		/* extract the outer l4 bit 21 chksum err*/
                outer_l4_flags = _mm256_and_si256(l3_l4_flags, l4_outer_mask);
                outer_l4_flags = _mm256_slli_epi32(outer_l4_flags, 20);
		l3_l4_flags = _mm256_or_si256(l3_l4_flags, outer_l4_flags);
		l3_l4_flags = _mm256_and_si256(l3_l4_flags, cksum_mask);
		flags = _mm256_or_si256(flags, l3_l4_flags);

	}
	return flags;
}

static inline __m256i
mce_desc_to_ptype(__m256i raw_6_7, __m256i raw_4_5,
		  __m256i raw_2_3, __m256i raw_0_1)
{
	__m256i combine1, combine0, combines;
	__m256i result_a, result_b;
	const __m256i ptype_msk = _mm256_set1_epi32(0xFFFFFC);
	__m256i result;

	__m256i idx_a_only = _mm256_setr_epi32(1, 3, 5, 7, 0x80, 0x80, 0x80, 0x80);
	combine1 = _mm256_unpackhi_epi64(raw_4_5, raw_6_7);
	combine0 = _mm256_unpackhi_epi64(raw_0_1, raw_2_3);

	result_b = _mm256_permutevar8x32_epi32(combine1, idx_a_only);
	result_a = _mm256_permutevar8x32_epi32(combine0, idx_a_only);
	result = _mm256_permute2x128_si256(result_a, result_b, 0x20);
	result = _mm256_and_si256(result, ptype_msk);
	result = _mm256_srli_epi32(result, 2);

	return result;
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

	__m256i shuf_msk;
	__m256i eop_check;
	/* constants used in processing loop */
	const __m256i crc_adjust =
		_mm256_set_epi16
		(/* first descriptor */
		 0, 0, 0,       /* ignore non-length fields */
		 -rxq->strip_len, /* sub crc on data_len */
		 0,             /* ignore high-16bits of pkt_len */
		 -rxq->strip_len, /* sub crc on pkt_len */
		 0, 0,          /* ignore pkt_type field */
		 /* second descriptor */
		 0, 0, 0,       /* ignore non-length fields */
		 -rxq->strip_len, /* sub crc on data_len */
		 0,             /* ignore high-16bits of pkt_len */
		 -rxq->strip_len, /* sub crc on pkt_len */
		 0, 0           /* ignore pkt_type field */
		);
	eop_check = _mm256_set_epi64x(0x1000000010000ULL, 0x1000000010000ULL,
			0x1000000010000ULL, 0x1000000010000ULL);
	/*
	 * compile-time check the above crc_adjust layout is correct.
	 * NOTE: the first field (lowest address) is given last in set_epi16
	 * call above.
	 */

	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			 offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	/* nb_pkts has to be floor-aligned to RTE_MCE_DESCS_PER_LOOP */
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, RTE_MCE_DESCS_PER_LOOP);

	/* Just the act of getting into the function from the application is
	 * going to cost about 7 cycles
	 */
	rxdp = rxq->rx_bdr + rxq->rx_tail;

	rte_prefetch0(rxdp);
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
	/* mask to shuffle from desc. to mbuf */
	shuf_msk = _mm256_set_epi8(
				3, 2, 1, 0, /* octet 0~3, 32bits rss */
				9, 8,       /* octet 2~3, low 16 bits vlan_macip */
				5, 4,       /* octet 15~14, 16 bits data_len */
				0xFF,
				0xFF,       /* skip high 16 bits pkt_len, zero out */
				5, 4,       /* octet 15~14, low 16 bits pkt_len */
				0xFF, 0xFF, /* pkt_type set as unknown */
				0xFF, 0xFF,  /*pkt_type set as unknown */
				/* second descriptor*/
				3, 2, 1, 0, /* octet 0~3, 32bits rss */
				9, 8,       /* octet 2~3, low 16 bits vlan_macip */
				5, 4,       /* octet 15~14, 16 bits data_len */
				0xFF,
				0xFF,       /* skip high 16 bits pkt_len, zero out */
				5, 4,       /* octet 15~14, low 16 bits pkt_len */
				0xFF, 0xFF, /* pkt_type set as unknown */
				0xFF, 0xFF  /*pkt_type set as unknown */
			);
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

	const __m256i mbuf_init = _mm256_set_epi64x(0, 0, 0, rxq->mbuf_initializer);
	const __m256i permute_mask = _mm256_set_epi32(6, 2, 4, 0, 7, 3, 5, 1);
	const __m256i eop_mask = _mm256_set1_epi32(0x10000);
	const __m256i dd_mask = _mm256_set1_epi32(0x20000);

	const __m256i mask_0_1 = _mm256_setr_epi8(
			0x00, 0x01, 0x02, 0x03,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x04, 0x05, 0x06, 0x07,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF
			);
	const __m256i mask_2_3 = _mm256_setr_epi8(
			0x08, 0x09, 0x0A, 0x0B,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x0C, 0x0D, 0x0E, 0x0F,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF
			);
	const __m256i mask_4_5 = _mm256_setr_epi8(
			0x10, 0x11, 0x12, 0x13,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x14, 0x15, 0x16, 0x17,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF
			);
	const __m256i mask_6_7 = _mm256_setr_epi8(
			0x18, 0x19, 0x1A, 0x1B,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x1C, 0x1D, 0x1E, 0x1F,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF
			);

	uint32_t ptypes[8];
	sw_ring = &rxq->sw_ring[rxq->rx_tail];
	for (pos = 0, nb_pkts_recd = 0; pos < nb_pkts;
	     pos += RTE_MCE_DESCS_PER_LOOP, rxdp += RTE_MCE_DESCS_PER_LOOP) {
		__m256i rearm0, rearm1, rearm2, rearm3, rearm4, rearm5, rearm6, rearm7;
		__m256i pkt_mb_6_7, pkt_mb_4_5, pkt_mb_2_3, pkt_mb_0_1;
		__m256i mbuf_6_7, mbuf_4_5, mbuf_2_3, mbuf_0_1;
		__m256i raw_6_7, raw_4_5, raw_2_3, raw_0_1;
		__m256i staterr, sterr_tmp1, sterr_tmp2;
		__m256i descs[RTE_MCE_DESCS_PER_LOOP];
		__m256i combine0, combine1, combines;
		__m256i result, cmp_result;
		__m256i eop_flags;

		 _mm256_storeu_si256((void *)&rx_pkts[pos],
				 _mm256_loadu_si256((void *)&sw_ring[pos]));
#ifdef RTE_ARCH_X86_64
		 _mm256_storeu_si256
			 ((void *)&rx_pkts[pos + 4],
			  _mm256_loadu_si256((void *)&sw_ring[pos + 4]));
#endif
		if (split_packet) {
			rte_mbuf_prefetch_part2(rx_pkts[pos]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 1]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 2]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 3]);
		}
		descs[7] = _mm256_loadu_si256((__m256i *)(rxdp + 7));
		rte_compiler_barrier();
		descs[6] = _mm256_loadu_si256((__m256i *)(rxdp + 6));
		rte_compiler_barrier();
		descs[5] = _mm256_loadu_si256((__m256i *)(rxdp + 5));
		rte_compiler_barrier();
		descs[4] = _mm256_loadu_si256((__m256i *)(rxdp + 4));
		rte_compiler_barrier();
		descs[3] = _mm256_loadu_si256((__m256i *)(rxdp + 3));
		rte_compiler_barrier();
		descs[2] = _mm256_loadu_si256((__m256i *)(rxdp + 2));
		rte_compiler_barrier();
		descs[1] = _mm256_loadu_si256((__m256i *)(rxdp + 1));
		rte_compiler_barrier();
		descs[0] = _mm256_loadu_si256((__m256i *)(rxdp));

		raw_6_7 = _mm256_permute2f128_si256(descs[6], descs[7], 0x31);
		raw_4_5 = _mm256_permute2f128_si256(descs[5], descs[4], 0x31);
		raw_2_3 = _mm256_permute2f128_si256(descs[2], descs[3], 0x31);
		raw_0_1 = _mm256_permute2f128_si256(descs[0], descs[1], 0x31);

		mbuf_6_7 = _mm256_permute2f128_si256(descs[6], descs[7], 0x20);
		mbuf_4_5 = _mm256_permute2f128_si256(descs[5], descs[4], 0x20);
		mbuf_2_3 = _mm256_permute2f128_si256(descs[2], descs[3], 0x20);
		mbuf_0_1 = _mm256_permute2f128_si256(descs[0], descs[1], 0x20);
		/* descs[3] = [a1, a2, a3, a4, a5, a6, a7, a8
		 * low 128bit a1,a2,a3,a4, high 128bit a5,a6,a7,a8
		 * imm8 = 0x31
		 * descs[2] = [b1, b2, b3, b4, b5, b6, b7, b8
		 * low 128bit b1,b2,b3,b4, high 128bit b5,b6,b7,b8
		 * imm8 = 0x31
		 * a4, a5, a6, a7, b4, b5, b6, b7
		 * dd cmd is at 8
		 * imm8 = 0x20,
		 * a1, a2, a3, a4, b1, b2, b3, b4
		 */
		pkt_mb_6_7 = _mm256_shuffle_epi8(mbuf_6_7, shuf_msk);
		pkt_mb_4_5 = _mm256_shuffle_epi8(mbuf_4_5, shuf_msk);
		pkt_mb_2_3 = _mm256_shuffle_epi8(mbuf_2_3, shuf_msk);
		pkt_mb_0_1 = _mm256_shuffle_epi8(mbuf_0_1, shuf_msk);

		pkt_mb_6_7 = _mm256_add_epi16(pkt_mb_6_7, crc_adjust);
		pkt_mb_4_5 = _mm256_add_epi16(pkt_mb_4_5, crc_adjust);
		pkt_mb_2_3 = _mm256_add_epi16(pkt_mb_2_3, crc_adjust);
		pkt_mb_0_1 = _mm256_add_epi16(pkt_mb_0_1, crc_adjust);
		__m256i mbuf_flags = mce_rx_desc_parse_field(rxq, raw_6_7, raw_4_5,
							     raw_2_3, raw_0_1);
		__m256i mbuf_ptypes = mce_desc_to_ptype(raw_6_7, raw_4_5,
				raw_2_3, raw_0_1);
		if (1) {
			__m256i mbuf_marks = mce_desc_to_mark(raw_6_7, raw_4_5, raw_2_3, raw_0_1);
			__m256i fdir_flags = mce_rxd_to_fdir_flags_vec_avx2(mbuf_marks);
			/* write to mbuf: have to use scalar store here */
#if 1
			uint32_t marks_tmp[8];
			int mi = 0;
			_mm256_storeu_si256((__m256i *)marks_tmp, mbuf_marks);
#if 0
			for (int mi = 0; mi < 8; mi += 2) {
				rx_pkts[pos + mi]->hash.fdir.hi     = marks_tmp[mi];
				rx_pkts[pos + mi + 1]->hash.fdir.hi = marks_tmp[mi + 1];
			}
#endif
			rx_pkts[pos + 0]->hash.fdir.hi = marks_tmp[0];
			rx_pkts[pos + 1]->hash.fdir.hi = marks_tmp[1];
			rx_pkts[pos + 2]->hash.fdir.hi = marks_tmp[2];
			rx_pkts[pos + 3]->hash.fdir.hi = marks_tmp[3];
			rx_pkts[pos + 4]->hash.fdir.hi = marks_tmp[4];
			rx_pkts[pos + 5]->hash.fdir.hi = marks_tmp[5];
			rx_pkts[pos + 6]->hash.fdir.hi = marks_tmp[6];
			rx_pkts[pos + 7]->hash.fdir.hi = marks_tmp[7];
#else
			rx_pkts[pos + 0]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 0);
			rx_pkts[pos + 1]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 1);
			rx_pkts[pos + 2]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 2);

			rx_pkts[pos + 3]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 3);

			rx_pkts[pos + 4]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 4);

			rx_pkts[pos + 5]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 5);

			rx_pkts[pos + 6]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 6);

			rx_pkts[pos + 7]->hash.fdir.hi =
				_mm256_extract_epi32(mbuf_marks, 7);
#endif
			mbuf_flags = _mm256_or_si256(mbuf_flags, fdir_flags);
		}
#if 0
		const uint32_t ptype7 = _mm256_extract_epi32(mbuf_ptypes, 7);
		const uint32_t ptype6 = _mm256_extract_epi32(mbuf_ptypes, 6);
		const uint32_t ptype5 = _mm256_extract_epi32(mbuf_ptypes, 5);
		const uint32_t ptype4 = _mm256_extract_epi32(mbuf_ptypes, 4);
		const uint32_t ptype3 = _mm256_extract_epi32(mbuf_ptypes, 3);
		const uint32_t ptype2 = _mm256_extract_epi32(mbuf_ptypes, 2);
		const uint32_t ptype1 = _mm256_extract_epi32(mbuf_ptypes, 1);
		const uint32_t ptype0 = _mm256_extract_epi32(mbuf_ptypes, 0);

		pkt_mb_6_7 = _mm256_insert_epi32(pkt_mb_6_7, mce_get_rx_parse_ptype(ptype7), 4);
		pkt_mb_6_7 = _mm256_insert_epi32(pkt_mb_6_7, mce_get_rx_parse_ptype(ptype6), 0);
		pkt_mb_4_5 = _mm256_insert_epi32(pkt_mb_4_5, mce_get_rx_parse_ptype(ptype5), 4);
		pkt_mb_4_5 = _mm256_insert_epi32(pkt_mb_4_5, mce_get_rx_parse_ptype(ptype4), 0);

		pkt_mb_2_3 = _mm256_insert_epi32(pkt_mb_2_3, mce_get_rx_parse_ptype(ptype3), 4);
		pkt_mb_2_3 = _mm256_insert_epi32(pkt_mb_2_3, mce_get_rx_parse_ptype(ptype2), 0);
		pkt_mb_0_1 = _mm256_insert_epi32(pkt_mb_0_1, mce_get_rx_parse_ptype(ptype1), 4);
		pkt_mb_0_1 = _mm256_insert_epi32(pkt_mb_0_1, mce_get_rx_parse_ptype(ptype0), 0);
#else
		uint32_t transformed[8];

		_mm256_storeu_si256((__m256i *)ptypes, mbuf_ptypes);
		transformed[0] = mce_get_rx_parse_ptype(ptypes[0]);
		transformed[1] = mce_get_rx_parse_ptype(ptypes[1]);
		transformed[2] = mce_get_rx_parse_ptype(ptypes[2]);
		transformed[3] = mce_get_rx_parse_ptype(ptypes[3]);
		transformed[4] = mce_get_rx_parse_ptype(ptypes[4]);
		transformed[5] = mce_get_rx_parse_ptype(ptypes[5]);
		transformed[6] = mce_get_rx_parse_ptype(ptypes[6]);
		transformed[7] = mce_get_rx_parse_ptype(ptypes[7]);
		__m256i trans_vec = _mm256_loadu_si256((__m256i *)transformed);

		pkt_mb_0_1 = _mm256_or_si256(pkt_mb_0_1, _mm256_shuffle_epi8(trans_vec, mask_0_1));
		pkt_mb_2_3 = _mm256_or_si256(pkt_mb_2_3, _mm256_shuffle_epi8(trans_vec, mask_2_3));
		pkt_mb_4_5 = _mm256_or_si256(pkt_mb_4_5, _mm256_shuffle_epi8(trans_vec, mask_0_1));
		pkt_mb_6_7 = _mm256_or_si256(pkt_mb_6_7, _mm256_shuffle_epi8(trans_vec, mask_2_3));
#endif
		combine0 = _mm256_unpackhi_epi32(_mm256_srli_epi64(raw_4_5, 16),
						 _mm256_srli_epi64(raw_6_7, 16));
		combine1 = _mm256_unpackhi_epi32(_mm256_srli_epi64(raw_0_1, 16),
						 _mm256_srli_epi64(raw_2_3, 16));
		combines = _mm256_unpacklo_epi32(combine0, combine1);
		eop_flags = _mm256_and_si256(combines, eop_mask);
		combines = _mm256_and_si256(combines, dd_mask);
		result = _mm256_permutevar8x32_epi32(combines, permute_mask);
		eop_flags = _mm256_permutevar8x32_epi32(eop_flags, permute_mask);
		cmp_result = _mm256_cmpeq_epi32(result, dd_mask);
		var = __builtin_ctzll(~(_mm256_movemask_ps(_mm256_castsi256_ps(cmp_result))));
		rearm0 = _mm256_blend_epi32(mbuf_init,
				_mm256_slli_si256(mbuf_flags, 8),
				0x04);
		rearm2 = _mm256_blend_epi32(mbuf_init, mbuf_flags,
				0x04);
		rearm1 = _mm256_blend_epi32(mbuf_init,
				_mm256_slli_si256(mbuf_flags, 4),
				0x04);
		rearm3 = _mm256_blend_epi32(mbuf_init,
				_mm256_srli_si256(mbuf_flags, 4),
				0x04);
		rearm0 = _mm256_permute2f128_si256(rearm0, pkt_mb_0_1, 0x20);
		rearm2 = _mm256_permute2f128_si256(rearm2, pkt_mb_2_3, 0x20);
		rearm1 = _mm256_blend_epi32(rearm5, pkt_mb_0_1, 0xF0);
		rearm3 = _mm256_blend_epi32(rearm3, pkt_mb_2_3, 0xF0);
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 0]->rearm_data,
				rearm0);
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 2]->rearm_data,
				rearm2);
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 1]->rearm_data,
				rearm1);
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 3]->rearm_data,
				rearm3);
		const __m256i hi_flags =
			_mm256_castsi128_si256
			(_mm256_extracti128_si256(mbuf_flags, 1));
		rearm4 = _mm256_blend_epi32(mbuf_init,
				_mm256_slli_si256(hi_flags, 8),
				0x04);
		rearm6 = _mm256_blend_epi32(mbuf_init, hi_flags,
				0x04);
		rearm5 = _mm256_blend_epi32(mbuf_init,
				_mm256_slli_si256(hi_flags, 4),
				0x04);
		rearm7 = _mm256_blend_epi32(mbuf_init,
				_mm256_srli_si256(hi_flags, 4),
				0x04);
		/* permute to add in the rx_descriptor e.g. rss fields */
		rearm4 = _mm256_permute2f128_si256(rearm4, pkt_mb_4_5, 0x20);
		rearm6 = _mm256_permute2f128_si256(rearm6, pkt_mb_6_7, 0x20);
		rearm5 = _mm256_blend_epi32(rearm5, pkt_mb_4_5, 0xF0);
		/* since odd mbufs are already in hi 128-bits use blend */
		rearm7 = _mm256_blend_epi32(rearm7, pkt_mb_6_7, 0xF0);
		/* write to mbuf */
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 4]->rearm_data,
				rearm4);
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 6]->rearm_data,
				rearm6);
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 5]->rearm_data,
				rearm5);
		_mm256_storeu_si256((__m256i *)&rx_pkts[pos + 7]->rearm_data,
				rearm7);
		if (split_packet) {
			__m256i eop_shuf_mask = _mm256_setr_epi8(
					0, 4, 8, 12, 16, 20, 24, 28,
					0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
					0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
					0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
					);
			__m256i eop_bits = _mm256_andnot_si256(eop_flags, eop_check);
			eop_bits = _mm256_srli_epi32(eop_bits, 16);
			eop_bits = _mm256_shuffle_epi8(eop_bits, eop_shuf_mask);
			*(uint64_t *)split_packet = _mm256_extract_epi64(eop_bits, 0);
			split_packet += RTE_MCE_DESCS_PER_LOOP;
			/* zero-out next pointers */
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 0].mbuf);
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 1].mbuf);
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 2].mbuf);
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 3].mbuf);
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 5].mbuf);
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 6].mbuf);
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 7].mbuf);
			rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 8].mbuf);
		}
		nb_pkts_recd += var;
		if (likely(var != RTE_MCE_DESCS_PER_LOOP))
			break;
		rte_prefetch0(rxdp + 8);
	}
	/* Update our internal tail pointer */
	rxq->rx_tail = (uint16_t)(rxq->rx_tail + nb_pkts_recd);
	rxq->rx_tail = (uint16_t)(rxq->rx_tail & (rxq->attr.nb_desc - 1));
	rxq->rxrearm_nb = (uint16_t)(rxq->rxrearm_nb + nb_pkts_recd);

	return nb_pkts_recd;
}

uint16_t mce_recv_pkts_vec_avx2(void *rx_queue, struct rte_mbuf **rx_pkts,
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
mce_recv_scattered_pkts_vec_avx2(void *rx_queue, struct rte_mbuf **rx_pkts,
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
uint16_t mce_xmit_fixed_burst_vec_avx2(void *tx_queue, struct rte_mbuf **tx_pkts,
				  uint16_t nb_pkts)
{
	return 0;
}
