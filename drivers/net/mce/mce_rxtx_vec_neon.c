#include <stdint.h>
#include <stdlib.h>

#include <rte_malloc.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(16, 11, 0, 0) <= RTE_VERSION
#include <rte_mbuf.h>
#include <rte_net.h>
#endif
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memzone.h>

#include "base/mce_hw.h"
#include "base/mce_ptype.h"
#include "mce_rxtx_vec.h"
#include "mce_rxtx.h"
#include "mce_logs.h"
#include "mce.h"

#include <arm_neon.h>

#pragma GCC diagnostic ignored "-Wcast-qual"
#define MCE_RX_MAX_BURST_SIZE	(32)

static __rte_always_inline int
mce_tx_free_bufs(struct mce_tx_queue *txq)
{
	struct rte_mbuf *m, **free = txq->free_mbuf;
	struct mce_txsw_entry *txep;
	int nb_free = 0;
	uint32_t n;
	uint32_t i;

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
			if (txep[i].mbuf == NULL)
				continue;
			free[i] = txep[i].mbuf;
			txep[i].mbuf = NULL;
			nb_free++;
		}
		if (nb_free)
			rte_mempool_put_bulk(free[0]->pool,
					(void **)free, nb_free);
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
		struct mce_tx_queue *txq,
		struct mce_txsw_entry *txep,
		struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	uint64_t tx_bytes = 0;
	int i;

	for (i = 0; i < (int)nb_pkts; ++i) {
		txep[i].mbuf = tx_pkts[i];
		if (txep[i].mbuf->data_len > 16 * 1024)
			txep[i].mbuf->data_len = 0;
	}
	RTE_SET_USED(txq);

	return tx_bytes;
}

static inline void
vtx1(struct mce_tx_queue *txq,
     volatile union mce_tx_desc *txdp,
     struct rte_mbuf *pkt, uint64_t flags)
{
	uint64_t high_qw = (uint64_t)pkt->data_len;

#if RTE_VERSION_NUM(17, 11, 0, 0) >  RTE_VERSION
	uint64x2_t descriptor = {pkt->buf_physaddr + pkt->data_off, high_qw};
#else
	uint64x2_t descriptor = {pkt->buf_iova + pkt->data_off, high_qw};
#endif
	vst1q_u64((uint64_t *)txdp, descriptor);
	txdp->d.qword6.cmd = flags;
	RTE_SET_USED(txq);
}

static inline void
vtx(struct mce_tx_queue *txq,
    volatile union mce_tx_desc *txdp,
    struct rte_mbuf **pkt, uint16_t nb_pkts,  uint64_t flags)
{
	int i;

	for (i = 0; i < nb_pkts; ++i, ++txdp, ++pkt)
		vtx1(txq, txdp, *pkt, flags);
}

uint16_t
mce_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
			    uint16_t nb_pkts)
{
	struct mce_tx_queue *txq = (struct mce_tx_queue *)tx_queue;
	uint64_t rs = MCE_CMD_RS | MCE_CMD_EOP;
	volatile union mce_tx_desc *txdp;
	uint16_t n, nb_commit, tx_id;
	uint64_t flags = MCE_CMD_EOP;
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
	tx_backlog_entry(txq, txep, tx_pkts, nb_commit);
	vtx(txq, txdp, tx_pkts, nb_commit, flags);

	tx_id = (uint16_t)(tx_id + nb_commit);
	if (tx_id > txq->tx_next_rs) {
		txq->tx_bdr[txq->tx_next_rs].d.qword6.cmd |= MCE_CMD_RS;
		txq->tx_next_rs =
			(uint16_t)(txq->tx_next_rs + txq->tx_rs_thresh);
	}
	txq->tx_tail = tx_id;

	rte_wmb();
	MCE_REG_ADDR_WRITE(txq->tx_tailreg,  0, tx_id);

	return nb_pkts;
}

#define MCE_UINT16_BIT (CHAR_BIT * sizeof(uint16_t))
static inline void
mce_desc_to_ptype(uint64x2_t descs[4],
		  struct rte_mbuf **rx_pkts)
{
	uint32x4_t ptype_msk = { 0xFFFFFC, 0xFFFFFC,
				 0xFFFFFC, 0xFFFFFC };
	uint32x4_t combine0, combine1, ptypes;
	uint32_t ptype[4];

	/* Get High Four Desc 64 Bit */
	combine0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
			vreinterpretq_u32_u64(descs[2])).val[1];
	combine1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
			vreinterpretq_u32_u64(descs[3])).val[1];
	/* Get High 32-Bit */
	ptypes = vzipq_u32(combine0, combine1).val[1];
	ptypes = vandq_u32(ptypes, ptype_msk);
	ptypes = vshrq_n_u32(ptypes, 2);
	ptype[0] = vgetq_lane_u32(ptypes, 0);
	ptype[1] = vgetq_lane_u32(ptypes, 1);
	ptype[2] = vgetq_lane_u32(ptypes, 2);
	ptype[3] = vgetq_lane_u32(ptypes, 3);
	rx_pkts[0]->packet_type = mce_get_rx_parse_ptype(ptype[0]);
	rx_pkts[1]->packet_type = mce_get_rx_parse_ptype(ptype[1]);
	rx_pkts[2]->packet_type = mce_get_rx_parse_ptype(ptype[2]);
	rx_pkts[3]->packet_type = mce_get_rx_parse_ptype(ptype[3]);
}

static uint32x4_t
desc_to_mark(uint64x2_t descs[4], struct rte_mbuf **rx_pkts)
{

	const uint32x4_t mark_msk = {
		0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF};
	uint32x4_t combine0, combine1;
	uint16x8_t mark_turn;
	uint32x4_t fd_id_mask;
	uint32x4_t mark;
	uint32_t val[4] = {0};

	combine0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
			vreinterpretq_u32_u64(descs[2])).val[0];
	combine1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
			vreinterpretq_u32_u64(descs[3])).val[0];
	mark = vzipq_u32(combine0, combine1).val[1];
	mark = vandq_u32(mark, mark_msk);
	mark_turn = vreinterpretq_u16_u32(mark);
	val[0] = vgetq_lane_u16(mark_turn, 0);
	val[1] = vgetq_lane_u16(mark_turn, 2);
	val[2] = vgetq_lane_u16(mark_turn, 4);
	val[3] = vgetq_lane_u16(mark_turn, 6);

	RTE_BUILD_BUG_ON(RTE_MBUF_F_RX_FDIR_ID != (1 << 13));
	fd_id_mask = vtstq_u32(vreinterpretq_u32_u16(mark_turn), mark_msk);
	fd_id_mask = vshrq_n_u32(fd_id_mask, 31);
	fd_id_mask = vshlq_n_u32(fd_id_mask, 13);

	rx_pkts[0]->hash.fdir.hi = val[0];
	rx_pkts[1]->hash.fdir.hi = val[1];
	rx_pkts[2]->hash.fdir.hi = val[2];
	rx_pkts[3]->hash.fdir.hi = val[3];

	return fd_id_mask;
}

static uint8x16_t mce_generate_l3_l4_flag(struct mce_rx_queue *rxq)
{
	uint8_t *bytes = rxq->l3_l4_cksum;

	uint8x16_t l3_l4e_flags = {
		bytes[0], bytes[1], bytes[2], bytes[3],
		bytes[4], bytes[5], bytes[6], bytes[7],
		bytes[8], bytes[9], bytes[10], bytes[11],
		bytes[12], bytes[13], bytes[14], bytes[15],
	};

	return l3_l4e_flags;
}

static inline void
mce_rx_desc_parse_field(struct mce_rx_queue *rxq, uint64x2_t descs[4],
		  struct rte_mbuf **rx_pkts)
{
	uint32x4_t err_cmd, rss_vlan, l3_l4e;
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	union {
		uint16_t e[4];
		uint64_t dword;
	} vol;
#else
	const uint64x2_t mbuf_init = {rxq->mbuf_initializer, 0};
	uint64x2_t rearm[4];
#endif
	uint32x4_t combine0, combine1;
	uint32x4x2_t result;
	uint32x4_t flags;

	/* mask everything except RSS, flow director and VLAN flags
	 * bit2 is for VLAN tag, bit11 for flow director indication
	 * bit13:12 for RSS indication.
	 */

	const uint32x4_t csum_msk = {
		0x7F0000, 0x7F0000, 0x7F0000, 0x7F0000 };
	uint32x4_t tunnel_flag;
	const uint32x4_t cksum_mask = {
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
			RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD
	};
	const uint32x4_t rss_vlan_mk = {
		0xF000000, 0xF000000, 0xF000000, 0xF000000};
	/*
	    #define RTE_MBUF_F_RX_RSS_HASH      (1ULL << 1)
	    #define RTE_MBUF_F_RX_VLAN          (1ULL << 0)
	    #define RTE_MBUF_F_RX_VLAN_STRIPPED (1ULL << 6)
	    #define RTE_MBUF_F_RX_FDIR_ID       (1ULL << 13)
	    #define RTE_MBUF_F_RX_FDIR          (1ULL << 2)
	    #define RTE_MBUF_F_RX_QINQ_STRIPPED (1ULL << 15) >>
	    #define RTE_MBUF_F_RX_QINQ          (1ULL << 20)
	    */
	const uint8x16_t rss_vlan_flag = {
			0, RTE_MBUF_F_RX_FDIR, RTE_MBUF_F_RX_RSS_HASH,
			(RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_RSS_HASH),
			RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 4 */
			RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 5 */
			RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 6*/
			RTE_MBUF_F_RX_RSS_HASH | RTE_MBUF_F_RX_FDIR |
			RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED, /* 7 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13, /* 8 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13 | RTE_MBUF_F_RX_FDIR, /* 9 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13 | RTE_MBUF_F_RX_RSS_HASH, /* 10 */
			(RTE_MBUF_F_RX_QINQ_STRIPPED | RTE_MBUF_F_RX_QINQ) >> 13 | RTE_MBUF_F_RX_FDIR |
			RTE_MBUF_F_RX_RSS_HASH, /* 11 */
			0,/* 12 */
			(RTE_MBUF_F_RX_FDIR), /* 13 */
			(RTE_MBUF_F_RX_RSS_HASH), /* 14 */
			(RTE_MBUF_F_RX_FDIR | RTE_MBUF_F_RX_RSS_HASH)
	};
	/*
	 * #define RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD        (1ULL << 21)
	 * #define RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD       (1ULL << 22)
	 * #define RTE_MBUF_F_RX_L4_CKSUM_BAD		    (1ULL << 3)
	 * #define RTE_MBUF_F_RX_L4_CKSUM_GOOD             (1ULL << 8)
	 * #define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD        (1ULL << 5)
	  */
	/* outer_l4 needt right 20 bit conpose 3,5,8,1,2
	 * so the value after (3,5,8,1,2) >> 1 can store in uint8_t
	 */
#if 0
	const uint8x16_t l3_l4e_flags = {
		 (RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD |
		  RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 |
		  RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		  RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		  RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 |
		  RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 |
		  RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		  RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		  RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_GOOD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20|
		  RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		 (RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 |
		 RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		(RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		 RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		 RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		(RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20| RTE_MBUF_F_RX_IP_CKSUM_BAD |
		 RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD >> 20 |
		 RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		(RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		 RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1,
		(RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD | RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD >> 20 |
		 RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD) >> 1
	};
#else
	const uint8x16_t l3_l4e_flags = mce_generate_l3_l4_flag(rxq);
#endif
	combine0 = vzipq_u32(vreinterpretq_u32_u64(descs[0]),
			vreinterpretq_u32_u64(descs[2])).val[1];
	combine1 = vzipq_u32(vreinterpretq_u32_u64(descs[1]),
			vreinterpretq_u32_u64(descs[3])).val[1];
	result = vzipq_u32(combine0, combine1);
	err_cmd = result.val[0];
	tunnel_flag = result.val[1];
	tunnel_flag = vshrq_n_u32(tunnel_flag, 13);
	rss_vlan = vandq_u32(err_cmd, rss_vlan_mk);
	rss_vlan = vshrq_n_u32(rss_vlan, 24);
	rss_vlan = vreinterpretq_u32_u8(vqtbl1q_u8(rss_vlan_flag,
					vreinterpretq_u8_u32(rss_vlan)));
	flags = rss_vlan;
	/* Rx-checksum Err Parse */
	if (rxq->rx_offload_capa & (RTE_ETH_RX_OFFLOAD_CHECKSUM |
				    RTE_ETH_RX_OFFLOAD_SCTP_CKSUM |
				    RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM)) {
		uint32x4_t l3_l4_flag_mask = {~0x00000006, ~0x00000006,
					    ~0x00000006, ~0x00000006};
		uint32x4_t l4_outer_mask = { 0x00000006, 0x00000006,
					    0x00000006, 0x00000006};
		uint32x4_t tunnel_msk = { 0x7, 0x7, 0x7, 0x7};
		uint32x4_t and_result = vandq_u32(tunnel_flag, tunnel_msk);
		uint32x4_t cmp_mask = vtstq_u32(and_result, tunnel_msk);
		uint32x4_t zero = {0, 0, 0, 0};
		uint32x4_t outer_l4_flags;
		uint32x4_t l3_l4_flags;

		l3_l4e = vandq_u32(err_cmd, csum_msk);
		l3_l4e = vshrq_n_u32(l3_l4e, 16 + 2);
		l3_l4e = vbslq_u32(cmp_mask, l3_l4e, vshlq_n_u32(l3_l4e, 2));
		l3_l4e = vreinterpretq_u32_u8(vqtbl1q_u8(l3_l4e_flags,
					vreinterpretq_u8_u32(l3_l4e)));
		/* then we shift left 1 bit */
		l3_l4e = vshlq_n_u32(l3_l4e, 1);
		outer_l4_flags = vandq_u32(l3_l4e, l4_outer_mask);
		outer_l4_flags = vbslq_u32(cmp_mask, outer_l4_flags, zero);
		outer_l4_flags = vshlq_n_u32(outer_l4_flags, 20);
		l3_l4_flags = vandq_u32(l3_l4e, l3_l4_flag_mask);
		l3_l4e = vorrq_u32(l3_l4_flags, outer_l4_flags);
		/* we need to mask out the redundant bits */
		l3_l4e = vandq_u32(l3_l4e, cksum_mask);
		flags = vorrq_u32(flags, l3_l4e);
	}
	flags = vorrq_u32(flags, desc_to_mark(descs, rx_pkts));
#if RTE_VERSION_NUM(17, 2, 1, 16) >= RTE_VERSION
	vol.e[0] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 0);
	vol.e[1] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 2);
	vol.e[2] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 4);
	vol.e[3] = vgetq_lane_u16(vreinterpretq_u16_u32(flags), 6);

	rx_pkts[0]->ol_flags = vol.e[0];
	rx_pkts[1]->ol_flags = vol.e[1];
	rx_pkts[2]->ol_flags = vol.e[2];
	rx_pkts[3]->ol_flags = vol.e[3];
#else
	rearm[0] = vsetq_lane_u64(vgetq_lane_u32(flags, 0), mbuf_init, 1);
	rearm[1] = vsetq_lane_u64(vgetq_lane_u32(flags, 1), mbuf_init, 1);
	rearm[2] = vsetq_lane_u64(vgetq_lane_u32(flags, 2), mbuf_init, 1);
	rearm[3] = vsetq_lane_u64(vgetq_lane_u32(flags, 3), mbuf_init, 1);

	vst1q_u64((uint64_t *)&rx_pkts[0]->rearm_data, rearm[0]);
	vst1q_u64((uint64_t *)&rx_pkts[1]->rearm_data, rearm[1]);
	vst1q_u64((uint64_t *)&rx_pkts[2]->rearm_data, rearm[2]);
	vst1q_u64((uint64_t *)&rx_pkts[3]->rearm_data, rearm[3]);
#endif
}
#define RTE_MCE_DESCS_PER_LOOP	(4)

static inline void
mce_rxq_rearm(struct mce_rx_queue *rxq)
{
	struct mce_rxsw_entry *rxep = &rxq->sw_ring[rxq->rxrearm_start];
	volatile union mce_rx_desc *rxdp;
	uint64x2_t zero = vdupq_n_u64(0);
	struct rte_mbuf *mb0, *mb1;
	uint16_t rx_id;
	int i;

	rxdp = rxq->rx_bdr + rxq->rxrearm_start;
	/* Pull 'n' more MBUFs into the software ring */
	if (unlikely(rte_mempool_get_bulk(rxq->mb_pool,
					(void *)rxep,
					rxq->rx_free_thresh) < 0)) {
		if (rxq->rxrearm_nb + rxq->rx_free_thresh >=
				rxq->attr.nb_desc) {
			for (i = 0; i < RTE_MCE_DESCS_PER_LOOP; i++) {
				rxep[i].mbuf = &rxq->fake_mbuf;
				vst1q_u64((uint64_t *)&rxdp[i].d, zero);
			}
		}
		rte_eth_devices[rxq->attr.rte_pid].data->rx_mbuf_alloc_failed +=
			rxq->rx_free_thresh;
		return;
	}

	/* Initialize the mbufs in vector, process 2 mbufs in one loop */
	for (i = 0; i < rxq->rx_free_thresh; i += 2, rxep += 2) {
		mb0 = rxep[0].mbuf;
		mb1 = rxep[1].mbuf;

#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
		RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, buf_iova) !=
				offsetof(struct rte_mbuf, buf_addr) + 8);
#else
		RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, buf_physaddr) !=
				offsetof(struct rte_mbuf, buf_addr) + 8);
#endif
		/* flush desc with pa dma_addr */
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
	rxq->rxrearm_start += rxq->rx_free_thresh;
	if (rxq->rxrearm_start >= rxq->attr.nb_desc)
		rxq->rxrearm_start = 0;

	rxq->rxrearm_nb -= rxq->rx_free_thresh;
	rx_id = (uint16_t)((rxq->rxrearm_start == 0) ?
				(rxq->attr.nb_desc - 1) :
				(rxq->rxrearm_start - 1));
	/* Update the tail pointer on the NIC */
	rte_wmb();
	MCE_REG_ADDR_WRITE(rxq->rx_tailreg, 0, rx_id);
}

#if 0
static void  buf_dump(const char *msg, void *ptr, int len)
{
	unsigned char *buf = ptr;
	int i;

	printf("\n%s #%d\n", msg, len);
	for (i = 0; i < len; i++) {
		if (i != 0 && (i % 16) == 0)
			printf("\n");

		printf("%02x ", buf[i]);
	}
	printf("\n");
}
#endif

static inline uint16_t
_recv_raw_pkts_vec(struct mce_rx_queue *rxq, struct rte_mbuf **rx_pkts,
		   uint16_t nb_pkts, uint8_t *split_packet __rte_unused)
{
	volatile union mce_rx_desc *rxdp;
	struct mce_rxsw_entry *sw_ring;
	uint16_t nb_pkts_recd;
	uint64_t stat;
	int pos;

	/* mask to shuffle from desc. to mbuf */
	uint8x16_t shuf_msk = {
		0xFF, 0xFF, 0xFF, 0xFF,	/* pkt_type set as unknown */
		4, 5, 0xff, 0xff,       /* octet 4~5, low 16 bits pkt_len */
		4, 5,			/* octet 4~5, 16 bits data_len */
		8, 9,			/* vlan-tci */
		0, 1, 2, 3,		/* octet 0~3, 32bits rss */
		};
	uint16x8_t crc_adjust = {
		0, 0,         /* ignore pkt_type field */
		rxq->strip_len, /* sub crc on pkt_len */
		0,            /* ignore high-16bits of pkt_len */
		rxq->strip_len, /* sub crc on data_len */
		0, 0, 0       /* ignore non-length fields */
	};

	int16x8_t dd_shift = {-15, -14, -13, -12, 0, 0, 0, 0};
	uint16x8_t dd_mask = {
		 0x2, 0x2, 0x2, 0x2, 0, 0, 0, 0
	};
	uint8x16_t eop_check = {
		0x01, 0x00, 0x01, 0x00,
		0x01, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	/* nb_pkts has to be floor-aligned to RTE_MCE_DESCS_PER_LOOP */
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, RTE_MCE_DESCS_PER_LOOP);

	/* Just the act of getting into the function from the application is
	 * going to cost about 7 cycles
	 */
	rxdp = rxq->rx_bdr + rxq->rx_tail;
	rte_prefetch_non_temporal(rxdp);

	/* See if we need to rearm the RX queue - gives the prefetch a bit
	 * of time to act
	 */
	if (rxq->rxrearm_nb > rxq->rx_free_thresh)
		mce_rxq_rearm(rxq);

	/* Before we start moving massive data around, check to see if
	 * there is actually a packet available
	 */
	if (!(rxdp->wb.cmd & rte_cpu_to_le_32(MCE_CMD_DD)))
		return 0;
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
	for (pos = 0, nb_pkts_recd = 0; pos < nb_pkts;
			pos += RTE_MCE_DESCS_PER_LOOP,
			rxdp += RTE_MCE_DESCS_PER_LOOP) {
		uint8x16_t pkt_mb4, pkt_mb3, pkt_mb2, pkt_mb1;
		uint64x2_t descs_hi[RTE_MCE_DESCS_PER_LOOP];
		uint64x2_t descs_lo[RTE_MCE_DESCS_PER_LOOP];
		uint16x8x2_t sterr_tmp1, sterr_tmp2;
		uint64x2_t mbp1, mbp2;
		uint16x8x2_t len_cmd;
		uint16x4_t dd_final;
		uint16x8_t dd_sort;
		uint16x8_t staterr;
		uint16x8_t tmp;

		mbp1 = vld1q_u64((uint64_t *)&sw_ring[pos]);
		descs_lo[3] = vld1q_u64((uint64_t *)&(rxdp + 3)->wb.stamp.timestamp_h);
		vst1q_u64((uint64_t *)&rx_pkts[pos], mbp1);
		mbp2 = vld1q_u64((uint64_t *)&sw_ring[pos + 2]);
		descs_lo[2] = vld1q_u64((uint64_t *)&(rxdp + 2)->wb.stamp.timestamp_h);
		descs_lo[1] = vld1q_u64((uint64_t *)&(rxdp + 1)->wb.stamp.timestamp_h);
		descs_lo[0] = vld1q_u64((uint64_t *)&(rxdp)->wb.stamp.timestamp_h);
		vst1q_u64((uint64_t *)&rx_pkts[pos + 2], mbp2);
#if 0
		if (rxq->pad_len) {
			pad_len4 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[3]), pad_msk);
			pad_len3 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[2]), pad_msk);
			pad_len2 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[1]), pad_msk);
			pad_len1 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[0]), pad_msk);
			descs_hi[3] = vreinterpretq_u64_u16(
					vsubq_u16(vreinterpretq_u16_u64(descs_hi[3]),
					vreinterpretq_u16_u8(pad_len4)));
			descs_hi[2] = vreinterpretq_u64_u16(
					vsubq_u16(vreinterpretq_u16_u64(descs_hi[2]),
					vreinterpretq_u16_u8(pad_len3)));
			descs_hi[1] = vreinterpretq_u64_u16(
					vsubq_u16(vreinterpretq_u16_u64(descs_hi[1]),
					vreinterpretq_u16_u8(pad_len2)));
			descs_hi[0] = vreinterpretq_u64_u16(
					vsubq_u16(vreinterpretq_u16_u64(descs_hi[0]),
					vreinterpretq_u16_u8(pad_len1)));
		}
#endif
		sterr_tmp2 = vzipq_u16(vreinterpretq_u16_u64(descs_lo[1]),
				vreinterpretq_u16_u64(descs_lo[3]));
		sterr_tmp1 = vzipq_u16(vreinterpretq_u16_u64(descs_lo[0]),
				vreinterpretq_u16_u64(descs_lo[2]));
		len_cmd = vzipq_u16(sterr_tmp1.val[1], sterr_tmp2.val[1]);
		staterr = len_cmd.val[1];
		if (split_packet) {
			uint8x16_t eop_shuf_mask = {
				0x00, 0x02, 0x04, 0x06,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF};
			uint8x16_t eop_bits;

			/* and with mask to extract bits, flipping 1-0 */
			eop_bits = vmvnq_u8(vreinterpretq_u8_u16(staterr));
			eop_bits = vandq_u8(eop_bits, eop_check);
			/* the staterr values are not in order, as the count
			 * of dd bits doesn't care. However, for end of
			 * packet tracking, we do care, so shuffle. This also
			 * compresses the 32-bit values to 8-bit
			 */
			eop_bits = vqtbl1q_u8(eop_bits, eop_shuf_mask);
			/* store the resulting 32-bit value */
			vst1q_lane_u32((uint32_t *)split_packet,
					vreinterpretq_u32_u8(eop_bits), 0);
			split_packet += RTE_MCE_DESCS_PER_LOOP;
			/* zero-out next pointers */
			rx_pkts[pos]->next = NULL;
			rx_pkts[pos + 1]->next = NULL;
			rx_pkts[pos + 2]->next = NULL;
			rx_pkts[pos + 3]->next = NULL;
		}
		staterr = vandq_u16(staterr, dd_mask);
		staterr = vshlq_n_u16(staterr, MCE_UINT16_BIT - 2);
		dd_sort = vshlq_u16(staterr, dd_shift);
		dd_final = vget_low_u16(dd_sort);
		stat = __builtin_ctzll(~vget_lane_u64(
					vpaddl_u32(vpaddl_u16(dd_final)), 0));
		if (stat == 0)
			break;
		descs_hi[3] = vld1q_u64((uint64_t *)(rxdp + 3));
		descs_hi[2] = vld1q_u64((uint64_t *)(rxdp + 2));
		descs_hi[1] = vld1q_u64((uint64_t *)(rxdp + 1));
		descs_hi[0] = vld1q_u64((uint64_t *)(rxdp));
		pkt_mb4 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[3]), shuf_msk);
		pkt_mb3 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[2]), shuf_msk);
		pkt_mb2 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[1]), shuf_msk);
		pkt_mb1 = vqtbl1q_u8(vreinterpretq_u8_u64(descs_hi[0]), shuf_msk);

		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb4), crc_adjust);
		pkt_mb4 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb3), crc_adjust);
		pkt_mb3 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb2), crc_adjust);
		pkt_mb2 = vreinterpretq_u8_u16(tmp);
		tmp = vsubq_u16(vreinterpretq_u16_u8(pkt_mb1), crc_adjust);
		pkt_mb1 = vreinterpretq_u8_u16(tmp);

		vst1q_u8((void *)&rx_pkts[pos + 0]->rx_descriptor_fields1, pkt_mb1);
		vst1q_u8((void *)&rx_pkts[pos + 1]->rx_descriptor_fields1, pkt_mb2);
		vst1q_u8((void *)&rx_pkts[pos + 2]->rx_descriptor_fields1, pkt_mb3);
		vst1q_u8((void *)&rx_pkts[pos + 3]->rx_descriptor_fields1, pkt_mb4);
		mce_rx_desc_parse_field(rxq, descs_lo, &rx_pkts[pos]);
		mce_desc_to_ptype(descs_lo, &rx_pkts[pos]);
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 3].mbuf);
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 2].mbuf);
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP + 1].mbuf);
		rte_prefetch0(sw_ring[pos + RTE_MCE_DESCS_PER_LOOP].mbuf);
		nb_pkts_recd += stat;
		if (stat != RTE_MCE_DESCS_PER_LOOP)
			break;
	}
	/* Update our internal tail pointer */
	rxq->rx_tail = (uint16_t)(rxq->rx_tail + nb_pkts_recd);
	rxq->rx_tail = (uint16_t)(rxq->rx_tail & (rxq->attr.nb_desc - 1));
	rxq->rxrearm_nb = (uint16_t)(rxq->rxrearm_nb + nb_pkts_recd);

	return nb_pkts_recd;
}

uint16_t
mce_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
		     uint16_t nb_pkts)
{
	struct mce_rx_queue *rxq = rx_queue;
	uint16_t nb_rx = 0, n, ret;

	if (unlikely(!rx_queue))
		return 0;

	if (likely(nb_pkts <= MCE_RX_MAX_BURST_SIZE))
		return _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts, NULL);

	while (nb_pkts) {
		n = RTE_MIN(nb_pkts, MCE_RX_MAX_BURST_SIZE);

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
	uint16_t nb_bufs = _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts,
			split_flags);
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
