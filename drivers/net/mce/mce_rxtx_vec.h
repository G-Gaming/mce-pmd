#ifndef _MCE_RXTX_VEC_H_
#define _MCE_RXTX_VEC_H_
#include <stdint.h>
#include <rte_mbuf.h>
#include "mce_rxtx.h"

uint16_t mce_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts);
uint16_t mce_scattered_burst_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
				 uint16_t nb_pkts);
uint16_t mce_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
				  uint16_t nb_pkts);
#ifdef RTE_ARCH_X86
uint16_t mce_recv_pkts_vec_avx2(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t
mce_recv_scattered_pkts_vec_avx2(void *rx_queue, struct rte_mbuf **rx_pkts,
			    uint16_t nb_pkts);
#endif
static inline uint16_t
mce_rx_reassemble_packets(struct mce_rx_queue *rxq,
			  struct rte_mbuf **rx_bufs, uint16_t nb_bufs,
			  uint8_t *split_flags)
{
	struct rte_mbuf *pkts[32] = {0}; /*finished pkts*/
	struct rte_mbuf *first_seg = rxq->pkt_first_seg;
	struct rte_mbuf *last_seg = rxq->pkt_last_seg;
	struct rte_mbuf *rxm = NULL;
	uint16_t crc_len = rxq->strip_len;
	unsigned int pkt_idx, buf_idx;

	for (buf_idx = 0, pkt_idx = 0; buf_idx < nb_bufs; buf_idx++) {
		rxm = rx_bufs[buf_idx];
		if (last_seg) {
			/* processing a split packet */
			rxm->data_len += crc_len;
			last_seg->next = rxm;
			first_seg->nb_segs++;
			first_seg->pkt_len += rxm->data_len;
			if (!split_flags[buf_idx]) {
				/* it's the last packet of the set */
				/* we need to strip crc for the whole packet */
				first_seg->pkt_len -= crc_len;
				if (last_seg->data_len > crc_len) {
					last_seg->data_len -= crc_len;
				} else {
					/* free up last mbuf */
					struct rte_mbuf *secondlast = first_seg;

					first_seg->nb_segs--;
					while (secondlast->next != last_seg)
						secondlast = secondlast->next;
					secondlast->data_len -= (crc_len - last_seg->data_len);
					secondlast->next = NULL;
					rte_pktmbuf_free_seg(last_seg);
				}
				pkts[pkt_idx++] = first_seg;
				rxm->next = NULL;
				last_seg = NULL;
				first_seg = NULL;
			} else {
				last_seg = rxm;
			}
		} else {
			/* not processing a split packet */
			if (!split_flags[buf_idx]) {
				/* not a split packet, save and skip */
				rxm->next = NULL;
				pkts[pkt_idx++] = rx_bufs[buf_idx];
				continue;
			}
			first_seg = rxm;
			first_seg->nb_segs = 1;
			first_seg->next = NULL;
			last_seg = rxm;
			rxm->data_len += crc_len;
			rxm->pkt_len += crc_len;
		}
	}
	rxq->pkt_first_seg = first_seg;
	rxq->pkt_last_seg = last_seg;
	memcpy(rx_bufs, pkts, pkt_idx * (sizeof(*pkts)));

	return pkt_idx;
}
#define MCE_MAX_TX_RETRY (10000)
static __rte_always_inline uint16_t mce_xmit_pkts_vec(void *_txq,
						      struct rte_mbuf **tx_pkts,
						      uint16_t nb_pkts)
{
	uint16_t nb_tx = 0;
	uint32_t retry = 0;
	uint32_t tx_burst;
	uint32_t idx = 0;
	struct mce_tx_queue *txq = (struct mce_tx_queue *)_txq;
	if (unlikely(!txq))
		return 0;
	while (nb_tx < nb_pkts) {
		tx_burst = nb_pkts - nb_tx >= 32 ? 32 : nb_pkts - nb_tx;
		idx = mce_xmit_fixed_burst_vec(_txq, &tx_pkts[nb_tx], tx_burst);
		nb_tx += idx;
		if (idx != tx_burst) {
			break;
			retry++;
			if (retry >= MCE_MAX_TX_RETRY)
			rte_prefetch0(&txq->tx_bdr[txq->tx_next_dd]);
		}
	}

	return nb_tx;
}
uint16_t
mce_recv_scattered_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			    uint16_t nb_pkts);

#endif
