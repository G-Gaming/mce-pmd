#include "mce_rxtx_vec.h"
#include <stdint.h>
#include <rte_mbuf.h>

uint16_t mce_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(nb_pkts);
	return 0;
}

uint16_t mce_recv_scattered_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
				     uint16_t nb_pkts)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(nb_pkts);
	return 0;
}

uint16_t mce_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
				 uint16_t nb_pkts)
{
	RTE_SET_USED(tx_queue);
	RTE_SET_USED(tx_pkts);
	RTE_SET_USED(nb_pkts);
	return 0;
}
