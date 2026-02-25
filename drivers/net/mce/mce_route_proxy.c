#include <rte_ethdev.h>
#include <rte_tailq.h>

#include "mce.h"
#include "mce_rxtx.h"
#include "mce_route_proxy.h"

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
#include "mce_service.h"
#endif

#define MCE_MAX_ROUTE_PKT_BURST (1)

#include <assert.h>
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
static int mce_proxy_routine(void *arg)
{
	struct mce_proxy_route_adapter *adapter = arg;
	struct rte_eth_dev_tx_buffer *buffer = NULL;
	struct mce_tx_queue *proxy_txq = NULL;
	struct mce_proxy_route_port *port;
	struct mce_vf_representor *repr = NULL;
	struct mce_pf *pf = adapter->back;
	struct rte_mbuf *rx_pkts[32];
	struct rte_ring *ring = NULL;
	struct rte_mbuf *m = NULL;
	void **objs = (void *)&rx_pkts[0];
	uint16_t n_rx;
	void *temp;
	int i = 0;

	buffer = adapter->tx_buffer;
	RTE_TAILQ_FOREACH_SAFE(port, &adapter->ports, next, temp) {
		if (pf->dev->data->nb_tx_queues == 0 ||
		    pf->dev->data->tx_queues[0] == NULL)
			continue;
		proxy_txq = pf->dev->data->tx_queues[0];
		if (port->type == MCE_PROXY_VF_REPR) {
			repr = (struct mce_vf_representor *)port->proxy_port;
			if (repr->state == 0)
				continue;
			struct mce_repr_txq *txq = repr->txqs[0];

			ring = txq->ring;
		}
		if (repr == NULL)
			continue;
		n_rx = rte_ring_sc_dequeue_burst(ring, objs,
						 MCE_MAX_ROUTE_PKT_BURST, NULL);
		if (n_rx == 0)
			continue;
		pthread_mutex_lock(&proxy_txq->lock);
		for (i = 0; i < n_rx; i++) {
			m = rx_pkts[i];
			*RTE_MBUF_DYNFIELD(
				m, (proxy_txq->mce_admin_dynfield_offset),
				uint16_t *) = repr->vf_id;
			m->ol_flags |= proxy_txq->mce_admin_dynflag;
			rte_eth_tx_buffer(adapter->upcall_port, 0, buffer, m);
		}
		pthread_mutex_unlock(&proxy_txq->lock);
	}

	return 0;
}

int mce_proxy_route_init(struct mce_proxy_route_adapter *adapter)
{
	adapter->tx_buffer = rte_zmalloc_socket(
		"mce_proxy_route_tx_buffer",
		RTE_ETH_TX_BUFFER_SIZE(MCE_MAX_ROUTE_PKT_BURST), 0,
		rte_eth_dev_socket_id(adapter->upcall_port));
	rte_eth_tx_buffer_init(adapter->tx_buffer, MCE_MAX_ROUTE_PKT_BURST);
	TAILQ_INIT(&adapter->ports);

	return 0;
}

/**
 * @brief Add a port to the proxy route adapter.
 *
 * Registers a port (such as a VF representor) to be monitored for packet
 * routing and proxying by the adapter.
 *
 * @param adapter
 *   Pointer to the proxy route adapter.
 * @param type
 *   Type of the proxy port (e.g., VF representor).
 * @param prox_port
 *   Pointer to the port structure.
 * @return
 *   0 on success, negative errno on failure.
 */
int mce_route_proxy_add_port(struct mce_proxy_route_adapter *adapter,
			     enum mce_proxy_port_type type, void *prox_port)
{
	struct mce_proxy_route_port *port = NULL;

	port = rte_zmalloc(NULL, sizeof(*port), 0);
	port->type = type;
	port->proxy_port = prox_port;

	TAILQ_INSERT_TAIL(&adapter->ports, port, next);

	return 0;
}

/**
 * @brief Register the proxy route service with the rte_service framework.
 *
 * Registers the proxy routing callback as a service component for managed
 * execution on a designated service core.
 *
 * @param adapter
 *   Pointer to the proxy route adapter.
 * @return
 *   0 on success, negative errno on failure.
 */
int mce_route_proxy_register(struct mce_proxy_route_adapter *adapter)
{
	int ret = 0;

	ret = mce_register_services("proxy_route", mce_proxy_routine,
				    (void *)adapter);
	if (ret < 0) {
		printf("proxy_route register service failed\n");
		return ret;
	}
	adapter->service_id = ret;
	mce_service_map_ctrl(adapter->service_id);

	return 0;
}
#endif
