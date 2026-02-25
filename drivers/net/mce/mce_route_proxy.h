#ifndef _MCE_REPR_PROXY_ROUTE_H_
#define _MCE_REPR_PROXY_ROUTE_H_

#include "mce_vf_representor.h"
enum mce_proxy_port_type {
	MCE_PROXY_VF_REPR,
	MCE_PROXY_ADMIN_REPR,
};

struct mce_proxy_route_port {
	TAILQ_ENTRY(mce_proxy_route_port) next;
	enum mce_proxy_port_type type;

	void *proxy_port;
};

TAILQ_HEAD(mce_proxy_ports, mce_proxy_route_port);
struct mce_proxy_route_adapter {
	void *back;
	struct mce_proxy_ports ports;
	struct rte_mbuf *rx_pkts[32];
	struct rte_eth_dev_tx_buffer *tx_buffer;
	uint16_t upcall_port;
	uint32_t service_id;
};

int mce_proxy_route_init(struct mce_proxy_route_adapter *adapter);
int mce_route_proxy_add_port(struct mce_proxy_route_adapter *adapter,
			     enum mce_proxy_port_type type, void *prox_port);
int mce_route_proxy_register(struct mce_proxy_route_adapter *adapter);

#endif /* _MCE_REPR_PROXY_ROUTE_H_ */
