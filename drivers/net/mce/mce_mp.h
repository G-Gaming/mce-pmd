#ifndef _MCE_MP_H_
#define _MCE_MP_H_

struct mce_sync_primary {
	RTE_ATOMIC(unsigned int) nb_secondary;
};

struct mce_sync_secondary {
	uint16_t dev_state;
	bool dev_closed;
	bool primary_is_destory;
};

union mce_process_sync {
	struct mce_sync_primary primary;
	struct mce_sync_secondary secondary;
};

struct mce_process_priv {
	bool is_primary;
	bool mp_no_sup;
	bool init_done; /* Process action register completed flag. */
	bool is_vf;
	union mce_process_sync mp_sync;
	char name[128];
};

enum mce_mp_req_type {
	MCE_MP_REQ_PRIMARY_REMOVED = 1,
	MCE_MP_REQ_SECONDARY_PROBED,
	MCE_MP_REQ_SECONDARY_REMOVED,
	MCE_MP_REQ_START_RXTX,
	MCE_MP_REQ_STOP_RXTX,
	MCE_MP_REQ_START_TX,
	MCE_MP_REQ_STOP_TX,
	MCE_MP_REQ_MAX
};

struct mce_mp_param {
	enum mce_mp_req_type type;
	int port_id;
	int result;
};
/* Request timeout for IPC. */
#define MCE_MP_REQ_TIMEOUT_SEC 2
int mce_mp_init(struct rte_eth_dev *dev);
int mce_mp_uinit(struct rte_eth_dev *dev);
void mce_mp_req_stop_rxtx(struct rte_eth_dev *dev);
void mce_mp_req_start_rxtx(struct rte_eth_dev *dev);
void mce_mp_req_secondry_probed(struct rte_eth_dev *dev);
void mce_mp_req_secondry_removed(struct rte_eth_dev *dev);
void mce_mp_req_removed(struct rte_eth_dev *dev);

#endif /* _MCE_MP_H_ */
