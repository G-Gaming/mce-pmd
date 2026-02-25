#include <unistd.h>
#include <rte_eal.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#include <rte_pci.h>
#include <rte_ethdev.h>
#else
#if RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
#include <rte_ethdev_pci.h>
#else
#include <ethdev_pci.h>
#endif /* RTE_VERSION > 21.2 */
#endif /* RTE_VERSION < 17.5 */
#include <rte_string_fns.h>
#include <rte_io.h>

#include "mce_logs.h"
#include "mce_rxtx.h"
#include "mce.h"
#include "mce_mp.h"

#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
/*
 * Initialize by primary process.
 */
#define MCE_MP_PF_NAME "net_mce_mp"
#define MCE_MP_VF_NAME "net_mcevf_mp"

enum mce_mp_type {
	MCE_MP_TYPE_PF = 0,
	MCE_MP_TYPE_VF = 1,
	MCE_MP_TYPE_MAX
};

struct mce_mp_registerd {
	RTE_ATOMIC(unsigned int) mp_used_cnt;
	RTE_ATOMIC(bool) init_done;
};
#define MCE_MP_GET_TYPE(priv) ((priv)->is_vf ? MCE_MP_TYPE_VF : MCE_MP_TYPE_PF)
static struct mce_mp_state {
	struct mce_mp_registerd mp_info[MCE_MP_TYPE_MAX];
} mce_mp_state;

static void mce_mp_increment_cnt(enum mce_mp_type type)
{
	int idx = (int)type;

	rte_atomic_fetch_add_explicit(&mce_mp_state.mp_info[idx].mp_used_cnt, 1,
			rte_memory_order_relaxed);
}

static void mce_mp_decrement_count(enum mce_mp_type type)
{
	int idx = (int)type;
	rte_atomic_fetch_sub_explicit(&mce_mp_state.mp_info[idx].mp_used_cnt, 1,
		    rte_memory_order_relaxed);
}

static unsigned int mce_mp_get_count(enum mce_mp_type type)
{
	int idx = (int)type;
	return rte_atomic_load_explicit(&mce_mp_state.mp_info[idx].mp_used_cnt,
			rte_memory_order_relaxed);
}

static bool mce_mp_is_init_done(enum mce_mp_type type)
{
    int idx = (int)type;
    return rte_atomic_load_explicit(&mce_mp_state.mp_info[idx].init_done,
                                  rte_memory_order_acquire);
}


static void mce_mp_set_init_done(enum mce_mp_type type, bool done)
{
	int idx = (int)type;
	rte_atomic_store_explicit(&mce_mp_state.mp_info[idx].init_done, done,
			rte_memory_order_release);
}

static inline void
mp_init_msg(struct rte_eth_dev *dev, struct rte_mp_msg *msg,
            enum mce_mp_req_type type)
{
        struct mce_mp_param *param = (struct mce_mp_param *)msg->param;
	struct mce_process_priv *priv = dev->process_private;

        memset(msg, 0, sizeof(*msg));
        strlcpy(msg->name, priv->name, sizeof(msg->name));
        msg->len_param = sizeof(*param);
        param->type = type;
        param->port_id = dev->data->port_id;
}

static bool
mp_req_type_is_valid(enum mce_mp_req_type type)
{
        return type == MCE_MP_REQ_START_RXTX ||
                type == MCE_MP_REQ_STOP_RXTX ||
		type == MCE_MP_REQ_PRIMARY_REMOVED;
}

static void
mp_req_on_rxtx(struct rte_eth_dev *dev, enum mce_mp_req_type type)
{
	struct mce_process_priv *priv = dev->process_private;
	struct rte_mp_msg mp_req;
	struct rte_mp_msg *mp_res;
	struct rte_mp_reply mp_rep;
	struct mce_mp_param *res;
	struct timespec ts;
	int ret;
	int i;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY &&
			rte_atomic_load_explicit(&priv->mp_sync.primary.nb_secondary,
				rte_memory_order_relaxed) == 0) {
		return;
	}
	if (dev->data->dev_started && type == MCE_MP_REQ_START_RXTX)
		return;
	if (!dev->data->dev_started && type == MCE_MP_REQ_STOP_RXTX)
		return;
	if (!mp_req_type_is_valid(type) ||
			rte_eal_process_type() == RTE_PROC_SECONDARY)
		return;
	PMD_INIT_LOG(INFO,
			"primary send cmd type %d port %d",
			type, dev->data->port_id);
	mp_init_msg(dev, &mp_req, type);
	ts.tv_sec = MCE_MP_REQ_TIMEOUT_SEC;
	ts.tv_nsec = 0;
	ret = rte_mp_request_sync(&mp_req, &mp_rep, &ts);
	if (ret) {
		goto exit;
	}
	if (mp_rep.nb_sent != mp_rep.nb_received) {
		PMD_INIT_LOG(ERR,
				"port %u not all secondaries responded (req_type %d)",
				dev->data->port_id, type);
		goto exit;
	}
	for (i = 0; i < mp_rep.nb_received; i++) {
		mp_res = &mp_rep.msgs[i];
		res = (struct mce_mp_param *)mp_res->param;
		if (res->result) {
			goto exit;
		}
	}
exit:
	free(mp_rep.msgs);
}

static int
mp_primary_handle(const struct rte_mp_msg *mp_msg __rte_unused,
                  const void *peer __rte_unused)
{
	const struct mce_mp_param *param =
		(const struct mce_mp_param *)mp_msg->param;
	struct rte_mp_msg mp_res = { 0 };
	struct mce_mp_param *res = (struct mce_mp_param *)mp_res.param;
	struct mce_process_priv *priv = NULL;
	struct rte_eth_dev *dev;
	int ret;

	if (!rte_eth_dev_is_valid_port(param->port_id)) {
		PMD_DRV_LOG(ERR, "MP handle port ID %u invalid", param->port_id);
		return -ENODEV;
	}
	dev = &rte_eth_devices[param->port_id];
	priv = dev->process_private;
	mp_init_msg(dev, &mp_res, param->type);
	PMD_DRV_LOG(INFO, "primary get msg type %d from secondary port %d",
			param->type, param->port_id);
	switch (param->type) {
	case MCE_MP_REQ_SECONDARY_REMOVED:
		rte_atomic_fetch_sub_explicit(&priv->mp_sync.primary.nb_secondary,
				1, rte_memory_order_relaxed);
		ret = rte_mp_reply(&mp_res, peer);
		break;
	case MCE_MP_REQ_SECONDARY_PROBED:
		rte_atomic_fetch_add_explicit(&priv->mp_sync.primary.nb_secondary,
				1, rte_memory_order_relaxed);
		res->result = 0;
		ret = rte_mp_reply(&mp_res, peer);
		break;
	default:
		PMD_DRV_LOG(ERR, "Port %u unknown primary MP type %u",
				param->port_id, param->type);
		ret = -EINVAL;
	}

	return ret;
}

static void
mp_req_to_primary(struct rte_eth_dev *dev, enum mce_mp_req_type type)
{
	struct rte_mp_msg mp_req;
	struct rte_mp_msg *mp_res;
	struct rte_mp_reply mp_rep;
	struct mce_mp_param *res;
	struct timespec ts;
	int ret;
	int i;

	mp_init_msg(dev, &mp_req, type);
	ts.tv_sec = MCE_MP_REQ_TIMEOUT_SEC;
	ts.tv_nsec = 0;
	ret = rte_mp_request_sync(&mp_req, &mp_rep, &ts);
	if (ret) {
		PMD_INIT_LOG(ERR, "request sync to primary failed");
		goto exit;
	}
	if (mp_rep.nb_sent != mp_rep.nb_received) {
		PMD_INIT_LOG(ERR,
				"port %u not all secondaries responded (req_type %d)",
				dev->data->port_id, type);
		goto exit;
	}
	for (i = 0; i < mp_rep.nb_received; i++) {
		mp_res = &mp_rep.msgs[i];
		res = (struct mce_mp_param *)mp_res->param;
		if (res->result) {
			goto exit;
		}
	}
exit:
	free(mp_rep.msgs);
}

void mce_mp_req_secondry_probed(struct rte_eth_dev *dev)
{
	struct mce_process_priv *priv = dev->process_private;

	if (priv->mp_no_sup)
		return;
	if (rte_eal_primary_proc_alive(NULL))
		mp_req_to_primary(dev, MCE_MP_REQ_SECONDARY_PROBED);
}

void mce_mp_req_secondry_removed(struct rte_eth_dev *dev)
{
	struct mce_process_priv *priv = dev->process_private;

	if (priv->mp_no_sup)
		return;
	if (priv->mp_sync.secondary.dev_closed == 1)
		return;
	if (rte_eal_primary_proc_alive(NULL) && !priv->mp_sync.secondary.primary_is_destory)
		mp_req_to_primary(dev, MCE_MP_REQ_SECONDARY_REMOVED);
	priv->mp_sync.secondary.dev_closed = 1;
	mce_mp_uinit(dev);
}

/* primary to secondary start */
void mce_mp_req_stop_rxtx(struct rte_eth_dev *dev)
{
	struct mce_process_priv *priv = dev->process_private;

	if (priv->mp_no_sup)
		return;
	mp_req_on_rxtx(dev, MCE_MP_REQ_STOP_RXTX);
}

void mce_mp_req_start_rxtx(struct rte_eth_dev *dev)
{
	struct mce_process_priv *priv = dev->process_private;

	if (priv->mp_no_sup)
		return;
	mp_req_on_rxtx(dev, MCE_MP_REQ_START_RXTX);
}

void mce_mp_req_removed(struct rte_eth_dev *dev)
{
	struct mce_process_priv *priv = dev->process_private;

	if (priv->mp_no_sup)
		return;
	mp_req_on_rxtx(dev, MCE_MP_REQ_PRIMARY_REMOVED);
	rte_atomic_store_explicit(&priv->mp_sync.primary.nb_secondary, 0,
			rte_memory_order_release);
	mce_mp_uinit(dev);
}
/* primary to secondary end */

static void
mce_eth_dev_fp_ops_config(const struct rte_eth_dev *dev)
{
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
        struct rte_eth_fp_ops *fpo = rte_eth_fp_ops;
        uint16_t port_id = dev->data->port_id;

        fpo[port_id].rx_pkt_burst = dev->rx_pkt_burst;
        fpo[port_id].tx_pkt_burst = dev->tx_pkt_burst;
        fpo[port_id].tx_pkt_prepare = dev->tx_pkt_prepare;
        fpo[port_id].rx_descriptor_status = dev->rx_descriptor_status;
        fpo[port_id].tx_descriptor_status = dev->tx_descriptor_status;
        fpo[port_id].rxq.data = dev->data->rx_queues;
        fpo[port_id].txq.data = dev->data->tx_queues;
#else
	RTE_SET_USED(dev);
#endif
}

#if RTE_VERSION_NUM(25, 11, 0, 0) > RTE_VERSION
static uint16_t
rte_eth_tx_pkt_prepare_dummy(void *queue __rte_unused,
                struct rte_mbuf **pkts __rte_unused,
                uint16_t nb_pkts)
{
        return nb_pkts;
}
#endif /* RTE_VERSION < 25.11 */

static void
mce_set_stop_function(struct rte_eth_dev *eth_dev)
{
	eth_dev->rx_pkt_burst = rte_eth_pkt_burst_dummy;
	eth_dev->tx_pkt_burst = rte_eth_pkt_burst_dummy;
	eth_dev->tx_pkt_prepare = rte_eth_tx_pkt_prepare_dummy;

        mce_eth_dev_fp_ops_config(eth_dev);
}

static void mce_stop_rxtx_datapath(struct rte_eth_dev *dev)
{
	mce_set_stop_function(dev);

	if (rte_eal_process_type() == RTE_PROC_SECONDARY)
		return;

	rte_wmb();
	/* Disable datapath on secondary process. */
	mce_mp_req_stop_rxtx(dev);
	/* Prevent crashes when queues are still in use. */
	rte_delay_ms(100);
}

static void mce_start_rxtx_datapath(struct rte_eth_dev *dev)
{
	mce_setup_rx_function(dev);
	mce_setup_tx_function(dev);

        mce_eth_dev_fp_ops_config(dev);
}

static int
mp_secondary_handle(const struct rte_mp_msg *mp_msg, const void *peer)
{
	struct rte_mp_msg mp_res;
	struct mce_mp_param *res = (struct mce_mp_param *)mp_res.param;
	const struct mce_mp_param *param =
		(const struct mce_mp_param *)mp_msg->param;
	struct mce_process_priv *priv = NULL;
	struct rte_eth_dev *dev;
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(param->port_id)) {
		rte_errno = ENODEV;
		PMD_INIT_LOG(ERR, "port %d invalid port ID parm->type %d", param->port_id, param->type);
		return -rte_errno;
	}
	dev = &rte_eth_devices[param->port_id];
	priv = dev->process_private;
	mp_init_msg(dev, &mp_res, param->type);
	PMD_INIT_LOG(INFO, "secondary get msg from primary type %d port %d",
			param->type, param->port_id);
	switch (param->type) {
	case MCE_MP_REQ_START_RXTX:
		PMD_INIT_LOG(INFO, "port %u starting datapath",
				dev->data->port_id);
		mce_start_rxtx_datapath(dev);
		res->result = 0;
		ret = rte_mp_reply(&mp_res, peer);
		break;
	case MCE_MP_REQ_STOP_RXTX:
		PMD_INIT_LOG(INFO, "port %u stopping datapath",
				dev->data->port_id);
		mce_stop_rxtx_datapath(dev);
		res->result = 0;
		ret = rte_mp_reply(&mp_res, peer);
		break;
	case MCE_MP_REQ_PRIMARY_REMOVED:
		mce_stop_rxtx_datapath(dev);
		priv->mp_sync.secondary.primary_is_destory = 1;
		rte_eth_dev_release_port(dev);
		res->result = 0;
		ret = rte_mp_reply(&mp_res, peer);
		break;
	default:
		rte_errno = EINVAL;
		PMD_INIT_LOG(ERR, "port %u invalid mp request type",
				dev->data->port_id);
		return -rte_errno;
	}

	return ret;
}

static bool
mce_check_mp_register(struct mce_process_priv *priv)
{
	if (mce_mp_is_init_done(MCE_MP_GET_TYPE(priv)))
		return 1;
	return 0;
}
/*
 * Initialize by secondary process.
 */
static int
mce_mp_init_secondary(void *param)
{
	struct mce_process_priv *priv = param;
	int ret;

	/* A process address space only needs to be registered once */
	if (mce_check_mp_register(priv) == 1)
		return 0;
	ret = rte_mp_action_register(priv->name, mp_secondary_handle);
	if (ret && rte_errno != ENOTSUP)
		return ret;
	if (rte_errno == ENOTSUP) {
		priv->mp_no_sup = 1;
		return 0;
	}
	mce_mp_set_init_done(MCE_MP_GET_TYPE(priv), 1);

	return 0;
}

static int
mce_mp_init_primary(void *param)
{
	struct mce_process_priv *priv = param;
	int ret;

	/* A process address space only needs to be registered once */
	if (mce_check_mp_register(priv) == 1)
		return 0;
	/* primary is allowed to not support IPC */
	ret = rte_mp_action_register(priv->name, mp_primary_handle);
	if (ret && rte_errno != ENOTSUP)
		return ret;
	if (rte_errno == ENOTSUP) {
		priv->mp_no_sup = 1;
		return 0;
	}
	mce_mp_set_init_done(MCE_MP_GET_TYPE(priv), 1);

	return 0;
}

int mce_mp_uinit(struct rte_eth_dev *dev)
{
	struct mce_process_priv *priv = dev->process_private;

	if (priv == NULL)
		return -EINVAL;
	mce_mp_decrement_count(MCE_MP_GET_TYPE(priv));
	if (mce_mp_get_count(MCE_MP_GET_TYPE(priv)) != 0)
		return 0;
	PMD_INIT_LOG(INFO, "action_mp_unregiser");
	rte_mp_action_unregister(priv->name);
	mce_mp_set_init_done(MCE_MP_GET_TYPE(priv), 0);

	return 0;
}

int mce_mp_init(struct rte_eth_dev *dev)
{
	struct mce_adapter *adapter = MCE_DEV_TO_ADAPTER(dev);
	struct mce_process_priv *priv;
	int ret = 0;

#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
	priv = calloc(1, sizeof(struct mce_process_priv));
	if (!priv) {
		PMD_DRV_LOG(ERR, "Could not calloc "
				"for Process_priv\n");
		goto fail_calloc;
	}
	memset(priv, 0, sizeof(*priv));
#endif
	if (mce_is_vf_device(dev)) {
		priv->is_vf = 1;
		strlcpy(priv->name, MCE_MP_VF_NAME, sizeof(priv->name));
	} else {
		strlcpy(priv->name, MCE_MP_PF_NAME, sizeof(priv->name));
	}
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		ret = mce_mp_init_secondary(priv);
		if (ret) {
			PMD_INIT_LOG(ERR, "Failed to init for secondary process, ret = %d",
					ret);
			return ret;
		}
		rte_atomic_fetch_add_explicit(&adapter->nb_secondary,
				1, rte_memory_order_relaxed);
	} else {
		priv->is_primary = 1;
		ret = mce_mp_init_primary(priv);
		if (ret) {
			PMD_INIT_LOG(ERR, "Failed to init for primary process, ret = %d",
					ret);
			return ret;
		}
	}
	mce_mp_increment_cnt(MCE_MP_GET_TYPE(priv));
	dev->process_private = priv;

	return 0;
fail_calloc:
	return -ENOMEM;
}
#else
int mce_mp_init(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}
int mce_mp_uinit(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}
void mce_mp_req_stop_rxtx(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
}
void mce_mp_req_start_rxtx(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
}
void mce_mp_req_secondry_removed(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
}
void mce_mp_req_secondry_probed(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
}
void mce_mp_req_removed(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
}
#endif /* RTE_VERSION >18.05 */
