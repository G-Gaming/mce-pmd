#ifndef _MCE_TM_H_
#define _MCE_TM_H_

enum mce_tm_node_type {
	MCE_TM_NODE_TYPE_PORT,
	MCE_TM_NODE_TYPE_QG,
	MCE_TM_NODE_TYPE_QUEUE,
	MCE_TM_NODE_TYPE_MAX,
};
struct rte_eth_dev;
int mce_tm_ops_get(struct rte_eth_dev *dev, void *arg);
void mce_tm_conf_init(struct rte_eth_dev *dev);
#endif /* _MCE_TM_H_ */
