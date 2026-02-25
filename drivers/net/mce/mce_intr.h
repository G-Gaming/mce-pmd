#ifndef _MCE_INTR_H_
#define _MCE_INTR_H_

int mce_rxq_intr_enable(struct rte_eth_dev *eth_dev);
int mce_dev_rx_queue_intr_enable(struct rte_eth_dev *dev, uint16_t qidx);
int mce_dev_rx_queue_intr_disable(struct rte_eth_dev *dev, uint16_t qidx);
int mce_rxq_intr_enable(struct rte_eth_dev *eth_dev);
int mce_dev_rx_queue_intr_enable(struct rte_eth_dev *dev, uint16_t qidx);
int mce_dev_rx_queue_intr_disable(struct rte_eth_dev *dev, uint16_t qidx);

#endif /* _MCE_INTR_H_ */
