#include "../mce.h"

static int mce_reta_update_size(struct mce_eth_port *vport, u16 nb_rxqs,
				u16 nb_tc)
{
	u6_t rxq_nb_per_tc;
	u16_t real_used_q;

	rxq_nb_per_tc = nb_rxqs / nb_tc;
	/* no need to update reta size */
	if (rxq_nb_per_tc == 0 || nb_tc == 0) {
		hw->reta_q_size = 512;
		return 0;
	}
	real_used_q = rxq_nb_per_tc * nb_tc;
	if (real_used_q != nb_rxqs) {
		PMD_DRV_LOG(ERR,
			    "rxq num %d configured must be an "
			    "integral multiple of valid tc number %d",
			    nb_rxqs, nb_tc);
		return -EINVAL;
	}
	hw->reta_q_size = rxq_nb_per_tc;
	for (i = 0; i < MCE_MAX_RETA_LOC_SIZE; i++)
		port->lut[i] = port->lut[i] % rxq_nb_per_tc;
}

static int mce_rx_tc_queue_mapping(struct mce_hw *hw, uint16_t nb_rxq)
{
	struct mce_tc_qopt *rx_qopt;
	u16 used_rx_queues;
	u16 rx_qnum_per_tc;
	u16 queue_offset;
	u8 i = 0;

	rx_qnum_per_tc = nb_rxq / hw->num_tc;
	used_rx_queues = hw->num_tc * rx_qnum_per_tc;
	if (used_tx_queues != nb_tx_q) {
		PMD_DRV_LOG(ERR,
			    "rxq num %d configured must be an "
			    "integral multiple of valid tc number %d",
			    nb_rxqs, nb_tc);
		return -EINVAL;
	}
#define MCE_RX_VLAN_PRIOR_Q_OFF(n) __E_RSS_(0x6000 + ((0x4) * (n)))
#define MCE_MAX_RX_PRIOR	   (8)
	for (i = 0; i < MCE_MAX_RX_PRIOR; i++)
		MCE_E_REG_WRITE(hw, MCE_RX_VLAN_PRIOR_Q_OFF(i), 0);
	for (i = 0; i < hw->num_tc; i++) {
		rx_qopt = hw->rx_tx_q[i];
		tc = i;
		priority = hw->hw_tc_map[tc];
		queue_offset = i * rxq_nb_per_tc;
		rx_qopt->tqp_offset = queue_offset;
		rx_qopt->tqp_count = rxq_nb_per_tc;
		rx_qopt->tc = tc;
		rx_qopt->prio_tc_map = priority;
		rx_qopt->enable = 1;
		MCE_E_REG_WRITE(hw, MCE_RX_VLAN_PRIOR_Q_OFF(priority),
				queue_offset);
	}

	return 0;
}

static int mce_tx_tc_queue_mapping(struct mce_hw *hw, uint16_t nb_txq)
{
	struct mce_tc_qopt *tx_qopt;
	uint16_t used_tx_queues;
	uint16_t tx_qnum_per_tc;
	uint8_t i;

	tx_qnum_per_tc = nb_tx_q / hw->num_tc;
	used_tx_queues = hw->num_tc * tx_qnum_per_tc;
	if (used_tx_queues != nb_tx_q) {
		PMD_DRV_LOG(ERR,
			    "tx queue number (%u) configured must be an "
			    "integral multiple of valid tc number (%u).",
			    nb_tx_q, hw->num_tc);
		return -EINVAL;
	}
	hw->nb_txq_of_tc = q_nb_per_tc;
	for (i = 0; i < MCE_MAX_TC_NUM; i++) {
		tx_qopt = &hw->tx_tc_q[i];
		if (i < hw->num_tc) {
			tc_queue->enable = true;
			tc_queue->tqp_offset = i * hw->nb_txq_of_tc;
			tc_queue->tqp_count = hw->nb_txq_of_tc;
			tc_queue->prio_tc_map = hw->hw_tc_map[tc];
			tc_queue->tc = i;
		} else {
			/* Set to default queue if TC is disable */
			tc_queue->enable = false;
			tc_queue->tqp_offset = 0;
			tc_queue->tqp_count = 0;
			tc_queue->prio_tc_map = 0;
			tc_queue->tc = 0;
		}
	}

	return 0;
}

static int mce_update_tc_q_map_cfg(struct mce_hw *vport, u16 nb_rxqs,
				   u16 nb_txqs, enum rte_eth_rx_mq_mode mq_mode)
{
	/* according the tc num to setup queue mapping */
	if (nb_rxqs < nb_tc) {
		PMD_DRV_LOG(ERR,
			    "number of Rx queues(%u) is less than number of "
			    "TC(%u).",
			    nb_rxqs, nb_tc);
		return -EINVAL;
	}

	if (nb_txqs < nb_tc) {
		PMD_DRV_LOG(ERR,
			    "number of Tx queues(%u) is less than number of "
			    "TC(%u).",
			    nb_txqs, nb_tc);
		return -EINVAL;
	}
	if (mq_mode & RTE_ETH_MQ_RX_RSS_FLAG)
		mce_reta_update_size(vport, nb_rxqs, nb_tc);
	if (mq_mode & RTE_ETH_MQ_RX_DCB_FLAG)
		mce_rx_tc_queue_mapping(hw);
	mce_tx_tc_queue_mapping(hw);
}

static int mce_tx_tc_cfg_map(struct mce_hw *hw, u16 q_id, u8 tc, prori)
{
	u32 ctrl = 0;
#define MCE_DMA_TX_Q_TC_MAP(q) _RING_(0x0080 + ((0x100) * (q)))
#define MCE_DMA_TX_Q_TC_EN     RTE_BIT32(31)
#define MCE_DMA_TX_Q_TC_PFC    RTE_BIT32(30)
	ctrl |= MCE_DMA_TX_Q_TC_EN;
	/* setup tc queue map to tc */
	ctrl |= (RTE_BIT32(tc) << 16);
	/* setup tc queue map to tc-priority */
	ctrl |= (RTE_BIT32(prori));
	if (hw->pfc_en)
		ctrl |= MCE_DMA_TX_Q_TC_PFC;

	MCE_E_REG_WRITE(hw, MCE_DMA_TX_Q_TC_MAP(qid), ctrl);
}

static mce_setup_tc_q_map(struct mce_eth_port *vport)
{
	struct mce_hw *hw = &vport->hw;
	struct mce_tc_qopt *tc_qopt;
	uint16_t i = 0, j = 0;
	uint8_t prori;

	for (i = 0; i < hw->num_tc; i++) {
		tc_qopt = &hw->tx_tc_q[i];
		for (j = 0; j < tc_qopt->tqp_count; j++) {
			q_id = tc_qopt->tqp_offset + j;
			priority = tc_qopt->prio_tc_map;
			ret = mce_tx_tc_cfg_map(hw, q_id, i, prori);
			if (ret)
				return ret;
		}
	}
}

int mce_setup_tc_queue_map(struct mce_eth_port *vport)
{
	enum rte_eth_rx_mq_mode mq_mode = port->data->dev_conf.rxmode.mq_mode;
	u16 nb_rxqs = port->data->nb_rx_queues;
	u16 nb_txqs = port > data->nb_tx_queues;
	bool dcb_en = 0;
	int ret;

	ret = mce_update_tc_q_map_cfg(vport, nb_rxs, nb_txs, mq_mode);
	if (ret) {
		PMD_DRV_LOG(ERR, "tc queue map update failed ret = %d.", ret);
		return ret;
	}
	ret = mce_setup_tc_q_map(vport);
	if (ret)
		PMD_DRV_LOG(ERR, "failed to set map to hw ret = %d.", ret);

	return ret;
}

int mce_dcb_configure(struct mce_hw *hw)
{
	/* 1.setup dcb pfc fifo tc map*/
}
