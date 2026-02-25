#ifndef _MCE_DMA_REGS_H_
#define _MCE_DMA_REGS_H_

#include "mce_osdep.h"
#define MCE_DMA_VERSION		  (0x40000)
/* mac address offset */
#define MCE_DMA_CTRL		  _DMA_(0x4)
#define MCE_DESC_TX_WB_CB	  RTE_BIT32(31)
#define MCE_DESC_RX_WB_CB	  RTE_BIT32(30)
#define MCE_DESC_RX_WB_CB_TH_MASK GENMASK_U32(1, 0)
#define MCE_DESC_TX_WB_CB_TH_MASK GENMASK_U32(3, 2)
#define MCE_DESC_TX_WB_CB_S	  (2)
enum mce_vf_queue_num {
	MCE_VF_1_Q,
	MCE_VF_2_Q,
	MCE_VF_4_Q,
	MCE_VF_8_Q,
};

enum mce_rx_desc_wthresh {
	MCE_RX_DESC_WTHRESH_1,
	MCE_RX_DESC_WTHRESH_2,
	MCE_RX_DESC_WTHRESH_4,
	MCE_RX_DESC_WTHRESH_8,
};

enum mce_tx_desc_wthresh {
	MCE_TX_DESC_WTHRESH_8,
	MCE_TX_DESC_WTHRESH_16,
	MCE_TX_DESC_WTHRESH_32,
	MCE_TX_DESC_WTHRESH_64,
};

enum mce_rx_desc_thresh {
	MCE_RX_WTHRSH_8 = 8,
	MCE_RX_WTHRSH_4 = 4,
	MCE_RX_WTHRSH_2 = 2,
};
enum mce_tx_desc_thresh {
	MCE_TX_WTHRSH_8 = 8,
	MCE_TX_WTHRSH_16 = 16,
	MCE_TX_WTHRSH_32 = 32,
	MCE_TX_WTHRSH_64 = 64,
};
#define MCE_TX_DESC_BULCK_WB		  RTE_BIT32(31)
#define MCE_RX_DESC_BULCK_WB		  RTE_BIT32(30)
#define MCE_DMA_VF_ACTION		  RTE_BIT32(25)
#define MCE_DMA_PAD			  RTE_BIT32(8)
#define MCE_DMA_VF_QUEUE_S		  (9)
#define MCE_DMA_PF_DEF_VPORT_S		  (16)
#define MCE_RX_DESC_WTHRESH_S		  (0)
#define MCE_TX_DESC_WTHRESH_S		  (2)

#define MCE_DMA_STATE			  _DMA_(0x8)
#define MCE_DMA_RESET_DONE		  RTE_BIT32(0)
#define MCE_HW_QUEUE_MASK		  GENMASK_U32(31, 24)
#define MCE_HW_QUEUE_SHIFT		  (24)
#define MCE_HW_CLOCK_MASK		  GENMASK_U32(11, 8)
#define MCE_HW_CLOCK_SHIFT		  (8)
#define MCE_AXI_CTRL			  _DMA_(0x10)
#define MCE_AXI_STATE			  _DMA_(0x14)

/* 1BIT <-> 16 bytes Dma Addr Size*/
#define MCE_DMA_SCATTER_MEM_MASK	  GENMASK(31, 16)
#define MCE_DMA_TX_MAP_MODE_SHIFT	  (12)
#define MCE_DMA_TX_MAP_MODE_MASK	  GENMASK(15, 12)
#define MCE_DMA_RX_MEM_PAD_EN		  RTE_BIT32(8)
/* === queue register ===== */
/* enable */
#define MCE_DMA_RXQ_START(qid)		  _RING_(0x0010 + 0x100 * (qid))
#define MCE_DMA_RXQ_READY(qid)		  _RING_(0x0014 + 0x100 * (qid))
#define MCE_DMA_TXQ_START(qid)		  _RING_(0x0018 + 0x100 * (qid))
#define MCE_DMA_TXQ_READY(qid)		  _RING_(0x001c + 0x100 * (qid))

#define MCE_DMA_Q_FLR_EN                 RTE_BIT32(1)
#define MCE_RXQ_START_EN                 RTE_BIT32(0)
#define MCE_TXQ_START_EN                 RTE_BIT32(0)

#define MCE_DMA_INT_STAT(qid)		  _RING_(0x0020 + 0x100 * (qid))
#define MCE_DMA_INT_MASK(qid)		  _RING_(0x0024 + 0x100 * (qid))
#define MCE_TX_INT_MASK			  (RTE_BIT32(1) | RTE_BIT32(17))
#define MCE_RX_INT_MASK			  (RTE_BIT32(0) | RTE_BIT32(16))
#define MCE_DMA_INT_CLER(qid)		  _RING_(0x0028 + 0x100 * (qid))

/* rx-queue */
#define MCE_DMA_RXQ_BASE_ADDR_HI(qid)	  _RING_(0x0030 + 0x100 * (qid))
#define MCE_DMA_RXQ_BASE_ADDR_LO(qid)	  _RING_(0x0034 + 0x100 * (qid))
#define MCE_DMA_RXQ_LEN(qid)		  _RING_(0x0038 + 0x100 * (qid))
#define MCE_DMA_RXQ_HEAD(qid)		  _RING_(0x003c + 0x100 * (qid))
#define MCE_DMA_RXQ_TAIL(qid)		  _RING_(0x0040 + 0x100 * (qid))
#define MCE_DMA_RXQ_DESC_FETCH_CTRL(qid)  _RING_(0x0044 + 0x100 * (qid))
#define MCE_DMA_RXQ_INT_DELAY_TIMER(qid)  _RING_(0x0048 + 0x100 * (qid))
#define MCE_DMA_RXQ_INT_DELAY_PKTCNT(qid) _RING_(0x004c + 0x100 * (qid))
#define MCE_DMA_RXQ_RX_PRI_LVL(qid)	  _RING_(0x0050 + 0x100 * (qid))
#define MCE_DMA_RXQ_DROP_TIMEOUT_TH(qid)  _RING_(0x0054 + 0x100 * (qid))
#define MCE_DMA_RXQ_SCATTER_BD_LEN(qid)	  _RING_(0x0058 + 0x100 * (qid))
#define MCE_DMA_RXQ_NODESC_DROP(qid)	  _RING_(0x005c + 0x100 * (qid))
/* tx-queue */
#define MCE_DMA_TXQ_BASE_ADDR_HI(qid)	  _RING_(0x0060 + 0x100 * (qid))
#define MCE_DMA_TXQ_BASE_ADDR_LO(qid)	  _RING_(0x0064 + 0x100 * (qid))
#define MCE_DMA_TXQ_LEN(qid)		  _RING_(0x0068 + 0x100 * (qid))
#define MCE_DMA_TXQ_HEAD(qid)		  _RING_(0x006c + 0x100 * (qid))
#define MCE_DMA_TXQ_TAIL(qid)		  _RING_(0x0070 + 0x100 * (qid))
#define MCE_DMA_TXQ_DESC_FETCH_CTRL(qid)  _RING_(0x0074 + 0x100 * (qid))
#define MCE_DMA_TXQ_INT_DELAY_TIMER(qid)  _RING_(0x0078 + 0x100 * (qid))
#define MCE_DMA_TXQ_INT_DELAY_PKTCNT(qid) _RING_(0x007c + 0x100 * (qid))

#define MCE_DMA_TXQ_PRI_LVL(qid)	  _RING_(0x0080 + 0x100 * (qid))
#define MCE_TXQ_TC_SCHED_EN		  RTE_BIT32(31)
#define MCE_TXQ_TC_SCHED_PFC		  RTE_BIT32(30)
#define MCE_TXQ_TC_NUM_S		  (16)
#define MCE_DMA_TXQ_RATE_CTRL_TH(qid)	  _RING_(0x0084 + 0x100 * (qid))
#define MCE_DMA_TXQ_RATE_CTRL_TM(qid)	  _RING_(0x0088 + 0x100 * (qid))
#define MCE_SCATTER_PER_BIT_LEN		  (64)

#define MCE_DMA_RX_NO_DESC_DROP(qid)	  _RING_(0x005c + 0x100 * (qid))
#define MCE_DMA_Q_STATS_CLR(qid)	  _RING_(0x0090 + 0x100 * (qid))
#define MCE_DMA_TX_BYTES_LO(qid)	  _RING_(0x00e0 + 0x100 * (qid))
#define MCE_DMA_TX_UNICAST_PKT_LO(qid)	  _RING_(0x00e8 + 0x100 * (qid))
#define MCE_DMA_TX_MULCAST_PKT_LO(qid)	  _RING_(0x00f0 + 0x100 * (qid))
#define MCE_DMA_TX_BROADCAST_PKT_LO(qid)  _RING_(0x00f8 + 0x100 * (qid))

#define MCE_DMA_RX_BYTES_LO(qid)	  _RING_(0x00c0 + 0x100 * (qid))
#define MCE_DMA_RX_UNICAST_PKT_LO(qid)	  _RING_(0x00c8 + 0x100 * (qid))
#define MCE_DMA_RX_MULCAST_PKT_LO(qid)	  _RING_(0x00d0 + 0x100 * (qid))
#define MCE_DMA_RX_BROADCAST_PKT_LO(qid)  _RING_(0x00d8 + 0x100 * (qid))
/* traffic gap ctrl */
#define MCE_DMA_FLOWCTRL_GAP		  _DMA_(0x0078)
#define MCE_DMA_ETSFLOW_GAP		  _DMA_(0x007c)
/* tx traffic sched control */
#define MCE_TC_BW_PCT(tc)		  _DMA_(0x1000 + 0x4 * (tc))
#define MCE_TC_TM_CTRL			  _DMA_(0x1020)
#define MCE_TC_TM_EN			  RTE_BIT32(31)
#define MCE_TC_TM_BP_MODE		  RTE_BIT32(30)
#define MCE_TC_TM_PP_MODE		  RTE_BIT32(29)
#define MCE_TC_CRC_VALID_EN		  RTE_BIT32(28)
#define MCE_TM_SAMPLE_EN		  RTE_BIT32(27)
#define MCE_TC_TM_SAMPLE		  GENMASK_U32(23, 16)
#define MCE_TC_TM_SAMPLE_SHIFT		  (16)
#define MCE_TC_VALID			  GENMASK_U32(15, 8)
#define MCE_TC_VALID_SHIFT		  (8)
#define MCE_TC_SCHED_MODE		  GENMASK_U32(7, 0)
enum { MCE_TC_SCHED_SP, MCE_TC_SCHED_ETS };
#define MCE_TC_QP_CTRL(qg)	  _DMA_(0x1200 + 0x4 * (qg))
/* stream burst compensate */
#define MCE_QG_STREAM_BURST_ALLOW RTE_BIT32(31)
#define MCE_QG_QP_EN		  RTE_BIT32(30)
#define MCE_QG_MEMBER_EN	  GENMASK_U32(11, 8)
#define MCE_QG_MEMBER_SHILT	  (8)
#define MCE_QG_WFQ_EN		  RTE_BIT32(7)
#define MCE_QG_WEIGHT		  GENMASK_U32(6, 0)
/* vf port rate limit ctrl */
#define MCE_VF_QG_CTRL_REG	  _DMA_(0x102c)
#define MCE_VF_QG_EN		  RTE_BIT32(31)
#define MCE_VF_QG_NUM		  GENMASK_U32(2, 0)
/* pps mode */
#define MCE_TC_QG_PPS_CIR_C(qg)	  _DMA_(0x1400 + 0x4 * (qg))
#define MCE_TC_QG_PPS_PIR_C(qg)	  _DMA_(0x1600 + 0x4 * (qg))
/* bps mode */
#define MCE_TC_QG_BPS_CIR_C(qg)	  _DMA_(0x1800 + 0x4 * (qg))
#define MCE_TC_QG_BPS_PIR_C(qg)	  _DMA_(0x1a00 + 0x4 * (qg))

#endif /* _MCE_DMA_REGS_H_ */
