#ifndef _MCE_ETH_REGS_H_
#define _MCE_ETH_REGS_H_

#include "mce_osdep.h"

#define ENABLE			(1)
#define DISABLE			(0)
#define FLUSH			(1)
#define MCE_ETH_RX_ES_DROP_CTRL _ETH_(0x0470)
#define MCE_RX_TRANS_DROP_EN	RTE_BIT32(0)
enum mce_rx_counter_cmd {
	MCE_RX_TRANS_IN = 0,
	MCE_RX_TRANS_OUT,
	MCE_RX_TRANS_DROP,
	MCE_RX_CRC_ERR = 4,
	MCE_RX_NOSYM_ERR,
	MCE_RX_USIZE_ERR,
	MCE_RX_OSIZE_ERR,
	MCE_RX_LEN_ERR,
	MCE_RX_SLEN_ERR,
	MCE_RX_GLEN_ERR,
	MCE_RX_FRAG_NUM,
	MCE_RX_LEN_EXP_NUM,
	MCE_RX_PKT_SOP_NUM,
	MCE_RX_PKT_EOP_NUM,
	MCE_RX_SOP_NUM,
	MCE_RX_EOP_NUM,
	MCE_RX_WPI_STATE,

	MCE_RX_PFC_PRI0_DROP = 24,
	MCE_RX_PFC_PRI1_DROP,
	MCE_RX_PFC_PRI2_DROP,
	MCE_RX_PFC_PRI3_DROP,
	MCE_RX_PFC_PRI4_DROP,
	MCE_RX_PFC_PRI5_DROP,
	MCE_RX_PFC_PRI6_DROP,
	MCE_RX_PFC_PRI7_DROP,
};
#define MCE_ETH_TX_ES_DROP_CTRL	    _ETH_(0x0474)
/* L2 filter base */
#define MCE_ETH_GLOBAL_L2_F_CTRL    _ETH_(0x8010)
#define MCE_G_L2_FILTER_EN	    RTE_BIT32(31)
#define MCE_G_DMAC_FILTER_EN	    RTE_BIT32(30)
#define MCE_G_ANTI_SPOO_VLAN_F_EN   RTE_BIT32(18)
#define MCE_G_ANTI_SPOOF_MAC_F_EN   (RTE_BIT32(17) | RTE_BIT32(19))
#define MCE_G_VLAN_FILTER_EN	    RTE_BIT32(26)
#define MCE_G_MNG_FILTER_EN	    	RTE_BIT32(25)
#define MCE_G_UNICAST_HASH_F_EN	    RTE_BIT32(24)
#define MCE_G_MULTICAST_HASH_F_EN   RTE_BIT32(23)
#define MCE_G_UNICAST_PROMISC	    RTE_BIT32(22)
#define MCE_G_MULTICAST_PROMISC	    RTE_BIT32(21)
#define MCE_G_BROADCAST_PROMISC	    RTE_BIT32(20)

#define MCE_G_DIR_RDMA_EN	    RTE_BIT32(8)
#define MCE_G_DOWN_TO_UP_F_EN	    RTE_BIT32(6)
#define MCE_G_VLAN_F_SEL_S	    (4)
#define MCE_G_VLAN_F_SEL_MASK	    GENMASK_U32(5, 4)
#define MCE_G_MULTICAST_HASH_SEL    RTE_BIT32(2)
#define MCE_G_UNICAST_HASH_SEL	    RTE_BIT32(3)

#define MCE_ETH_GLOBAL_L2_EX_F_CTRL _ETH_(0x8014)
#define MCE_G_MCAST_CVERT_TO_BCAST  RTE_BIT32(31)

enum mce_vlan_tag_filter {
	MCE_FILTER_CVLAN = 1,
	MCE_FILTER_SVLAN,
	MCE_FILTER_VLAN_2,
};

#define MCE_ETH_RQA_CTRL	    _ETH_(0x8020)
#define MCE_RQA_REDIR_EN	    RTE_BIT32(31)
#define MCE_RQA_FDIR_EN		    RTE_BIT32(30)
#define MCE_RQA_ETHTYPE_EN	    RTE_BIT32(29)
#define MCE_RQA_TCP_SYNC_EN	    RTE_BIT32(28)
#define MCE_RQA_5TUPLE_EN	    RTE_BIT32(27)
#define MCE_RQA_RSS_EN		    RTE_BIT32(26)
#define MCE_RQA_MULTICAST_F_EN	    RTE_BIT32(25)
#define MCE_RQA_VF_VIDF_EN	    RTE_BIT32(23)
#define MCE_RQA_RX_ERR_MASK	    GENMASK_U32(15, 10)

#define MCE_RQA_VF_RING_MASK	    GENMASK_U32(18, 16)
#define MCE_RQA_VF_RING_SHIFT	    (16)
#define MCE_RQA_RX_I_L4_ERR	    RTE_BIT32(15)
#define MCE_RQA_RX_I_L3_ERR	    RTE_BIT32(14)
#define MCE_RQA_RX_O_L4_ERR	    RTE_BIT32(13)
#define MCE_RQA_RX_O_L3_ERR	    RTE_BIT32(12)
#define MCE_RQA_RX_LEN_ERR	    RTE_BIT32(11)
#define MCE_RQA_MAC_HDR_ERR	    RTE_BIT32(10)

#define MCE_ETH_RSS_MARK_CTRL	    _ETH_(0x8028)
/* switch vport rule register base */
#define MCE_SW_ENGINE_CTRL	    _ETH_(0x8014)
#define MCE_SW_TUPLE10_EN	    RTE_BIT32(21)
#define MCE_SW_TUPLE10_MASK_EN	    RTE_BIT32(20)
#define MCE_SW_UP_TUPLE4_MASK_EN    RTE_BIT32(19)
#define MCE_SW_DN_TUPLE4_MASK_EN    RTE_BIT32(18)

#define MCE_SW_DN_TUPLE4_TUN_MASK   RTE_BIT32(17)
#define MCE_SW_DN_TUPLE4_VLAN_MASK  RTE_BIT32(16)
#define MCE_SW_DN_TUPLE4_DMAC_MASK  RTE_BIT32(15)
#define MCE_SW_DN_TUPLE4_LPORT_MASK RTE_BIT32(14)

#define MCE_SW_UP_TUPLE4_TUN_MASK   RTE_BIT32(13)
#define MCE_SW_UP_TUPLE4_VLAN_MASK  RTE_BIT32(12)
#define MCE_SW_UP_TUPLE4_DMAC_MASK  RTE_BIT32(11)
#define MCE_SW_UP_TUPLE4_LPORT_MASK RTE_BIT32(10)

#define MCE_SW_TUPLE10_L2TYPE_MASK  RTE_BIT32(9)
#define MCE_SW_TUPLE10_L3TYPE_MASK  RTE_BIT32(8)
#define MCE_SW_TUPLE10_L4SP_MASK    RTE_BIT32(7)
#define MCE_SW_TUPLE10_L4DP_MASK    RTE_BIT32(6)
#define MCE_SW_TUPLE10_DIP_MASK	    RTE_BIT32(5)
#define MCE_SW_TUPLE10_SIP_MASK	    RTE_BIT32(4)
#define MCE_SW_TUPLE10_TUN_MASK	    RTE_BIT32(3)
#define MCE_SW_TUPLE10_VLAN_MASK    RTE_BIT32(2)
#define MCE_SW_TUPLE10_DMAC_MASK    RTE_BIT32(1)
#define MCE_SW_TUPLE10_LPORT_MASK   RTE_BIT32(0)

#define MCE_ETH_FWD_CTRL            _ETH_(0x801c)
#define MCE_FWD_TRUST_EN            RTE_BIT32(9)
#define MCE_FWD_DEF_VPORT_MASK      GENMASK_U32(31, 25)
#define MCE_SW_VM_CTRL(n)	    _E_L2_F_(0x0000 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_S_VPID_EN	    RTE_BIT32(15)
#define MCE_SW_VM_MAC_EN	    RTE_BIT32(14)
#define MCE_SW_VM_VID_EN	    RTE_BIT32(13)
#define MCE_SW_VM_TUN_EN	    RTE_BIT32(12)
#define MCE_SW_VM_TUN_TYPE_MASK	    GENMASK_U32(10, 8)
enum mce_sw_vm_tun_type {
	MCE_SW_VM_TUN_VXLAN = 1,
	MCE_SW_VM_TUN_GRE,
	MCE_SW_VM_TUN_GENEVE,
	MCE_SW_VM_TUN_GTP_U,
	MCE_SW_VM_TUN_GTP_C,
};
#define MCE_SW_VM_TUN_TYPE_S	   (8)
#define MCE_SW_VM_S_VPID_MASK	   GENMASK_U32(7, 0)

#define MCE_SW_VM_DMAC_RAL(n)	   _E_L2_F_(0x0800 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_DMAC_RAH(n)	   _E_L2_F_(0x1000 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_VLAN(n)	   _E_L2_F_(0x1800 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_TUN_KEY(n)	   _E_L2_F_(0x2000 + BIT_TO_BYTES(32) * (n))

#define MCE_ANTISPOOF_MAC_RAL(n)   _E_L2_F_(0x4c00 + BIT_TO_BYTES(32) * (n))
#define MCE_ANTISPOOF_MAC_HI_M	   GENMASK_U32(15, 0)
#define MCE_ANTISPOOF_MAC_RAHC(n)  _E_L2_F_(0x4e00 + BIT_TO_BYTES(32) * (n))
#define MCE_ANTISPOOF_VLAN_EN	   RTE_BIT32(31)
#define MCE_ANTISPOOF_SMAC_EN	   RTE_BIT32(30)
#define MCE_ANTISPOOF_DMAC_EN	   RTE_BIT32(29)
#define MCE_ANTISPOOF_MAC_EN	   MCE_ANTISPOOF_SMAC_EN
#define MCE_ANTISPOOF_VLAN_S	   (16)
#define MCE_ANTISPOFF_VLAN_M	   GENMASK_U32(27, 16)
#define MCE_ANTISPOOF_MAC_LO_M	   GENMASK_U32(31, 0)
#define MCE_ANTISPOOF_SMAC_DROP_LO _E_L2_F_(0x4934)
#define MCE_ANTISPOOF_SMAC_DROP_HI _E_L2_F_(0x4914)
#define MCE_ANTISPOOF_DMAC_DROP_LO _E_L2_F_(0x4938)
#define MCE_ANTISPOOF_DMAC_DROP_HI _E_L2_F_(0x4918)
#define MCE_ANTISPOFF_VLAN_DROP_LO _E_L2_F_(0x493c)
#define MCE_ANTISPOOF_VLAN_DROP_HI _E_L2_F_(0x491c)

#define MCE_L2_DMAC_F_DROP_CNT     _E_L2_F_(0x4920)
#define MCE_L2_VLAN_F_DROP_CNT     _E_L2_F_(0x4924)

#define MCE_SW_VM_DIP(n)	   _E_SW_F_(0x3000 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_SIP(n)	   _E_SW_F_(0x3200 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_L4PORT(n)	   _E_SW_F_(0x3400 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_NTUPLE_CTRL(n)   _E_SW_F_(0x3600 + BIT_TO_BYTES(32) * (n))
#define MCE_VM_L2TYPE_VALID	   RTE_BIT32(26)
#define MCE_VM_L3TYPE_VALID	   RTE_BIT32(27)
#define MCE_VM_L4SP_VALID	   RTE_BIT32(28)
#define MCE_VM_L4DP_VALID	   RTE_BIT32(29)
#define MCE_VM_SIP_VALID	   RTE_BIT32(30)
#define MCE_VM_DIP_VALID	   RTE_BIT32(31)
#define MCE_VM_L3TYPE_MASK	   GENMASK_U32(7, 0)
#define MCE_VM_L2TYPE_MASK	   GENMASK_U32(23, 8)
#define MCE_VM_L2TYPE_SHIFT	   (8)

#define MCE_SW_VM_ACT_CTRL(n)	   _E_L2_F_(0x2800 + BIT_TO_BYTES(32) * (n))
#define MCE_SW_VM_ACT_DB_MASK	   GENMASK_U32(17, 8)
#define MCE_SW_VM_ACT_DROP_DB	   (1023)
#define MCE_SW_VM_ACT_DB_S	   (8)
#define MCE_SW_ACT_TO_RDMA	   RTE_BIT32(7)
#define MCE_SW_ACT_TO_BMC	   RTE_BIT32(6)
#define MCE_SW_ACT_TO_SWITCH	   RTE_BIT32(5)
#define MCE_SW_ACT_TO_HOST	   RTE_BIT32(4)
enum mce_switch_port { MCE_SW_TO_UPLINK_P_0 = 0, MCE_SW_TO_UPLINK_P_1 };
#define MCE_SW_VM_ACT_DB_BTMAP(r, n) \
	_E_ATTR_(0x1000 + ((r) * 0x1000) + ((n) * BIT_TO_BYTES(32)))

/* switch vport rule register end */

#define MCE_ETH_DMAC_RAL(entry)	 _E_L2_F_(0x5000 + BIT_TO_BYTES(32) * (entry))
#define MCE_ETH_DMAC_RAH(entry)	 _E_L2_F_(0x5800 + BIT_TO_BYTES(32) * (entry))
#define MCE_MAC_FILTER_EN	 RTE_BIT32(31)

#define MCE_ETH_W_ETYPE_F(entry) _E_L2_F_(0x3800 + ((entry) * BIT_TO_BYTES(32)))
#define MCE_ETH_W_ETYPEID_MASK	 GENMASK_U32(15, 0)
#define MCE_ETH_W_ETYPE_F_EN	 RTE_BIT32(31)

#define MCE_ETH_VLAN_HASH(entry) _E_L2_F_(0x4600 + BIT_TO_BYTES(32) * (entry))
#define MCE_ETH_UNICAST_HASH(entry) \
	_E_L2_F_(0x4200 + BIT_TO_BYTES(32) * (entry))
#define MCE_ETH_MULTICAST_HASH(entry) \
	_E_L2_F_(0x4400 + BIT_TO_BYTES(32) * (entry))
#define MCE_MAC_HASH_MASK GENMASK_U32(11, 0)
#define MCE_UTA_BIT_SHIFT (5)
#define MCE_UTA_BIT_MASK  ((1 << MCE_UTA_BIT_SHIFT) - 1)

/* ethertype flow direct */
#define MCE_ETH_ETQF(vport, entry) \
	_E_RQA_ETYPE_F_(((vport) * BIT_TO_BYTES(512)) + ((entry) << 2))
#define MCE_ETQF_EN	       RTE_BIT32(31)
#define MCE_ETQF_PRIV_S	       (16)
#define MCE_ETQF_MASK	       GENMASK_U32(19, 16)
#define MCE_ETQF_L2_PROTO_MASK GENMASK_U32(15, 0)
#define MCE_ETH_ETQS(vport, entry) \
	_E_RQA_ETYPE_F_(0x2000 + ((vport) * BIT_TO_BYTES(512)) + ((entry) << 2))
/* tcp sync filter */
#define MCE_SYNC_PRIORITY(entry) \
	_E_RQA_SYNC_F_(0x0 + ((entry)) * BIT_TO_BYTES(64))
#define MCE_SYNC_RULE_EN	 RTE_BIT32(31)
#define MCE_SYNC_HI_PRIV_EN	 RTE_BIT32(0)
#define MCE_SYCN_FLOW_PRIO_SHIFT (20)
#define MCE_SYNC_QF(entry)	 _E_RQA_SYNC_F_(0x4 + ((entry)) * BIT_TO_BYTES(64))
/* Ntuple flow direct */
#define MCE_NTUPLE_SIP(entry) \
	_E_RQA_NTUPLE_F_(0x0 + ((entry) * BIT_TO_BYTES(256)))
#define MCE_NTUPLE_DIP(entry) \
	_E_RQA_NTUPLE_F_(0x4 + ((entry) * BIT_TO_BYTES(256)))
#define MCE_NTUPLE_L4PORT(entry) \
	_E_RQA_NTUPLE_F_(0x8 + ((entry) * BIT_TO_BYTES(256)))
#define MCE_NTUPLE_L4_DP_S (16)
#define MCE_NTUPLE_F_CTRL(entry) \
	_E_RQA_NTUPLE_F_(0xc + ((entry) * BIT_TO_BYTES(256)))
#define MCE_NTUPLE_F_EN		 RTE_BIT32(31)
#define MCE_NTUPLE_F_P_EN	 RTE_BIT32(30)
#define MCE_NTUPLE_F_P_S	 (23)
#define MCE_NTUPLE_F_P_MASK	 GENMASK_U32(29, 23)
#define MCE_NTUPLE_F_PRIV_S	 (20)
#define MCE_NTUPLE_F_PRIV_MASK	 GENMASK_U32(22, 20)
#define MCE_NTUPLE_F_L3TYPE_MASK RTE_BIT32(19)
/* L4 dst port ignore */
#define MCE_NTUPLE_F_L4DP_MASK	 RTE_BIT32(18)
/* L4 src port ignore */
#define MCE_NTUPLE_F_L4SP_MASK	 RTE_BIT32(17)
#define MCE_NTUPLE_F_DIP_MASK	 RTE_BIT32(16)
#define MCE_NTUPLE_F_SIP_MASK	 RTE_BIT32(15)
#define MCE_NTUPLE_F_IPV6	 RTE_BIT32(8)
#define MCE_NTUPLE_F_ACT(entry) \
	_E_RQA_NTUPLE_F_(0x10 + ((entry) * BIT_TO_BYTES(256)))

/* common all rule action bit define */
#define MCE_RULE_ACTION_DROP	      RTE_BIT32(31)
#define MCE_RULE_ACTION_PASS	      (0)
#define MCE_RULE_ACTION_Q_EN	      RTE_BIT32(30)
#define MCE_RULE_ACTION_VLAN_EN	      RTE_BIT32(29)
#define MCE_RULE_ACTION_MARK_EN	      RTE_BIT32(28)
#define MCE_RULE_ACTION_PRIO_EN	      RTE_BIT32(27)
#define MCE_RULE_ACTION_Q_S	      (18)
#define MCE_RULE_ACTION_Q_MASK	      GENMASK_U32(28, 18)
#define MCE_RULE_ACTION_POP_VLAN_MASK GENMASK_U32(17, 16)
#define MCE_RULE_ACTION_POP_VLAN_S    (16)
#define MCE_RULE_ACTION_MARK_MASK     GENMASK_U32(15, 0)
enum mce_pop_vlan_tag {
	MCE_POP_1VLAN = 1,
	MCE_POP_2VLAN,
	MCE_POP_3VLAN,
};

/* RSS Ctrl Base */
#define MCE_ETH_RSS_KEY_ENTRY(vport, entry) \
	_E_RSS_(((vport) * BIT_TO_BYTES(512)) + ((12 - (entry)) << 2))
#define MCE_ETH_RSS_FUNC_SET(vport) \
	_E_RSS_(((vport) * BIT_TO_BYTES(512)) + (13 << 2))
#define MCE_VF_RSS_KEY_ENTRY(entry) (0x29000 + ((12 - (entry)) << 2))
#define MCE_RSS_KEY_ENTRY(b, entry) ((b) + ((12 - (entry)) << 2))
#define MCE_VF_RSS_FUNC_SET	    (0x29000 + (13 << 2))
#define MCE_RSS_FUNC_SET(b)         ((b) + (13 << 2))
#define MCE_RSS_HASH_FUNC_EN	    RTE_BIT32(31)
#define MCE_RSS_HASH_FUNC_XOR_EN    RTE_BIT32(30)
#define MCE_RSS_HASH_FUNC_ORDER_EN  RTE_BIT32(29)
#define MCE_RSS_HASH_PTP_EN	    RTE_BIT32(28)
#define MCE_RSS_HASH_ONLY_FLEX	    RTE_BIT32(14)
#define MCE_RSS_HASH_IPV4_FLEX	    RTE_BIT32(13)
#define MCE_RSS_HASH_IPV6_FLEX	    RTE_BIT32(12)
#define MCE_RSS_INPUT_IPV4_SPI	    RTE_BIT32(11)
#define MCE_RSS_INPUT_IPV6_SPI	    RTE_BIT32(10)
#define MCE_RSS_INPUT_IPV4_TEID	    RTE_BIT32(9)
#define MCE_RSS_INPUT_IPV6_TEID	    RTE_BIT32(8)
#define MCE_RSS_INPUT_IPV4	    RTE_BIT32(7)
#define MCE_RSS_INPUT_IPV6	    RTE_BIT32(6)
#define MCE_RSS_INPUT_IPV4_TCP	    RTE_BIT32(5)
#define MCE_RSS_INPUT_IPV6_TCP	    RTE_BIT32(4)
#define MCE_RSS_INPUT_IPV4_UDP	    RTE_BIT32(3)
#define MCE_RSS_INPUT_IPV6_UDP	    RTE_BIT32(2)
#define MCE_RSS_INPUT_IPV4_SCTP	    RTE_BIT32(1)
#define MCE_RSS_INPUT_IPV6_SCTP	    RTE_BIT32(0)
#define MCE_RSS_INPUT_MASK	    GENMASK_U32(11, 0)
#define MCE_RSS_FUNC_MASK	  GENMASK_U32(31, 29)
#define MCE_PF_ETH_RSS_RETA_BASE    _E_RSS_(0x6000)
#define MCE_VF_ETH_RSS_RETA_BASE    _E_RSS_(0x2000)
#define MCE_RSS_RETA_LO_MASK	    GENMASK_U32(15, 0)
#define MCE_RSS_RETA_HI_S	    (16)
#define MCE_PF_QUEUE_VLAN_STRIP_CTRL(entry) \
	_E_RSS_(0x4000 + BIT_TO_BYTES(32) * (entry))
#define MCE_PF_QUEUE_ATTR_CTRL	     MCE_PF_QUEUE_VLAN_STRIP_CTRL
#define MCE_RSS_ACT_ATTR(b, entry)   ((b) + BIT_TO_BYTES(32) * (entry))
#define MCE_Q_ATTR_RSS_DROP_EN	     RTE_BIT32(31)
#define MCE_Q_ATTR_RSS_Q_VALID	     RTE_BIT32(30)
#define MCE_Q_ATTR_RSS_POP_VLAN_EN   RTE_BIT32(29)
#define MCE_Q_ATTR_RSS_MARK_EN	     RTE_BIT32(28)
#define MCE_Q_ATTR_RSS_F_LEVEL_EN    RTE_BIT32(27)
#define MCE_Q_ATTR_RSS_F_LEVEL_MASK  GENMASK_U32(26, 21)
#define MCE_Q_ATTR_RSS_F_LEVEL_S     (21)
#define MCE_Q_ATTR_RSS_MARK_MASK     GENMASK_U32(15, 0)
#define MCE_VF_QUEUE_VLAN_STRIP_CTRL MCE_VF_ETH_RSS_RETA
#define MCE_QUEUE_STRIP_S	     (16)
#define MCE_QUEUE_STRIP_MASK	     GENMASK_U32(17, 16)
enum mce_strip_mode {
	MCE_VLAN_NO_STRIP = 0,
	MCE_VLAN_STRIP_QINQ,
	MCE_VLAN_STRIP_VLAN,
	MCE_VLAN_STRIP_3_TIP
};

#define MCE_RSS_RETA_QUEUE_S	  (16)
#define MCE_RSS_RETA_MASK	  GENMASK_U32(26, 18)
#define MCE_RSS_RATA_MARK_EN	  RTE_BIT32(28)
#define MCE_QUEUE_STRIP_VLAN_EN	  RTE_BIT32(29)
#define MCE_RSS_RATA_ENTRY_EN	  RTE_BIT32(30)

#define MCE_RSS_MARK_CTRL	  _ETH_(0x8024)
#define MCE_RSS_VF_MARK_S	  (16)
#define MCE_RSS_PF_MARK_MASK	  GENMASK_U32(15, 0)
#define MCE_RSS_VF_MARK_MASK	  GENMASK_U32(31, 16)
/* eth vport fwd attr ctrl */
/* vf trust ctrl */
#define MCE_ETH_VPORT_TRUST(pf)	  _ETH_(0xe000 + ((pf) * BIT_TO_BYTES(32)))
#define MCE_ETH_VPORT_TRUST_MASK  GENMASK_U32(0, 3)
#define MCE_ETH_FWD_ATTR(vport)	  _E_ATTR_(((vport) * BIT_TO_BYTES(32)))
#define MCE_VF_FWD_ATTR		  _SRIOV_(0x20000)
#define MCE_ATTR_TRUST_EN         RTE_BIT32(31)
/* enable vport max length to host */
#define MCE_FWD_LIMIT_LEN_EN	  RTE_BIT32(30)
/* limit the max-length packet to host */
#define MCE_FWD_MAXLEN_SHIFT	  (16)
#define MCE_FWD_MAXLEN_MASK	  GENMASK_U32(29, 16)
/* for unknown packet fwd packet to which ring of port */
#define MCE_FWD_DEF_RING_S	  (7)
#define MCE_FWD_DEF_RING_MASK	  GENMASK_U32(15, 7)
/* enable tunnel packet select which tun
 * when disable just use outer calculate
 */
#define MCE_FWD_TUNNEL_CTRL_MASK  GENMASK_U32(6, 5)
#define MCE_FWD_TUNNEL_CTRL_EN	  RTE_BIT32(5)
/* tunnel packet select inner to calculate */
#define MCE_FWD_SECLECT_INNER	  RTE_BIT32(6)
/* tunnel packet select outer to calculate */
#define MCE_FWD_SECLECT_OUTER	  (0 << 6)
/* Multicast Promisc Enable */
#define MCE_FWD_MPE		  (RTE_BIT32(4) | MCE_ATTR_TRUST_EN)
/* Unicast Promisc Enable */
#define MCE_FWD_PE		  (RTE_BIT32(3) | MCE_ATTR_TRUST_EN)
/* VLAN Promisc Enable */
#define MCE_FWD_VPE		  (RTE_BIT32(2) | MCE_ATTR_TRUST_EN)
/* Bypass the eth fwd engine */
#define MCE_FWD_BYPASS_EN	  RTE_BIT32(1)
/* all packet of vport drop enable */
#define MCE_FWD_DROP		  RTE_BIT32(0)

#define MCE_E_UPLINK_DEFAULT_VPRT _ETH_(0xe100)

#define MCE_BITMAP_DB(r, n) \
	_E_ATTR_(0x1000 + ((r) * 0x1000) + ((n) * BIT_TO_BYTES(32)))

/* global ctrl */
#define MCE_ETH_RX_MIN_LEN	_ETH_GBL_(0x80f0)
#define MCE_ETH_RX_MAX_LEN	_ETH_GBL_(0x80f0)
#define MCE_ETH_MAX_TSO_LEN	_ETH_GBL_(0x80f8)

#define MCE_ETH_OUT_2_VLAN_TYPE _ETH_GBL_(0x1634)
#define MCE_ETH_OUT_VLAN_TYPE(loc) \
	_ETH_GBL_(0x1700 + ((loc) * BIT_TO_BYTES(32)))
#define MCE_ETH_VLAN_TYPE(loc)	   _ETH_GBL_(0x1800 + ((loc) * BIT_TO_BYTES(32)))
#define MCE_ETH_I_OVLAN_TYPE(loc)  _ETH_(0x480 + ((loc) * BIT_TO_BYTES(32)))

#define MCE_VF_MC_FILTER_CTRL(n)   _ETH_(0xe200 + ((n) * BIT_TO_BYTES(32)))
#define MCE_VF_VLAN_FILTER_CTRL(n) _ETH_(0xe210 + ((n) * BIT_TO_BYTES(32)))
#define MCE_VF_MULCAST_CTRL0(vf, n)                     \
	_E_RQA_F_(0x4000 + ((vf) * BIT_TO_BYTES(512)) + \
		  ((n) * BIT_TO_BYTES(32)))
#define MCE_VF_MULCAST_CTRL1(vf, n)                     \
	_E_RQA_F_(0x6000 + ((vf) * BIT_TO_BYTES(512)) + \
		  ((n) * BIT_TO_BYTES(32)))
#define MCE_VF_VLAN_VID_CTRL(vf, n)                     \
	_E_RQA_F_(0x8000 + ((vf) * BIT_TO_BYTES(256)) + \
		  ((n) * BIT_TO_BYTES(32)))

/* Mac Manage Counts */
#define MCE_RX_TRANS_BUS                  _ETH_(0x0470)
#define MCE_RX_TRANS_READ                 _ETH_(0x6300)
#define MCE_TX_TRANS_BUS                  _ETH_(0x0474)
#define MCE_TX_TRANS_READ                 _ETH_(0x6554)

#define MCE_ETH_LIP_E_N			  _ETH_(0x6008)
#define MCE_ETH_TUN_LIP_E_N		  _ETH_(0x600c)
#define MCE_ETH_IVLAN_E_N		  _ETH_(0x6010)
#define MCE_ETH_RX_SCTP_CKSUM_E_N	  _ETH_(0x6014)
#define MCE_ETH_RX_L4_CKSUM_E_N		  _ETH_(0x6018)
#define MCE_ETH_RX_IPV4_CKSUM_E_N	  _ETH_(0x601c)
#define MCE_ETH_IP_LEN_E_N		  _ETH_(0x6020)
#define MCE_ETH_IP_HDR_L_E_N		  _ETH_(0x6024)

#define MCE_ETH_802_3_N			  _ETH_(0x6028)
#define MCE_ETH_PTP_N			  _ETH_(0x602c)
#define MCE_ETH_RDMA_N			  _ETH_(0x6030)
#define MCE_ETH_GTPU_N			  _ETH_(0x6034)
#define MCE_ETH_GTPC_N			  _ETH_(0x6038)
#define MCE_ETH_GENEVE_N		  _ETH_(0x603c)
#define MCE_ETH_VXLAN_N			  _ETH_(0x6040)
#define MCE_ETH_GRE_N			  _ETH_(0x6044)
#define MCE_ETH_ESP_N			  _ETH_(0x6048)
#define MCE_ETH_SCTP_N			  _ETH_(0x604c)
#define MCE_ETH_TCPSYNC_N		  _ETH_(0x6050)
#define MCE_ETH_TCP_N			  _ETH_(0x6054)
#define MCE_ETH_UDP_N			  _ETH_(0x6058)
#define MCE_ETH_ICMP6_N			  _ETH_(0x605c)
#define MCE_ETH_ICMP_N			  _ETH_(0x6060)
#define MCE_ETH_FRAG_N			  _ETH_(0x6064)
#define MCE_ETH_ARP_N			  _ETH_(0x6068)
#define MCE_ETH_IPV6_EXT_N		  _ETH_(0x606c)
#define MCE_ETH_IPV6_N			  _ETH_(0x6070)
#define MCE_ETH_IPV4_N			  _ETH_(0x6074)
#define MCE_ETH_LAY3_VLAN_N		  _ETH_(0x6078)
#define MCE_ETH_LAY2_VLAN_N		  _ETH_(0x607c)
#define MCE_ETH_LAY1_VLAN_N		  _ETH_(0x6080)
#define MCE_ETH_IN_SCTP_N		  _ETH_(0x6084)
#define MCE_ETH_IN_TCPSYNC_N		  _ETH_(0x6088)
#define MCE_ETH_IN_TCP_N		  _ETH_(0x608c)
#define MCE_ETH_IN_UDP_N		  _ETH_(0x6090)
#define MCE_ETH_IN_ICMP6_N		  _ETH_(0x6094)
#define MCE_ETH_IN_ICMP_N		  _ETH_(0x6098)
#define MCE_ETH_IN_FRAG_N		  _ETH_(0x609c)
#define MCE_ETH_IN_ARP_N		  _ETH_(0x60a0)
#define MCE_ETH_IN_IPV6_EXT_N		  _ETH_(0x60a4)
#define MCE_ETH_IN_IPV6_N		  _ETH_(0x60a8)
#define MCE_ETH_IN_IPV4_N		  _ETH_(0x60ac)
#define MCE_ETH_IN_LAY3_VLAN_N		  _ETH_(0x60b0)
#define MCE_ETH_IN_LAY2_VLAN_N		  _ETH_(0x60b4)
#define MCE_ETH_IN_LAY1_VLAN_N		  _ETH_(0x60b8)

#define MCE_ETH_L2_FILTER_DROP_N	  _ETH_(0x61a4)
#define MCE_ETH_FLOW_DIR_DROP_N		  _ETH_(0x6178)
#define MCE_ETH_STRIP_VLAN_N		  _ETH_(0x61dc)
#define MCE_ETH_STRIP_1VLAN_N		  _ETH_(0x61e0)
#define MCE_ETH_STRIP_2VLAN_N		  _ETH_(0x61e4)
#define MCE_ETH_STRIP_3VLAN_N		  _ETH_(0x61e8)

#define MCE_ETH_RX_TRANS_DROP_N		  _ETH_(0x6300)
#define MCE_ETH_RX_CRC_ERR_N		  _ETH_(0x6314)
#define MCE_ETH_RX_SLEN_DROP_N		  _ETH_(0x6318)
#define MCE_ETH_RX_GLEN_DROP_N		  _ETH_(0x631c)

#define MCE_ETH_FWD_VEB_DROP		  _ETH_(0x6238)

#define MCE_ETH_RX_POLICY_DROP_T_N	  _ETH_(0x61d8)
#define MCE_ETH_RX_MTU_LIMIT_DROP_N	  _ETH_(0x6174)
#define MCE_ETH_RX_FD_DROP_N		  _ETH_(0x6184)
#define MCE_ETH_RX_NTUPLE_DROP_N	  _ETH_(0x6180)

#define MCE_FDIR_HASH_CMD_CTRL		  _E_FDIR_F(0x40)
#define MCE_FDIR_HASH_ADDR_W		  _E_FDIR_F(0x44)
#define MCE_FDIR_HASH_DATA_W		  _E_FDIR_F(0x48)
#define MCE_FDIR_HASH_ENTRY_R		  _E_FDIR_F(0x4c)
#define MCE_FDIR_HASH_ENTRY_V		  _E_FDIR_F(0x50)
#define MCE_HASH_ENTRY_EN		  RTE_BIT64(13)

#define MCE_FDIR_EX_HASH_CTRL		  _E_FDIR_F(0x80)
#define MCE_FDIR_EX_HASH_ADDR_W		  _E_FDIR_F(0x84)
#define MCE_FDIR_EX_HASH_DATA_W		  _E_FDIR_F(0x88)
#define MCE_FDIR_EX_HASH_ADDR_R		  _E_FDIR_F(0x8c)
#define MCE_FDIR_EX_HASH_DATA_R		  _E_FDIR_F(0x90)
#define MCE_FDIR_EX_DATA_VLD		  RTE_BIT32(13)

#define MCE_FDIR_CTRL			  _E_FDIR_F(0x0)
#define MCE_FDIR_MAX_LEN		  GENMASK_U32(21, 16)
#define MCE_FDIR_MAX_LEN_S		  (16)
#define MCE_FDIR_L2_M_NONE		  (0)
#define MCE_FDIR_L2_M_VLAN		  (1)
#define MCE_FDIR_L2_M_MAC		  (2)
#define MCE_FDIR_MATCH_L2_EN		  GENMASK_U32(12, 11)
#define MCE_FDIR_L2_M_S			  (11)
#define MCE_FDIR_TUN_TYPE_HASH_EN	  RTE_BIT32(22)
#define MCE_FDIR_PRF_MASK_EN		  RTE_BIT32(13)
#define MCE_FDIR_HASH_PORT		  RTE_BIT32(10)
#define MCE_FDIR_SIGN_M_EN		  RTE_BIT32(9)
#define MCE_FDIR_GL_MASK_EN		  RTE_BIT32(8)
#define MCE_FDIR_PAY_PROTO_EN		  RTE_BIT32(7)
#define MCE_FDIR_IP_DSCP_EN		  RTE_BIT32(6)
#define MCE_FDIR_UDP_ESP_SPI_EN		  RTE_BIT32(5)
#define MCE_FDIR_TCP_MODE_SYNC		  RTE_BIT32(4)
#define MCE_FDIR_TUNPE_MODE		  GENMASK_U32(3, 0)

#define MCE_FDIR_LK_KEY			  _E_FDIR_F(0x08)
#define MCE_FDIR_SIGN_LK_KEY		  _E_FDIR_F(0x0c)
#define MCE_FDIR_CMD_CTRL		  _E_FDIR_F(0xc0)
#define MCE_FDIR_HW_RD			  RTE_BIT32(31)
#define MCE_FDIR_WR_CMD			  RTE_BIT32(0)
#define MCE_FDIR_RD_CMD			  RTE_BIT32(1)

#define MCE_FDIR_ENTRY_ID_EDIT		  _E_FDIR_F(0xc4)
#define MCE_FDIR_ENTRY_META_EDIT(n)	  _E_FDIR_F(0xc8 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FDIR_ENTRY_ID_READ		  _E_FDIR_F(0xe0)
#define MCE_FDIR_ENTRY_META_READ(n)	  _E_FDIR_F(0xe4 + ((n) * BIT_TO_BYTES(32)))

#define MCE_FDIR_META_LEN		  (BIT_TO_BYTES(384) / 4)
/* fdir rule age */
#define MCE_FDIR_RULE_AGE		  _E_FDIR_F(0x0018)
#define MCE_FDIR_AGE_EN			  RTE_BIT32(31)
#define MCE_FDIR_AGE_AUTO_EN		  RTE_BIT32(30)
/* 1bit == 1ms, max auto age time 8181ms  */
#define MCE_FDIR_AGE_TM_VAL		  GENMASK_U32(28, 16)
#define MCE_FDIR_AGE_TM_VAL_S		  (16)
#define MCE_FDIR_AGE_TM_READ		  RTE_BIT32(12)
#define MCE_FDIR_AGE_TM_WRITE		  RTE_BIT32(13)
#define MCE_FIDR_RULE_AGE_STATE		  _E_FDIR_F(0x001c)
/* fdir mask */
#define MCE_FDIR_MASK_ETH_KEY		  _E_FDIR_F(0x013c)
#define MCE_FDIR_MASK_ETH_KEY_MASK	  GENMASK_U32(2, 0)
#define MCE_FDIR_MASK_ETH_VLAN		  RTE_BIT32(0)
#define MCE_FDIR_MASK_ETH_DMAC		  RTE_BIT32(1)
#define MCE_FDIR_MASK_ETH_SMAC		  RTE_BIT32(2)

#define MCE_PROFILE_MASK_DB_CTRL(n)	  _E_FDIR_F(0x01c0 + ((n) * BIT_TO_BYTES(32)))
#define MCE_PROFILE_MASK_LOC		  RTE_GENMASK32(4, 0)
#define MCE_PROFILE_MASK_VALID_MASK	  RTE_GENMASK32(31, 16)
#define MCE_PROFILE_MASK_SELECT(n)	  _E_FDIR_F(0x01c0 + ((n) * BIT_TO_BYTES(32)))
#define MCE_PROFILE_FIELD_MASK_SELECT(id) _E_FDIR_F(0x0340 + ((id / 4) * 0x4))
#define MCE_PROFILE_FIELD_LOC_SHIFT(id)	  ((id % 4) * 8)

#define MCE_NIC_CTRL			  _NIC_(0x0004)
#define MCE_ESWITCH_EN			  RTE_BIT32(0)

#define MCE_FPGA_VF_NUM			  _NIC_(0xf000)
#define MCE_VF_NUM_MASK			  GENMASK_U32(11, 4)
#define MCE_VF_NUM_SHIFT		  (4)

#define MCE_MISE_IRQ_MASK		  _NIC_(0x1c)
#define MCE_TITAL_IRQ_REQ_NUM		  _MSIX_EX_(0xb004) /* 5003_b004 */

#define N20_VFNUM_ISOLATED		  (0x30000)
#define N20_VFNUM_NO_ISOLAT		  (0x7f000)

#define MCE_ETH_PTP_TX_TSVALUE_STATUS _ETH_(0x6488)
#define MCE_ETH_PTP_TX_LTIMES         _ETH_(0x6480)
#define MCE_ETH_PTP_TX_HTIMES         _ETH_(0x6484)
#define MCE_ETH_PTP_TX_CLEAR          _ETH_(0x4c0)
#endif /* _MCE_ETH_REGS_H_ */
