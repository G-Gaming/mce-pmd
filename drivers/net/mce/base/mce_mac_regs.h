#ifndef _MCE_MAC_REGS_H
#define _MCE_MAC_REGS_H

#include "mce_osdep.h"

#define MCE_M_MAC_CTRL		      _MAC_(0x00)
/* mac manager counter  read on clear */
#define MCE_M_RX_EN                   RTE_BIT32(27)
#define MCE_M_TX_EN                   RTE_BIT32(26)
#define MCE_M_MMC_RCLRC		      RTE_BIT32(24)
#define MCE_M_CRC_STRIP_EN            RTE_BIT32(15)
#define MCE_M_TX_PAD_EN               RTE_BIT32(14)
#define MCE_M_DIC_EN		      RTE_BIT32(13)

#define MCE_M_EXTAG_EN                RTE_BIT32(8)
#define MCE_M_QTAG_EN                 RTE_BIT32(7)
#define MCE_M_JUMBO_EN                RTE_BIT32(6)
#define MCE_M_JUMBO_LEN_C	      _MAC_(0xc)
#define MCE_M_JUMBO_M		     GENMASK_U32(31, 0)
#define MCE_M_RX_LEN_S		      (16)
#define MCE_M_IPG_CFG		      _MAC_(0x18)
#define MCE_M_IPG_VAL_MASK	     GENMASK_U32(7, 0)

#define MCE_MAC_PAUSE_TIMER          _MAC_(0x1c)
#define MCE_BYPASS_PTP_TIMER_EN      RTE_BIT32(28)
#define MCE_PTP_CFG                  _MAC_(0x60)
#define MCE_PTP_TCR_TSENA            RTE_BIT32(0) /*Timestamp Enable*/
#define MCE_PTP_TX_EN                RTE_BIT32(1)
#define MCE_PTP_RX_EN                RTE_BIT32(2)
/* Enable Timestamp for All Frames */
#define MCE_PTP_TCR_TSENALL          RTE_BIT32(8)
/* Enable Processing of PTP over Ethernet Frames */
#define MCE_PTP_TCR_TSIPENA          RTE_BIT32(9)
/* Enable Processing of PTP Frames Sent over IPv4-UDP */
#define MCE_PTP_TCR_TSIPV4ENA        RTE_BIT32(10)
/* Enable Processing of PTP Frames Sent over IPv6-UDP */
#define MCE_PTP_TCR_TSIPV6ENA        RTE_BIT32(11)
/* Support PTP Event SYNC/Delay_Req/Pdelay_Req/Pdelay_Resp */
/* Enable Timestamp Snapshot for Event Messages */
#define MCE_PTP_TCR_TSEVNTENA        RTE_BIT32(12)
#define MCE_TS_CFG_S                 _MAC_(0x300)
#define MCE_TS_CFG_NS                _MAC_(0x304)
#define MCE_TS_INCR_CNT              _MAC_(0x308) //[15:0] 2  bit[31:16] 16
#define MCE_INCR_CNT_NS_FINE         _MAC_(0x310)
#define MCE_INCR_CNT_NS_FINE_2       _MAC_(0x31c)
#define MCE_INITIAL_UPDATE_CMD       _MAC_(0x30c)
#define MCE_TM_INIT_CMD              RTE_BIT32(0)
#define MCE_TM_UPDATE_CMD            RTE_BIT32(1)
#define MCE_TM_TS_START              RTE_BIT32(2)
#define MCE_TS_GET_S                 _MAC_(0x314)
#define MCE_TS_GET_NS                _MAC_(0x318)
#define MCE_TS_COMP                  _MAC_(0x390)
/*----- MAC manager counter------------------- */
/* Rx FCS Error Frames Num Base */
#define MCE_M_RX_FCS_ERR	      _MAC_(0x88)
/* Rx Good Frame Num Base */
#define MCE_M_RX_GFRAMSB	      _MAC_(0x84)
#define MCE_M_RX_GFRAMSB_HI	      _MAC_(0xac)
/* Rx Good Bytes Base */
#define MCE_M_RX_GOCTGB		      _MAC_(0x180)
#define MCE_M_RX_GOCTGB_HI	      _MAC_(0x1cc)
/* RX Bad Frame Num Base */
#define MCE_M_RX_BFRMB		      _MAC_(0x184)
#define MCE_M_RX_BFRMB_HI	      _MAC_(0x1d0)
/* Rx Good Pause Frame Num Base */
#define MCE_M_RX_PAUSE_FRAMS	      _MAC_(0x94)
/* Rx Good Vlan Frame Num Base */
#define MCE_M_RX_VLAN_FRAMB	      _MAC_(0xa4)
/* Rx Good PFC priority 0 Frame Num */
#define MCE_M_RX_PFC_PRI0_NUM	      _MAC_(0xe0)
/* Rx Good PFC priority 1 Frame Num */
#define MCE_M_RX_PFC_PRI1_NUM	      _MAC_(0xe4)
/* Rx Good PFC priority 2 Frame Num */
#define MCE_M_RX_PFC_PRI2_NUM	      _MAC_(0xe8)
/* Rx Good PFC priority 3 Frame Num */
#define MCE_M_RX_PFC_PRI3_NUM	      _MAC_(0xec)
/* Rx Good PFC priority 4 Frame Num */
#define MCE_M_RX_PFC_PRI4_NUM	      _MAC_(0xf0)
/* Rx Good PFC priority 5 Frame Num */
#define MCE_M_RX_PFC_PRI5_NUM	      _MAC_(0xf4)
/* Rx Good PFC priority 6 Frame Num */
#define MCE_M_RX_PFC_PRI6_NUM	      _MAC_(0xf8)
/* Rx Good PFC priority 7 Frame Num */
#define MCE_M_RX_PFC_PRI7_NUM	      _MAC_(0xfc)
/* Rx Good Unicast Frame Num Base */
#define MCE_M_RX_GUCASTB	      _MAC_(0x188)
#define MCE_M_RX_GUCASTB_HI	      _MAC_(0x1d4)
/* Rx Good Multicast Frame Num Base */
#define MCE_M_RX_GMCASTB	      _MAC_(0x18c)
#define MCE_M_RX_GMCASTB_HI	      _MAC_(0x1d8)
/* Rx Good Broadcast Frame Num Base */
#define MCE_M_RX_GBCASTB	      _MAC_(0x190)
#define MCE_M_RX_GBCASTB_HI	      _MAC_(0x1dc)
/* Rx Good And Bad Bytes Num Base */
#define MCE_M_RX_GBOCTGB	      _MAC_(0x198)
#define MCE_M_RX_GBOCTGB_HI	      _MAC_(0x1e0)
/* Rx Good And Bad Frame Num Base */
#define MCE_M_RX_GBFRMB		      _MAC_(0x19c)
#define MCE_M_RX_GBFRMB_HI	      _MAC_(0x1e4)
/* Rx undersize_pkts_counter */
#define MCE_M_RX_USIZECB	      _MAC_(0x1a0)
/* Rx Good And Bad 64Bytes Frame Num */
#define MCE_M_RX_64_BYTESB	      _MAC_(0x1a4)
#define MCE_M_RX_64_BYTESB_HI	      _MAC_(0x1e8)
/* Rx Good And Bad 65 to 127 Bytes Frame Num */
#define MCE_M_RX_65TO127_BYTESB	      _MAC_(0x1a8)
#define MCE_M_RX_65TO127_BYTESB_HI    _MAC_(0x1ec)
/* Rx 128Bytes To 255Bytes Frame Num Base */
#define MCE_M_RX_128TO255_BYTESB      _MAC_(0x1ac)
#define MCE_M_RX_128TO255_BYTESB_HI   _MAC_(0x1f0)
/* Rx 256Bytes To 511Bytes Frame Num Base */
#define MCE_M_RX_256TO511_BYTESB      _MAC_(0x1b0)
#define MCE_M_RX_256TO511_BYTESB_HI   _MAC_(0x1f4)
/* Rx 512Bytes To 1023Bytes Frame Num Base */
#define MCE_M_RX_512TO1023_BYTESB     _MAC_(0x1b4)
#define MCE_M_RX_512TO1023_BYTESB_HI  _MAC_(0x1f8)
/* Rx 1024bytes To 1518Bytes Frame Num Base */
#define MCE_M_RX_1024TO1518_BYTESB    _MAC_(0x1b8)
#define MCE_M_RX_1024TO1518_BYTESB_HI _MAC_(0x178)
/* Rx 1519toMax Bytes Frame Num Base */
#define MCE_M_RX_1519TOMAX_BYTESB     _MAC_(0x1bc)
#define MCE_M_RX_1519TOMAX_BYTESB_HI  _MAC_(0x17c)
/* Rx len Oversize Than Support with correct crc */
#define MCE_M_RX_OSIZE_FRMB	      _MAC_(0x1c0)
/* Rx len Oversize Than support with invalid crc */
#define MCE_M_RX_JABBER_FRMB	      _MAC_(0x1c4)
/* Rx Less Than 64Byes with crc err Base*/
#define MCE_M_RX_RUNTERB	      _MAC_(0x1c8)
/* Rx discard num */
#define MCE_M_RX_DISCARD	      _MAC_(0x1fc)
/* Rx frame_too_long_errors_counter */
#define MCE_M_RX_TLE_FRMB	      _MAC_(0x98)
/* Rx alignment_errors_counter */
#define MCE_M_RX_ALIGNE_FRMB	      _MAC_(0x8c)
/* Rx in_range_length_errors_counter */
#define MCE_M_RX_ORSE_FRAM	      _MAC_(0x9c)

/* Tx Good Frame Num Base */
#define MCE_M_TX_GFRAMSB	      _MAC_(0x80)
#define MCE_M_TX_GFRAMSB_HI	      _MAC_(0xa8)
/* Tx Good Bytes Base */
#define MCE_M_TX_GOCTGB		      _MAC_(0x100)
#define MCE_M_TX_GOCTGB_HI	      _MAC_(0x140)
/* TX Bad Frame Num Base */
#define MCE_M_TX_BFRMB		      _MAC_(0x104)
#define MCE_M_TX_BFRMB_HI	      _MAC_(0x144)
/* Tx Good Pause Frame Num Base */
#define MCE_M_TX_PAUSE_FRAMS	      _MAC_(0x90)
/* Tx Good Vlan Frame Num Base */
#define MCE_M_TX_VLAN_FRAMB	      _MAC_(0xa0)
/* Tx Good PFC priority 0 Frame Num */
#define MCE_M_TX_PFC_PRI0_NUM	      _MAC_(0xc0)
/* Tx Good PFC priority 1 Frame Num */
#define MCE_M_TX_PFC_PRI1_NUM	      _MAC_(0xc4)
/* Tx Good PFC priority 2 Frame Num */
#define MCE_M_TX_PFC_PRI2_NUM	      _MAC_(0xc8)
/* Tx Good PFC priority 3 Frame Num */
#define MCE_M_TX_PFC_PRI3_NUM	      _MAC_(0xcc)
/* Tx Good PFC priority 4 Frame Num */
#define MCE_M_TX_PFC_PRI4_NUM	      _MAC_(0xd0)
/* Tx Good PFC priority 5 Frame Num */
#define MCE_M_TX_PFC_PRI5_NUM	      _MAC_(0xd4)
/* Tx Good PFC priority 6 Frame Num */
#define MCE_M_TX_PFC_PRI6_NUM	      _MAC_(0xd8)
/* Tx Good PFC priority 7 Frame Num */
#define MCE_M_TX_PFC_PRI7_NUM	      _MAC_(0xdc)
/* Tx Good Unicast Frame Num Base */
#define MCE_M_TX_GUCASTB	      _MAC_(0x108)
#define MCE_M_TX_GUCASTB_HI	      _MAC_(0x148)
/* Tx Good Multicast Frame Num Base */
#define MCE_M_TX_GMCASTB	      _MAC_(0x10c)
#define MCE_M_TX_GMCASTB_HI	      _MAC_(0x14c)
/* Tx Good Broadcast Frame Num Base */
#define MCE_M_TX_GBCASTB	      _MAC_(0x110)
#define MCE_M_TX_GBCASTB_HI	      _MAC_(0x150)
/* Tx Good And Bad Bytes Base */
#define MCE_M_TX_GBOCTGB	      _MAC_(0x114)
#define MCE_M_TX_GBOCTGB_HI	      _MAC_(0x154)
/* Tx Good And Bad Frame Num Base */
#define MCE_M_TX_GBFRMB		      _MAC_(0x118)
#define MCE_M_TX_GBFRMB_HI	      _MAC_(0x158)
/* Tx Good And Bad 64Bytes Frame Num */
#define MCE_M_TX_64_BYTESB	      _MAC_(0x11c)
#define MCE_M_TX_64_BYTESB_HI	      _MAC_(0x15c)
/* Tx Good And Bad 65 to 127 Bytes Frame Num */
#define MCE_M_TX_65TO127_BYTESB	      _MAC_(0x120)
#define MCE_M_TX_65TO127_BYTESB_HI    _MAC_(0x160)
/* Tx 128Bytes To 255Bytes Frame Num Base */
#define MCE_M_TX_128TO255_BYTESB      _MAC_(0x124)
#define MCE_M_TX_128TO255_BYTESB_HI   _MAC_(0x164)
/* Tx 256Bytes To 511Bytes Frame Num Base */
#define MCE_M_TX_256TO511_BYTESB      _MAC_(0x128)
#define MCE_M_TX_256TO511_BYTESB_HI   _MAC_(0x168)
/* Tx 512Bytes To 1023Bytes Frame Num Base */
#define MCE_M_TX_512TO1023_BYTESB     _MAC_(0x12c)
#define MCE_M_TX_512TO1023_BYTESB_HI  _MAC_(0x16c)
/* Tx 1024bytes To 1518Bytes Frame Num Base */
#define MCE_M_TX_1024TO1518_BYTESB    _MAC_(0x130)
#define MCE_M_TX_1024TO1518_BYTESB_HI _MAC_(0x170)
/* Tx 1519toMax Bytes Frame Num Base */
#define MCE_M_TX_1519TOMAX_BYTESB     _MAC_(0x134)
#define MCE_M_TX_1519TOMAX_BYTESB_HI  _MAC_(0x174)
/* Tx len Oversize Than Support with correct crc */
#define MCE_M_TX_OSIZE_FRMB	      _MAC_(0x138)
/* Tx len Oversize Than support with invalid crc */
#define MCE_M_TX_JABBER_FRMB	      _MAC_(0x13C)

#endif /* _MCE_MAC_REGS_H_ */
