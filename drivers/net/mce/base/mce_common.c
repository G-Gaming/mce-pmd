/**
 * @file mce_common.c
 * @brief Hardware initialization and common utility functions implementation
 *
 * Provides core hardware initialization, control register access, and utility
 * functions for the MCE PMD driver. Handles:
 * - Hardware reset and initialization
 * - Interrupt handling and MSIX configuration
 * - DMA setup and control
 * - Speed configuration and negotiation
 * - Memory and register dump utilities
 * - Checksum handling
 * - VLAN configuration
 *
 * Key Components:
 * - mce_reset_hw() - Full hardware reset sequence
 * - mce_init_hw() - Initialize hardware after reset
 * - Speed conversion functions (Mbps <-> hardware encoding)
 * - Memory dump and debug utilities
 * - Register and CSR access wrappers
 *
 * @see mce_common.h for public API and macro definitions
 * @see mce_hw.h for hardware structure definitions
 * @see base/mce_irq.c for interrupt configuration
 */

#include <errno.h>
#include <unistd.h>

#include <rte_ether.h>

#include "mce_common.h"
#include "mce_dma_regs.h"
#include "mce_eth_regs.h"
#include "mce_fwchnl.h"
#include "mce_hw.h"
#include "mce_irq.h"
#include "mce_mbx.h"
#include "mce_osdep.h"
#include "mce_rpu.h"
#include "mce_sched.h"
#include "mce_mac_regs.h"
#include "../mce.h"
#include "../mce_logs.h"
#include "../mce_compat.h"

/* Disable Rx/Tx Dma */
#define MCE_RX_RD_VALID RTE_BIT32(16)
#define MCE_RX_WR_VALID RTE_BIT32(17)
#define MCE_TX_RD_VALID RTE_BIT32(18)
#define MCE_TX_WR_VALID RTE_BIT32(19)
#define MCE_HW_RESET_REG	(0x70004)
#define MCE_HW_RESET_BIT	RTE_BIT32(6)

static s32 mce_reset_hw(struct mce_hw *hw)
{
	uint32_t reg = 0;

	rte_io_wmb();
	reg = MCE_E_REG_READ(hw, MCE_HW_RESET_REG);
	reg &= MCE_HW_RESET_BIT;
	wr32(hw, 0x70004, reg);
	rte_delay_ms(100);
	wr32(hw, MCE_HW_RESET, 0 | RTE_BIT32(16) | RTE_BIT32(18));
	rte_io_wmb();
	rte_delay_ms(100);
	wr32(hw, MCE_HW_RESET,
	     RTE_BIT32(0) | RTE_BIT32(2) | RTE_BIT32(16) | RTE_BIT32(18));
	mce_mbx_fw_nic_reset(hw);

	return 0;
}

static int speed_map[] = {
	0, 10, 100, 1000, 10000, 25000, 40000, 100000,
};

int speed_zip_to_bit3(int speed)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(speed_map); i++) {
		if (speed_map[i] == speed)
			return i;
	}
	return 0;
}

int speed_unzip(int speed_3bit)
{
	if (speed_3bit >= ARRAY_SIZE(speed_map))
		return 0;

	return speed_map[speed_3bit];
}

void mce_hexdump(const char *msg, void *_ptr, int bytes)
{
	u8 *ptr = _ptr;
	int i;

	printf("%s #%d\n", msg, bytes);
	printf("%05x: ", 0);
	for (i = 0; i < bytes; i++) {
		printf("%02x ", ptr[i]);
		if (i != 0 && (i % 16) == 0) {
			printf("\n");
			printf("%05x: ", i);
		}
	}
	printf("\n");
}

static void
mce_set_pf_default_vport(struct mce_hw *hw)
{
	int block_index, bit_index;
	uint32_t defalut_pf_port;
	uint16_t vport_id = 0;

	vport_id = (512 / hw->vf_max_ring) - 1;
	block_index = vport_id / 32;
	bit_index = vport_id % 32;
	defalut_pf_port = RTE_BIT32(bit_index);
	wr32(hw, 0x8e000 + 0x4 * block_index, defalut_pf_port);
	wr32(hw, 0x8e100 + 0x4 * block_index, defalut_pf_port);

	modify32(hw, MCE_ETH_FWD_CTRL,
			MCE_FWD_DEF_VPORT_MASK, vport_id << 25);
	modify32(hw, MCE_ETH_FWD_CTRL,
			0, MCE_FWD_TRUST_EN);
	/* set default uplink vport */
	if (hw->max_vfs)
		wr32(hw, MCE_E_UPLINK_DEFAULT_VPRT + 0x4 * block_index, defalut_pf_port);
}

static void
mce_set_default_mpls_tunnel(struct mce_hw *hw)
{
	/* mpls over udp mpls len */
	wr32(hw, 0x81620, 4);
	/* mpls over gre mpls len */
	wr32(hw, 0x81624, 4);
	/* mpls over geneve mpls len */
	wr32(hw, 0x81628, 4);
	/* mpls over vxlan-gpe mpls len */
	wr32(hw, 0x8162c, 4);
}

static void
mce_flush_etype(struct mce_hw *hw)
{
	wr32(hw, 0xbe000, 1);
	do {
		if (rd32(hw, 0xbe000) & RTE_BIT32(31))
			break;
	} while (1);
	wr32(hw, 0xbe000, 2);
	wr32(hw, 0xbe000, 0);
}

static void
mce_flush_bitmap(struct mce_hw *hw)
{
	wr32(hw, 0xa0200, 1);
	do {
		if (rd32(hw, 0xa0200) & RTE_BIT32(31))
			break;
	} while (1);
	wr32(hw, 0xa0200, 2);
	wr32(hw, 0xa0200, 0);
}

static void
mce_set_mem_init(struct mce_hw *hw)
{
	u32 ctrl = 0;
	u32 hw_state;
	int i = 0;
	int j = 0;

	/* clear hw memory */
	for (i = 0; i < 4096; i++) {
		do {
			hw_state = MCE_E_REG_READ(hw, MCE_FDIR_CMD_CTRL);
			if (!(hw_state & MCE_FDIR_HW_RD))
				break;
		} while (1);
		wr32(hw, MCE_FDIR_ENTRY_ID_EDIT, i);
		for (j = 0; j < MCE_FDIR_META_LEN; j++)
			wr32(hw, MCE_FDIR_ENTRY_META_EDIT(j), 0);
		wr32(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
	for (i = 0; i < 4096; i++) {
		do {
			hw_state = MCE_E_REG_READ(hw, MCE_FDIR_EX_HASH_CTRL);
			if (!(hw_state & MCE_FDIR_HW_RD))
				break;
		} while (1);
		wr32(hw, MCE_FDIR_EX_HASH_ADDR_W, i);
		wr32(hw, MCE_FDIR_EX_HASH_DATA_W, 0);
		wr32(hw, MCE_FDIR_EX_HASH_CTRL, MCE_FDIR_WR_CMD);
	}
	for (i = 0; i < 8192; i++) {
		do {
			hw_state = MCE_E_REG_READ(hw, MCE_FDIR_HASH_CMD_CTRL);
			if (!(hw_state & MCE_FDIR_HW_RD))
				break;
		} while (1);
		wr32(hw, MCE_FDIR_HASH_ADDR_W, i);
		wr32(hw, MCE_FDIR_HASH_DATA_W, 0);
		wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
	mce_flush_bitmap(hw);
	mce_flush_etype(hw);
	for (i = 0; i < MCE_MAX_RETA_LOC_SIZE; i++) {
		ctrl = MCE_Q_ATTR_RSS_Q_VALID;
		wr32(hw, MCE_PF_QUEUE_VLAN_STRIP_CTRL(i), ctrl);
	}
	/* setup FPGA default eth fifo thresh */
	wr32(hw, 0x804c0, 0x1004020); /* 1518 */
	wr32(hw, 0x804c0, 0x10040a0); /* 9732 */
	wr32(hw, 0x804c0, 0x1e040a0); /* good for 16384 */
	/* for tx port send fifo */
	wr32(hw, 0x84020, 0x110);
	/* for dma fifo */
	wr32(hw, 0x40088, 0x100);
	/* for tx tso fifo */
	wr32(hw, 0x840d8, 0x110);
}

#define N20_ETH_PROG_REG_LO(i, j) (_ETH_(0x2000) + ((i) * 0x200) + (0x8 * (j)))
#define N20_ETH_PROG_REG_HI(i, j) (_ETH_(0x2000) + ((i) * 0x200) + (0x8 * (j)) + 0x4)
static void mce_ddp_default_init(struct mce_hw *hw)
{
	int g_id, r_id;
	u32 val;

	/* reset all rules */
	for (g_id = 0; g_id < 16; g_id++) {
		for (r_id = 0; r_id < 4; r_id++) {
			val = 0;
			MODIFY_BITFIELD(val, g_id * 4 + r_id, 6, 24);
			wr32(hw, N20_ETH_PROG_REG_LO(r_id, g_id), 0x00);
			wr32(hw, N20_ETH_PROG_REG_HI(r_id, g_id), val);
		}
	}
	/* 88a8+88a8/8100+88a8 two vlan bypass  */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 0), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 0), 0x8083010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 0), 0x0030e218);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 0), 0xc183010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 0), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 0), 0x8283010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 0), 0x0030e218);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 0), 0xc383010c);
	/* arp */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 1), 0x0003984c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 1), 0x8403000c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 1), 0x000c96d1);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 1), 0xc503000c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 1), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 1), 0xc603000c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 1), 0x00c01463);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 1), 0xc703000c);
	/* 1vlan + arp */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 2), 0x000cd26e);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 2), 0x8803000e);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 2), 0x0030c018);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 2), 0xc903000e);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 2), 0x00c0030f);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 2), 0xca03000e);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 2), 0x03004fdf);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 2), 0xcb03000e);
	/* 2vlan + arp */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 3), 0x00304a32);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 3), 0x8c030010);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 3), 0x00c07906);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 3), 0xcd030010);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 3), 0x030020c6);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 3), 0xce030010);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 3), 0x0c008e1c);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 3), 0xcf030010);
	/* 8100 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 4), 0x80305a07);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 4), 0x9083010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 4), 0x8000803f);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 4), 0xd183010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 4), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 4), 0xd283010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 4), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 4), 0xd383010c);
	/* 8100 + io6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 5), 0x8030aadd);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 5), 0x9483010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 5), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 5), 0xd583010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 5), 0x800070e5);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 5), 0xd683010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 5), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 5), 0xd783010c);
	/* 8100 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 6), 0x80302a9c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 6), 0x9883010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 6), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 6), 0xd983010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 6), 0x8000f0a4);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 6), 0xda83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 6), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 6), 0xdb83010c);
	/* 8100 + 8100 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 7), 0x80305a07);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 7), 0x9c830110);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 7), 0x0033b0b7);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 7), 0xdd830110);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 7), 0x8003eab0);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 7), 0xde830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 7), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 7), 0xdf83010c);
	/* 8100 + 8100 + ip6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 8), 0x8030aadd);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 8), 0xa0830110);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 8), 0x0033b0b7);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 8), 0xe1830110);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 8), 0x80031a6a);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 8), 0xe2830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 8), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 8), 0xe383010c);
	/* 8100 + 8100 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 9), 0x80302a9c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 9), 0xa4830110);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 9), 0x0033b0b7);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 9), 0xe5830110);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 9), 0x80039a2b);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 9), 0xe6830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 9), 0x00036a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 9), 0xe783010c);
	/* 88a8 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 10), 0x80305a07);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 10), 0xa883010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 10), 0x8000803f);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 10), 0xe983010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 10), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 10), 0xea83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 10), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 10), 0xeb83010c);
	/* 88a8 + ip6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 11), 0x8030aadd);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 11), 0xac83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 11), 0x0030da38);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 11), 0xed83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 11), 0x800070e5);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 11), 0xee83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 11), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 11), 0xef83010c);
	/* 88a8 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 12), 0x80302a9c);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 12), 0xb083010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 12), 0x0033c31f);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 12), 0xf183010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 12), 0x8003e983);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 12), 0xf283010c);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 12), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 12), 0xf383010c);
	/* 1: ip4inip 2: 88a8 + 8100 + ip4inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 13), 0x080056e7);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 13), 0xb483010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 13), 0x00030b47);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 13), 0xf583010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 13), 0x80333088);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 13), 0xb6830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 13), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 13), 0xf783010c);
	/* 1: ip6inip 2: 88a8 + 8100 + ip6inip */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 14), 0x08007a32);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 14), 0xb883010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 14), 0x00030b47);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 14), 0xf983010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 14), 0x80336a8f);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 14), 0xba830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 14), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 14), 0xfb83010c);
	/* 1: gre 2: 88a8 + 8100 + gre */
	wr32(hw, N20_ETH_PROG_REG_LO(0, 15), 0x0800811b);
	wr32(hw, N20_ETH_PROG_REG_HI(0, 15), 0xbc83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(1, 15), 0x00030b47);
	wr32(hw, N20_ETH_PROG_REG_HI(1, 15), 0xfd83010c);
	wr32(hw, N20_ETH_PROG_REG_LO(2, 15), 0x80334013);
	wr32(hw, N20_ETH_PROG_REG_HI(2, 15), 0xbe830110);
	wr32(hw, N20_ETH_PROG_REG_LO(3, 15), 0x00031927);
	wr32(hw, N20_ETH_PROG_REG_HI(3, 15), 0xff83010c);
}

#define MCE_TUNNEL_TYPE_OFFSET(type)    (0x100 * (type))
#define MCE_TUNNEL_LOC_OFFSET(loc)      (0x4 * (loc))
#define MCE_TUNNEL_PORT_BASE            0x1000

#define MCE_TUNNEL_PORT_SETUP(type, loc) \
	_ETH_(MCE_TUNNEL_PORT_BASE + MCE_TUNNEL_TYPE_OFFSET(type) + MCE_TUNNEL_LOC_OFFSET(loc))
static void
mce_udp_tunnel_setup(struct mce_hw *hw,
		     enum mce_udp_tunnel_type type, uint16_t hw_loc,
		     uint16_t udp_port)
{
	wr32(hw, MCE_TUNNEL_PORT_SETUP(type, hw_loc), udp_port);
}

static void
mce_udp_tunnel_clear(struct mce_hw *hw,
		     enum mce_udp_tunnel_type type, uint16_t hw_loc)
{
	wr32(hw, MCE_TUNNEL_PORT_SETUP(type, hw_loc), 0);
}

int
mce_tunnel_udp_port_add(struct mce_pf *pf,
			enum mce_udp_tunnel_type tunnel_type,
			u16 udp_port)
{
	struct mce_tunnel_udp_port *tunnel = &pf->tunnel_port[tunnel_type];
	struct mce_hw *hw = MCE_DEV_TO_HW(pf->dev);;
	int i = 0;

	if (tunnel == NULL)
		return -1;
	if (tunnel->port_count == MAX_UDP_PORTS_PER_TUNNEL) {
		PMD_HW_ERR(hw, "max support 8 port parse:");
		return -ENOMEM;
	}
	for (i = 0; i < MAX_UDP_PORTS_PER_TUNNEL; i++) {
		if (tunnel->port_used[i] && tunnel->udp_ports[i] == udp_port) {
			PMD_HW_ERR(hw, "config has been exist");
			return -EEXIST;
		}
	}
	for (i = 0; i < MAX_UDP_PORTS_PER_TUNNEL; i++) {
		if (!tunnel->port_used[i]) {
			tunnel->udp_ports[i] = udp_port;
			tunnel->port_used[i] = true;
			tunnel->port_count++;
			break;
		}
	}
	mce_udp_tunnel_setup(hw, tunnel_type, i, udp_port);

	return 0;
}

int mce_tunnel_udp_port_remove(struct mce_pf *pf,
			       enum mce_udp_tunnel_type tunnel_type,
			       u16 udp_port)
{
	struct mce_tunnel_udp_port *tunnel = &pf->tunnel_port[tunnel_type];
	struct mce_hw *hw = MCE_DEV_TO_HW(pf->dev);;
	int i = 0;

	if (tunnel == NULL)
		return -1;
	for (i = 0; i < MAX_UDP_PORTS_PER_TUNNEL; i++) {
		if (tunnel->port_used[i] && tunnel->udp_ports[i] == udp_port) {
			tunnel->udp_ports[i] = 0;
			tunnel->port_used[i] = false;
			tunnel->port_count--;
			break;
		}
	}
	mce_udp_tunnel_clear(hw, tunnel_type, i);

	return 0;
}

static void
mce_rx_paser_init(struct mce_hw *hw)
{
	int i = 0;

	for (i = 0; i < 8; i++) {
		wr32(hw, MCE_ETH_OUT_VLAN_TYPE(i), 0xffff);
		wr32(hw, MCE_ETH_VLAN_TYPE(i), 0xffff);
		wr32(hw, MCE_ETH_I_OVLAN_TYPE(i), 0xffff);
	}
	/* rx vlan filter */
	wr32(hw, MCE_ETH_OUT_VLAN_TYPE(0), RTE_ETHER_TYPE_VLAN);
	wr32(hw, MCE_ETH_OUT_VLAN_TYPE(1), RTE_ETHER_TYPE_QINQ);
	wr32(hw, MCE_ETH_VLAN_TYPE(0), RTE_ETHER_TYPE_VLAN);
	wr32(hw, MCE_ETH_VLAN_TYPE(1), RTE_ETHER_TYPE_QINQ);
	/* tx vlan insert */
	wr32(hw, MCE_ETH_I_OVLAN_TYPE(0), RTE_ETHER_TYPE_VLAN);
	wr32(hw, MCE_ETH_I_OVLAN_TYPE(1), RTE_ETHER_TYPE_QINQ);
	/* setup esp udp port */
	wr32(hw, 0x81500, 4500);
	wr32(hw, 0x81504, 500);
	mce_set_default_mpls_tunnel(hw);
	mce_tunnel_udp_port_add(&hw->back->pf, MCE_TUNNEL_TYPE_VXLAN_GPE,
			RTE_VXLAN_GPE_DEFAULT_PORT);
	mce_tunnel_udp_port_add(&hw->back->pf, MCE_TUNNEL_TYPE_VXLAN,
			RTE_VXLAN_DEFAULT_PORT);
	mce_tunnel_udp_port_add(&hw->back->pf, MCE_TUNNEL_TYPE_GENEVE,
			RTE_GENEVE_DEFAULT_PORT);
	mce_tunnel_udp_port_add(&hw->back->pf, MCE_TUNNEL_TYPE_GPU_C,
			RTE_GTPC_UDP_PORT);
	mce_tunnel_udp_port_add(&hw->back->pf, MCE_TUNNEL_TYPE_GPU_U,
			RTE_GTPU_UDP_PORT);
	mce_tunnel_udp_port_add(&hw->back->pf, MCE_TUNNEL_TYPE_MPLSoUDP,
			RTE_MPLSoUDP_DEFAULT_PORT);
	mce_ddp_default_init(hw);
}

static void
mce_mac_init(struct mce_hw *hw)
{
	u32 reg = 0;

	reg = rd32(hw, MCE_M_MAC_CTRL);
	reg |= MCE_M_DIC_EN | MCE_M_JUMBO_EN;
	reg &= ~MCE_M_MMC_RCLRC;
	reg |= MCE_M_RX_EN;
	reg |= MCE_M_TX_EN;
	reg |= MCE_M_CRC_STRIP_EN;
	reg |= MCE_M_TX_PAD_EN;
	reg |= MCE_M_EXTAG_EN;
	reg |= MCE_M_QTAG_EN;
	wr32(hw, MCE_M_MAC_CTRL, reg);
	modify32(hw, MCE_M_IPG_CFG, MCE_M_IPG_VAL_MASK, 10);
	reg = MCE_M_MAX_JUMBO << MCE_M_RX_LEN_S;
	reg |= MCE_M_MAX_JUMBO;
	modify32(hw, MCE_M_JUMBO_LEN_C, MCE_M_JUMBO_M, reg);
}

static void mce_dma_init(struct mce_hw *hw)
{
	int i = 0;

	for (i = 0; i < 512; i++) {
		wr32(hw, MCE_DMA_RXQ_START(i), MCE_DMA_Q_FLR_EN);
		wr32(hw, MCE_DMA_TXQ_START(i), MCE_DMA_Q_FLR_EN);
	}
}

static void
mce_eth_init(struct mce_hw *hw)
{
	u32 reg = 0;

	wr32(hw, MCE_ETH_RQA_CTRL,
			MCE_RQA_REDIR_EN |
			MCE_RQA_FDIR_EN |
			MCE_RQA_ETHTYPE_EN |
			MCE_RQA_RSS_EN | MCE_RQA_5TUPLE_EN |
			MCE_RQA_TCP_SYNC_EN);
	reg = MCE_G_L2_FILTER_EN | MCE_G_DMAC_FILTER_EN;
	reg |= MCE_G_BROADCAST_PROMISC;
	reg |= MCE_G_DIR_RDMA_EN;
	if(hw->is_ocp_card){
		reg |= MCE_G_MNG_FILTER_EN;
	}
	if (hw->max_vfs) {
		u32 ctrl;

		ctrl = MCE_E_REG_READ(hw, MCE_ETH_GLOBAL_L2_EX_F_CTRL);
		ctrl |= MCE_G_MCAST_CVERT_TO_BCAST;
		wr32(hw, MCE_ETH_GLOBAL_L2_EX_F_CTRL, ctrl);

		ctrl = MCE_E_REG_READ(hw, MCE_ETH_RQA_CTRL);
		ctrl |= MCE_RQA_MULTICAST_F_EN;
		ctrl |= MCE_RQA_VF_VIDF_EN;
		wr32(hw, MCE_ETH_RQA_CTRL, ctrl);
		mce_set_pf_default_vport(hw);
	} else {
		reg |= MCE_G_UNICAST_HASH_F_EN;
		reg |= MCE_G_MULTICAST_HASH_F_EN;
		reg |= MCE_G_MULTICAST_HASH_SEL;
		reg |= MCE_G_UNICAST_HASH_SEL;
	}
	wr32(hw, MCE_ETH_GLOBAL_L2_F_CTRL, reg);
}

int mce_init_hw(struct mce_hw *hw)
{
	struct port_ablity ablity = { 0 };
	u32 total_queue = 0;
	uint32_t version;
	uint32_t reg = 0;
	int err;

	PMD_INIT_FUNC_TRACE();

	version = rd32(hw, MCE_DMA_VERSION);
	PMD_DRV_LOG(INFO, "NIC HW Version:0x%.2x\n", version);
	if ((version & 0xFFF00000) != 0x20200000) {
		PMD_HW_ERR(hw, "%s", "invalid dma-version\n");
		return -EIO;
	}
	/* disable ext irq to rc irq*/
	modify32(hw, MCE_MISE_IRQ_MASK, 0xffff0000, 0);
	hw->total_irq_req_num = rd32(hw, MCE_TITAL_IRQ_REQ_NUM);
	/* mailbox */
	{
		mce_setup_pf_mbx_info(hw, &hw->vf2pf_mbx);
		mce_setup_pf2fw_mbx_info(hw, &hw->pf2fw_mbx);
		mce_mbx_init_configure(&hw->pf2fw_mbx);
		err = mce_fw_get_ablity(hw, &ablity);
		if (err < 0) {
			PMD_HW_ERR(hw, "get ablity failed: err:%d\n", err);
			return -EIO;
		}
		hw->fw_stat.stat0.v = _rd32(hw->dm_stat);
		hw->fw_stat.stat1.v = _rd32(hw->nic_stat);

		hw->fw_stat.stat2.mac_addr_hi = _rd32(
				hw->ext_stat + offsetof(struct ext_stat, mac_addr_hi));
		hw->fw_stat.stat2.mac_addr_lo = _rd32(
				hw->ext_stat + offsetof(struct ext_stat, mac_addr_lo));
		hw->fw_stat.stat2.fw_version = _rd32(
				hw->ext_stat + offsetof(struct ext_stat, fw_version));
		hw->fw_stat.stat2.pxe_version = _rd32(
				hw->ext_stat + offsetof(struct ext_stat, pxe_version));
		hw->fw_stat.stat2.ext.v =
			_rd32(hw->ext_stat + offsetof(struct ext_stat, ext));
		memcpy(hw->perm_mac_addr, (u8 *)&hw->fw_stat.stat2.mac_addr,
				6);
		hw->vf_bar_isolate_on = !hw->fw_stat.stat1.vf_isolate_disabled;
	}
	rte_io_wmb();
	wr32(hw, MCE_ETH_RX_ES_DROP_CTRL, ENABLE);
	wr32(hw, MCE_ETH_TX_ES_DROP_CTRL, ENABLE);
	rte_io_wmb();
	modify32(hw, MCE_ETH_RX_ES_DROP_CTRL, 0, RTE_BIT32(0));
	modify32(hw, MCE_ETH_TX_ES_DROP_CTRL, 0, RTE_BIT32(0));
	rte_io_wmb();
	wr32(hw, MCE_AXI_CTRL, 0 | GENMASK_U32(19, 16));
	/* wait for dma axi disabled */
	rte_io_rmb();
	while (rd32(hw, MCE_AXI_STATE) == 0)
		;
	rte_io_wmb();

	/* Reset Nic All Hardware */
	if (mce_reset_hw(hw))
		return -EPERM;
	rte_io_rmb();
	while (rd32(hw, MCE_HW_RESET_DONE) == 0)
		;
	rte_io_wmb();
	modify32(hw, MCE_ETH_RX_ES_DROP_CTRL, 0, RTE_BIT32(0));
	modify32(hw, MCE_ETH_TX_ES_DROP_CTRL, 0, RTE_BIT32(0));
#ifdef PHYTIUM_SUPPORT
#define MCE_DMA_PADDING (1 << 8)
	reg |= MCE_DMA_PADDING;
#endif
	wr32(hw, MCE_DMA_CTRL, reg);
	/* Enabled REDIR ACTION */
	mce_eth_init(hw);
	mce_dma_init(hw);
	/* Enable Rx/Tx Dma */
	wr32(hw, MCE_AXI_CTRL, 0xf | GENMASK_U32(19, 16));
	mce_set_mem_init(hw);
	/* mac init */
	mce_mac_init(hw);
	mce_sched_init(hw);
	/* set dma fifo full thresh */
	/* setup tso max pkt len limit */
	wr32(hw, MCE_ETH_MAX_TSO_LEN, 16000 + 64 - 4);
	if (ablity.rpu_en == 0)
		hw->npu_base = NULL;
	if (hw->npu_base)
		download_n20_rpu_firmware(hw);
	total_queue = MCE_E_REG_GET_VAL(hw, MCE_DMA_STATE, MCE_HW_QUEUE);
	if (total_queue == 0)
		total_queue = 512;
	if (hw->max_vfs) {
		hw->max_reta_num = hw->vf_max_ring;
		hw->nb_mulcast_per_vf = MCE_MCAST_ADDR_PER_VF;
		hw->nb_qpair_per_vf = hw->vf_max_ring;
		hw->nb_qpair = hw->nb_qpair_per_vf;
		hw->nb_vid_per_vf = 16;
		hw->nb_mac_per_vf = 4;
	} else {
		hw->max_reta_num = MCE_MAX_RETA_LOC_SIZE;
		hw->nb_mulcast_per_vf = 0;
		hw->nb_qpair_per_vf = 0;
		hw->nb_vid_per_vf = 0;
		hw->nb_mac_per_vf = 0;
		hw->nb_qpair = total_queue;
	}
	mce_rx_paser_init(hw);
	/* setup irq0 vector */
	mce_update_fw_stat(hw);

	return 0;
}
