#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>

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

#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION
#include <rte_telemetry.h>

#include "mce_rxtx.h"
#include "mce_fwchnl.h"
#include "mce.h"
#include "mce_logs.h"

struct mce_tel_ctx {
	struct rte_tel_data *d;
	int entries;
	struct mce_hw *hw;
};

static void tel_println(struct mce_tel_ctx* ctx, const char*fmt,...);

struct item {
	unsigned char hi;
	unsigned char lo;
	char func_id;
	const char *value_fmt;
	const char *item_descript;
};

#define FIELD(bit_hi, bit_lo, fmt_str, descript) \
	&((struct item){ bit_hi, bit_lo, -1, fmt_str, descript })

#define F32(fmt_str, descript) &((struct item){ 31, 0, -1, fmt_str, descript })
#define D32(descript) &((struct item){ 31, 0, -1, "%u", descript })
#define D_32BIT &((struct item){ 31, 0, -1, "%u", "" })
#define D_FIELD(descript, bit_hi, bit_lo) \
	&((struct item){ bit_hi, bit_lo, -1, "%u", descript })
#define H32(descript) &((struct item){ 31, 0, -1, "0x%x", descript })
#define Hex_32BIT &((struct item){ 31, 0, -1, "0x%x", "" })

#define FUNC_FIELD(func_id, descript, bit_hi, bit_lo, fmt_str) \
	&((struct item){ bit_hi, bit_lo, func_id, fmt_str, descript })

#define FUNC_D32(func_id) &((struct item){ 31, 0, func_id, "%u", "" })
#define FUNC_D32_DESC(func_id, desc) \
	&((struct item){ 31, 0, func_id, "%u", desc })

#define CFG_RXMUX_CTRL_REG 0x8e584
#define DEBUG_RXMUX_BUS 0x86304

#define DEBUG_TXMUX_BUS 0x86550
#define CFG_TXMUX_CTRL_REG 0x8e588

#define DEBUG_RXTRANS_BUS 0x86300
#define CFG_RXTRANS_CTRL_REG 0x80470

#define DEBUG_TXTRANS_BUS 0x86554
#define CFG_TXTRANS_CTRL_REG 0x80474

#define EMAC_POST_CRTL_REG 0x8047c
#define RX_DEBUG24_REG 0x86460
#define RX_DEBUG25_REG 0x86464
#define RX_DEBUG26_REG 0x86468
#define RX_DEBUG27_REG 0x8646c

#define DBG_RX_SWITCH_BUS 0x73004
#define CFG_RX_SWITCH_CTRL_REG 0x73000

static inline unsigned int value_pick_bits(unsigned int v, int bit_hi,
					   int bit_lo)
{
	v = v >> bit_lo;

	return v & GENMASK_U32(bit_hi - bit_lo, 0);
}

static inline unsigned int reg_read_bits(u8 *reg, int bit_hi, int bit_lo)
{
	unsigned int v;

	v = rte_read32(reg);
	return value_pick_bits(v, bit_hi, bit_lo);
}

static inline void reg_modify_bits(u8 *reg, int bit_hi, int bit_lo,
				   int value_no_shift)
{
	unsigned int v, mask;

	mask = GENMASK_U32(bit_hi, bit_lo);

	value_no_shift &= GENMASK_U32(bit_hi - bit_lo, 0);

	v = rte_read32(reg);
	v &= ~((unsigned int)mask);
	v |= value_no_shift << bit_lo;
	rte_write32_relaxed(v, reg);
}

static int do_indir_func_reg_read(struct mce_hw *hw, int reg, int func_id,
				  int *v)
{
	if (!(reg >= 0 && reg < 2 * 1024 * 1024)) {
		return -EINVAL;
	}

	switch (reg) {
	case DEBUG_RXMUX_BUS: {
		reg_modify_bits(hw->nic_base + CFG_RXMUX_CTRL_REG, 31, 27,
				func_id);

		*v = rte_read32(hw->nic_base + reg);
		break;
	}
	case DEBUG_TXMUX_BUS: {
		reg_modify_bits(hw->nic_base + CFG_TXMUX_CTRL_REG, 31, 27,
				func_id);

		*v = rte_read32(hw->nic_base + reg);
		break;
	}
	case DEBUG_RXTRANS_BUS: {
		reg_modify_bits(hw->nic_base + CFG_RXTRANS_CTRL_REG, 29, 24,
				func_id);

		*v = rte_read32(hw->nic_base + reg);
		break;
	}
	case RX_DEBUG24_REG:
	case RX_DEBUG25_REG:
	case RX_DEBUG26_REG:
	case RX_DEBUG27_REG: {
		reg_modify_bits(hw->nic_base + EMAC_POST_CRTL_REG, 23, 16,
				func_id);

		*v = rte_read32(hw->nic_base + reg);
		break;
	}
	case 0x86500:
	case 0x86504:
	case 0x86508: {
		reg_modify_bits(hw->nic_base + 0x880f8, 31, 28, func_id);

		*v = rte_read32(hw->nic_base + reg);
		break;
	}

	case DEBUG_TXTRANS_BUS: {
		reg_modify_bits(hw->nic_base + CFG_TXTRANS_CTRL_REG, 29, 24,
				func_id);

		*v = rte_read32(hw->nic_base + reg);
		break;
	}
	case DBG_RX_SWITCH_BUS: {
		reg_modify_bits(hw->nic_base + CFG_RX_SWITCH_CTRL_REG, 21,
				16, func_id);

		*v = rte_read32(hw->nic_base + reg);
		break;
	}
	default: {
		return -EINVAL;
	}
	}

	return 0;
}

static int do_normal_reg_read(struct mce_hw *hw, unsigned int reg, int *v)
{
	if (reg < 2 * 1024 * 1024) { /* bar4 reg */
		*v = rte_read32(hw->nic_base + reg);
	} else if (reg >= 0x30000000 && reg < 0x80000000) {
		/* soc reg */
		if (mce_soc_ioread32(hw, reg, v)) {
			return -EIO;
		}
	} else {
		return -EINVAL;
	}
	return 0;
}

static int dsnprintf(char*dst, int dst_sz,const char *fmt,...)
{
	char buf[512];
	va_list args;

	if(dst_sz <=0)
		return 0;

	memset(buf,0, sizeof(buf));

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	rte_strlcpy(dst, buf, dst_sz);
	return strlen(buf);
}

static int snprintf_reg(struct mce_hw *hw, char *big_buf,
			int big_buf_sz,const char *descript,
			unsigned int reg, ...)
{
	int i, cnt = 0, v, err;
	int bsz = 4096;
	char buf[4096];
	va_list args;

	va_start(args, reg);

	cnt += snprintf(buf + cnt, bsz - cnt, "%-26s 0x%-8x: ", descript, reg);

	for (i = 0; i < 32; i++) {
		struct item *it = va_arg(args, struct item *);
		if (it == NULL) {
			break;
		}

		if (i != 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, ",\t");
			if ((i % 3) == 0) {
				cnt += snprintf(buf + cnt, bsz - cnt, "\n\t\t\t\t\t\t\t");
			}
		}

		if (it->func_id > 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, "F%-2d ", it->func_id);
			err = do_indir_func_reg_read(hw, reg, it->func_id, &v);
		} else {
			err = do_normal_reg_read(hw, reg, &v);
		}

		if (it->item_descript && strlen(it->item_descript) >= 1) {
			cnt += snprintf(buf + cnt, bsz - cnt, "%s", it->item_descript);
		}

		if (err) {
			cnt += snprintf(buf + cnt, bsz - cnt, " !read error!");
			continue;
		}

		if (!(it->hi == 31 && it->lo == 0)) {
			if (it->hi == it->lo) {
				cnt += snprintf(buf + cnt, bsz - cnt, "[%d]=", it->hi);
			} else {
				cnt += snprintf(buf + cnt, bsz - cnt, "[%d:%d]=", it->hi, it->lo);
			}
		}

		v = value_pick_bits(v, it->hi, it->lo);
		if (it->value_fmt == NULL || strlen(it->value_fmt) == 0) {
			cnt += snprintf(buf + cnt, bsz - cnt, "%u / 0x%x", v, v);
		} else {
			cnt += dsnprintf(buf + cnt, bsz  - cnt , it->value_fmt, v);
		}
	}

	cnt += snprintf(buf + cnt, bsz - cnt, "\n");
	buf[cnt] = 0;

	va_end(args);

	if (cnt > big_buf_sz) {
		cnt = big_buf_sz;
	}
	rte_strlcpy(big_buf, buf, big_buf_sz);

	return cnt;
}

#define SNPRINTF_REG(args...) \
	snprintf_reg(hw, buf + cnt, buf_sz - cnt, args, NULL)
#define SNPRINTF(args...) snprintf(buf + cnt, buf_sz - cnt, args)
static int split_string(const char *str, char *argv[50],
			char *buf, int buf_sz,
			const char *new_spliter)
{
	const char* spliter=" ,\t\n";
	char *token;
	int cnts = 0;

	if (str == NULL)
		return 0;
	if (new_spliter)
		spliter = new_spliter;
	rte_strlcpy(buf, str, buf_sz);
	token = strtok(buf, spliter);
	while (token != NULL && (cnts < 50)) {
		argv[cnts++] = token;
		token = strtok(NULL, spliter);
	}
	return cnts;
}

static struct rte_eth_dev *get_mce_port(int port_id)
{
	uint16_t ethdev_num =  rte_eth_dev_count_avail();
	struct rte_eth_dev *eth_dev = NULL;

	if (ethdev_num == 0)
		return NULL;
	if (port_id > (ethdev_num - 1))
		return NULL;
	eth_dev = &rte_eth_devices[port_id];
	if (eth_dev == NULL || !is_mce_supported(eth_dev))
		return NULL;
	return eth_dev;
}

static void tel_ctx_init(struct mce_tel_ctx *ctx, struct rte_tel_data *d)
{
	ctx->entries = 0;
	ctx->d = d;

	rte_tel_data_start_array(d, RTE_TEL_STRING_VAL);
}

__maybe_unused static void
tel_print_string_overwrite(struct mce_tel_ctx *ctx, const char *fmt,...)
{
	char buf[RTE_TEL_MAX_SINGLE_STRING_LEN];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	rte_tel_data_string(ctx->d, buf);
	ctx->entries = RTE_TEL_MAX_ARRAY_ENTRIES;
}

static void tel_println(struct mce_tel_ctx *ctx, const char *fmt,...)
{
	char buf[RTE_TEL_MAX_STRING_LEN];
	va_list ap;

	if (ctx->entries > RTE_TEL_MAX_ARRAY_ENTRIES)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	rte_tel_data_add_array_string(ctx->d, buf);
	ctx->entries++;
}

static int
mce_rx_ring_desc_handle_info(const char *cmd __rte_unused,
			     const char *params, struct rte_tel_data *d)
{
	volatile union mce_rx_desc *desc;
	struct mce_rx_queue *rxq = NULL;
	struct rte_eth_dev *eth_dev;
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	int argc = 0, port = 0, ring = 0, loc = 0;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc != 3) {
		tel_println(&ctx, "Usage:   /mce/rx_ring_desc,port ring desc_loc");
		return 0;
	}
	port = atoi(argv[0]);
	ring = atoi(argv[1]);
	loc = atoi(argv[2]);
	eth_dev = get_mce_port(port);
	if (eth_dev == NULL) {
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}
	if (ring >= eth_dev->data->nb_rx_queues) {
		tel_println(&ctx, "error: ring num is out of range(%d)", eth_dev->data->nb_rx_queues);
		return 0;
	}
	rxq = eth_dev->data->rx_queues[ring];
	if (loc >= rxq->attr.nb_desc) {
		tel_println(&ctx, "error: desc loc is out of range(%d)", rxq->attr.nb_desc);
		return 0;
	}
	desc = &rxq->rx_bdr[loc];
	/* start record info */
	tel_println(&ctx, "port: %d", port);
	tel_println(&ctx, "ring: %d", ring);
	tel_println(&ctx, "location: %d", loc);
	if (desc->wb.cmd) {
		tel_println(&ctx, "rss_hash: 0x%x", desc->wb.rss_hash);
		tel_println(&ctx, "len_pad: 0x%x", desc->wb.len_pad);
		tel_println(&ctx, "vlan_tag1: %d", desc->wb.vlan_tag1);
		tel_println(&ctx, "vlan_tag2: %d", desc->wb.vlan_tag2);
		tel_println(&ctx, "timestamp_h: 0x%x", desc->wb.stamp.timestamp_h);
		tel_println(&ctx, "timestamp_l: 0x%x", desc->wb.stamp.timestamp_l);
		tel_println(&ctx, "mark_id: %d", desc->wb.mark_id);
		tel_println(&ctx, "csum_err_and_f_cmd: 0x%x",  desc->wb.err_cmd);
		tel_println(&ctx, "cmd: 0x%x", desc->wb.cmd, 0);
	} else {
		tel_println(&ctx, "addr: 0x%x", desc->d.pkt_addr);
	}

	return 0;
}

static int
mce_tx_ring_desc_handle_info(const char *cmd __rte_unused,
			     const char *params, struct rte_tel_data *d)
{
	volatile union mce_tx_desc *desc;
	struct mce_tx_queue *txq = NULL;
	struct rte_eth_dev *eth_dev;
	char *argv[50]={0}, buf[512];
	struct mce_tel_ctx ctx;
	int ethdev_num = 0, argc = 0, port = 0, ring = 0, loc = 0;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf), NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if (argc == 1 && !strcmp(argv[0], "help")) {
		tel_println(&ctx, "Usage: /mce/tx_ring_desc,port ring desc_loc");
		return 0;
	}
	if (argc < 3) {
		tel_println(&ctx, "error: insufficient parameters");
		return 0;
	}
	port = atoi(argv[0]);
	ring = atoi(argv[1]);
	loc = atoi(argv[2]);
	ethdev_num = rte_eth_dev_count_avail();
	if (port >= ethdev_num) {
		tel_println(&ctx, "error: invalid port number");
		return 0;
	}
	eth_dev = &rte_eth_devices[port];
	if (!eth_dev) {
		tel_println(&ctx, "error: device not found");
		return 0;
	}
	if (!is_mce_supported(eth_dev)) {
		tel_println(&ctx, "error: port is not MCE (n20) supported");
		return 0;
	}
	if (ring >= eth_dev->data->nb_tx_queues) {
		tel_println(&ctx, "error: ring number out of range(%d)", eth_dev->data->nb_tx_queues);
		return 0;
	}
	txq = eth_dev->data->tx_queues[ring];
	if (!txq) {
		tel_println(&ctx, "error: TX queue not found");
		return 0;
	}
	if (loc >= txq->attr.nb_desc) {
		tel_println(&ctx, "error:  descriptor location out of range(%d)", txq->attr.nb_desc);
		return 0;
	}
	desc = &txq->tx_bdr[loc];

	tel_println(&ctx, "port: %d", port);
	tel_println(&ctx, "ring: %d", ring);
	tel_println(&ctx, "location: %d", loc);

	tel_println(&ctx, "addr: 0x%x", desc->d.pkt_addr);
	tel_println(&ctx, "length: %d", desc->d.qword1.length);
	tel_println(&ctx, "macip_len: %d", desc->d.qword1.macip_len);
	tel_println(&ctx, "in_macip_len: %d", desc->d.qword2.in_macip_len);
	tel_println(&ctx, "vlan0: %d", desc->d.qword2.vlan0);
	tel_println(&ctx, "vlan1: %d", desc->d.qword3.vlan1);
	tel_println(&ctx, "mss: %d", desc->d.qword4.mss);
	tel_println(&ctx, "l4_tun_len: %d", desc->d.qword4.l4_tun_len);
	tel_println(&ctx, "mac_vlan_ctrl: %d", desc->d.qword5.mac_vlan_ctrl);
	tel_println(&ctx, "in_l3l4_type: %d", desc->d.qword5.in_l3l4_type);
	tel_println(&ctx, "cmd: 0x%x", desc->d.qword6.cmd);

	return 0;
}

static void
add_register_to_telemetry(struct mce_tel_ctx *ctx, uint32_t value, int mode,
			  int show_bits, int group_size)
{
	int i = 0;

	if (mode == 1 || mode == 2) {
		char bin_str[128] = "";
		char bit_str[128] = "";
		int pos = 0;

		if (show_bits) {
			pos += snprintf(bit_str + pos,sizeof(bit_str) - pos,"                    ");
			for (i = 31; i >= 0; i--) {
				pos += snprintf(bit_str + pos, sizeof(bit_str) - pos, "%2d ", i);
				if (group_size > 0 && i > 0 && i % group_size == 0)
					pos += snprintf(bit_str + pos, sizeof(bit_str) - pos, " ");
			}
			tel_println(ctx, bit_str);
		}
		pos = 0;
		pos += snprintf(bin_str + pos,sizeof(bin_str) - pos,"                    ");
		for (i = 31; i >= 0; i--) {
			int bit = (value >> i) & 1;
			pos += snprintf(bin_str + pos, sizeof(bin_str) - pos, " %d ", bit);

			if (group_size > 0 && i > 0 && i % group_size == 0)
				pos += snprintf(bin_str + pos, sizeof(bin_str) - pos, " ");
		}
		tel_println(ctx, bin_str);
	}
}

static int
mce_reg_write_handle_info(const char *cmd __rte_unused, const char *params,
			  struct rte_tel_data *d)
{
	char *argv[50] = {0}, buf[512];
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	struct mce_tel_ctx ctx;
	u32 reg, v=0,argc;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc != 3) {
		tel_println(&ctx, "Usage: /mce/reg_write,port reg value");
		return 0;
	}
	eth_dev = get_mce_port(atoi(argv[0]));
	if (eth_dev == NULL){
		tel_println(&ctx, "error: port is not MCE (n20) supported");
		return 0;
	}
	hw = MCE_DEV_TO_HW(eth_dev);
	reg = strtoul(argv[1],NULL, 0);
	v = strtoul(argv[2], NULL, 0);
	if(reg >= 0x30000000){
		if (mce_soc_iowrite32(hw, reg, v))
			tel_println(&ctx, "soc 0x%x <- 0x%x failed",reg, v);
		else
			tel_println(&ctx, "soc 0x%x <- 0x%x done",reg, v);
	} else if(reg < (2 * 1024 * 1024)){
		wr32(hw, reg, v);
		tel_println(&ctx, "0x%x <- 0x%x done",reg, v);
	} else {
		tel_println(&ctx, "invalid addr: 0x%x",reg);
	}


	return 0;
}

static int
mce_reg_read_handle_info(const char *cmd __rte_unused, const char *params,
			 struct rte_tel_data *d)
{
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	u32 i,reg, v=0,argc,cnt=1;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf), NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc < 2) {
		tel_println(&ctx, "Usage: /mce/reg_read,port reg [cnt]");
		return 0;
	}
	eth_dev = get_mce_port(atoi(argv[0]));
	if (eth_dev == NULL){
		tel_println(&ctx, "error: port is not MCE (n20) supported");
		return 0;
	}

	hw = MCE_DEV_TO_HW(eth_dev);
	reg = strtoul(argv[1],NULL, 0);
	if (argc == 3)
		cnt = strtoul(argv[2], NULL, 0);
	for(i = 0;i < cnt;i++) {
		if (reg >= 0x30000000) {
			if (mce_soc_ioread32(hw, reg, (int*)&v)) {
				tel_println(&ctx, "soc 0x%x -> failed",reg);
			} else {
				tel_println(&ctx, "soc 0x%x -> 0x%x",reg, v);
				add_register_to_telemetry(&ctx, v, 2, 1, 0);
			}
		} else if( reg < (2 * 1024 * 1024)) {
			v =  rd32(hw, reg);
			tel_println(&ctx, "0x%x -> 0x%x",reg, v);
			add_register_to_telemetry(&ctx, v, 2, 1, 0);
		} else {
			tel_println(&ctx,  "invalid reg: 0x%x", reg);
			break;
		}
		reg += 4;
	}

	return 0;
}

struct mce_debug_reg {
	int8_t name[32];
	uint32_t address;
	uint32_t next_offset;
	bool hex;
};
enum mce_debug_reg_cmd {
	MCE_RXQ_ADDR_HI,
	MCE_RXQ_ADDR_LO,
	MCE_RXQ_LENGTH,
	MCE_RXQ_START,
	MCE_RXQ_EMPTY,
	MCE_RXQ_HEAD,
	MCE_RXQ_TAIL,
	MCE_RXQ_FETCH,
	MCE_RXQ_NOBUF_DROP,
	MCE_RXQ_BUF_LEN,
	MCE_RXQ_NOBUF_TM,
	MCE_RXQ_PRIOV_LV,

	MCE_TXQ_ADDR_HI,
	MCE_TXQ_ADDR_LO,
	MCE_TXQ_LENGTH,
	MCE_TXQ_START,
	MCE_TXQ_EMPTY,
	MCE_TXQ_HEAD,
	MCE_TXQ_TAIL,
	MCE_TXQ_FETCH,
	MCE_TXQ_PRIO_LV,
	MCE_DEBUG_MAX,
};

static const struct mce_debug_reg mce_debug_regs[] = {
	{ "rxq_addr_hi", MCE_DMA_RXQ_BASE_ADDR_HI(0), 0x100, 1},
	{ "rxq_addr_lo", MCE_DMA_RXQ_BASE_ADDR_LO(0), 0x100, 1 },
	{ "rxq_length", MCE_DMA_RXQ_LEN(0), 0x100, 0 },
	{ "rxq_start", MCE_DMA_RXQ_START(0), 0x100, 0 },
	{ "rxq_empty", MCE_DMA_RXQ_READY(0), 0x100, 0 },
	{ "rxq_irq_state", MCE_DMA_INT_STAT(0), 0x100, 0 },
	{ "rxq_head", MCE_DMA_RXQ_HEAD(0), 0x100, 0 },
	{ "rxq_tail", MCE_DMA_RXQ_TAIL(0), 0x100, 0 },
	{ "rxq_fetch", MCE_DMA_RXQ_DESC_FETCH_CTRL(0), 0x100, 1 },
	{ "rxq_nobuf_drop", MCE_DMA_RXQ_NODESC_DROP(0), 0x100, 0 },
	{ "rxq_dma_buf_len", MCE_DMA_RXQ_SCATTER_BD_LEN(0), 0x100, 0 },
	{ "rxq_no_buf_tm", MCE_DMA_RXQ_DROP_TIMEOUT_TH(0), 0x100, 0 },
	{ "rxq_prio_lv", MCE_DMA_RXQ_RX_PRI_LVL(0), 0x100, 0 },

	{ "txq_addr_hi", MCE_DMA_TXQ_BASE_ADDR_HI(0), 0x100, 1},
	{ "txq_addr_lo", MCE_DMA_TXQ_BASE_ADDR_LO(0), 0x100, 1 },
	{ "txq_length", MCE_DMA_TXQ_LEN(0), 0x100, 0 },
	{ "txq_start", MCE_DMA_TXQ_START(0), 0x100, 0 },
	{ "txq_empty", MCE_DMA_TXQ_READY(0), 0x100, 0 },
	{ "txq_head", MCE_DMA_TXQ_HEAD(0), 0x100, 0 },
	{ "txq_tail", MCE_DMA_TXQ_TAIL(0), 0x100, 0 },
	{ "txq_fetch", MCE_DMA_TXQ_DESC_FETCH_CTRL(0), 0x100, 1 },
	{ "txq_prio_lv", MCE_DMA_TXQ_PRI_LVL(0), 0x100, 0 },
};

static int
mce_dump_rxq_info_handle_info(const char *cmd __rte_unused, const char *params,
			      struct rte_tel_data *d)
{
	struct mce_rx_queue *rxq = NULL;
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	uint32_t val = 0, i = 0;
	int argc=0, port = 0, ring = 0;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc != 2) {
		tel_println(&ctx, "Usage: /mce/dump_rxq_info,port queue");
		return 0;
	}
	port = atoi(argv[0]);
	ring = atoi(argv[1]);
	eth_dev = get_mce_port(port);
	if (!eth_dev) {
		tel_println(&ctx, "error: port is not MCE (n20) supported");
		return 0;
	}
	if (ring > eth_dev->data->nb_rx_queues) {
		tel_println(&ctx, "error: ring num is out of range(%d)", eth_dev->data->nb_rx_queues);
		return 0;
	}
	rxq = eth_dev->data->rx_queues[ring];
	hw = MCE_DEV_TO_HW(eth_dev);

	tel_println(&ctx, "port: %d", port);
	tel_println(&ctx, "rx_ring: %d", ring);
	tel_println(&ctx, "rx_tail: %d", rxq->rx_tail);
	tel_println(&ctx, "rx_nb_desc: %d", rxq->attr.nb_desc);
	tel_println(&ctx, "mark_enabled: %d", rxq->mark_enabled);
	for (i = 0; i < MCE_TXQ_ADDR_HI; i++) {
		val = MCE_E_REG_READ(hw, mce_debug_regs[i].address);
		if (mce_debug_regs[i].hex)
			tel_println(&ctx, "%s: 0x%x",(const char *)mce_debug_regs[i].name, val);
		else
			tel_println(&ctx, "%s: %u",(const char *)mce_debug_regs[i].name, val);
	}

	return 0;
}

static int
mce_dump_txq_info_handle_info(const char *cmd __rte_unused, const char *params,
			      struct rte_tel_data *d)
{
	struct mce_tx_queue *txq = NULL;
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	uint32_t val = 0, i = 0;
	int  argc = 0, port = 0, ring = 0;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc != 2) {
		tel_println(&ctx, "Usage: /mce/dump_txq_info,port queue");
		return 0;
	}
	port = atoi(argv[0]);
	ring = atoi(argv[1]);
	eth_dev = get_mce_port(port);
	if (!eth_dev) {
		tel_println(&ctx, "error: port is not MCE (n20) supported");
		return 0;
	}
	if (ring >= eth_dev->data->nb_tx_queues) {
		tel_println(&ctx, "error: ring num is out of range(%d)", eth_dev->data->nb_tx_queues);
		return 0;
	}
	txq = eth_dev->data->tx_queues[ring];
	hw = MCE_DEV_TO_HW(eth_dev);

	tel_println(&ctx, "port: %d", port);
	tel_println(&ctx, "tx_ring: %d", ring);
	tel_println(&ctx, "tx_tail: %d", txq->tx_tail);
	tel_println(&ctx, "tx_free_thresh: %d", txq->attr.nb_desc);
	tel_println(&ctx, "tx_next_rs: %d", txq->tx_next_rs);
	tel_println(&ctx, "tx_next_dd: %d", txq->tx_next_dd);
	tel_println(&ctx, "last_desc_cleaned: %d", txq->last_desc_cleaned);
	tel_println(&ctx, "nb_tx_free: %d", txq->nb_tx_free);
	for (i = MCE_TXQ_ADDR_HI; i < MCE_DEBUG_MAX; i++) {
		val = MCE_E_REG_READ(hw, mce_debug_regs[i].address);
		if (mce_debug_regs[i].hex)
			tel_println(&ctx,  "%s: 0x%x",(const char *)mce_debug_regs[i].name, val, 0);
		else
			tel_println(&ctx, "%s: %u",(const char *)mce_debug_regs[i].name, val);
	}

	return 0;
}

#define MCE_FWVERS_LEN 32
#define RTE_ETHER_ADDR_PRT_FMT     "%02X:%02X:%02X:%02X:%02X:%02X"
static int
mce_nic_info_summary(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	char fw_version[MCE_FWVERS_LEN];
	struct rte_ether_addr mac_addr;
	char name[RTE_ETH_NAME_MAX_LEN];
	struct rte_eth_link link;
	struct mce_tel_ctx ctx;
	struct rte_eth_dev *eth_dev;
	uint16_t ethdev_num = 0;
	int i = 0;

	tel_ctx_init(&ctx,d);

	ethdev_num = rte_eth_dev_count_avail();
	if (ethdev_num == 0)
		return 0;
	tel_println(&ctx, "%-4s %-17s %-12s %-14s %-8s %s", "Port", "MAC Address", "Name", "Firmware", "Status", "Link");
	for (i = 0; i < ethdev_num; i++) {
		eth_dev = &rte_eth_devices[i];
		if (!is_mce_supported(eth_dev))
			continue;
		rte_eth_dev_get_name_by_port(i, name);
		if (rte_eth_link_get_nowait(i, &link) < 0)
			memset(&link, 0, sizeof(link));
		if (rte_eth_macaddr_get(i, &mac_addr) < 0)
			memset(&mac_addr, 0, sizeof(mac_addr));
		if (rte_eth_dev_fw_version_get(i, fw_version, MCE_FWVERS_LEN) < 0)
			rte_strlcpy(fw_version, "unknown", sizeof(fw_version));
		tel_println(&ctx,
			    "%-4d " RTE_ETHER_ADDR_PRT_FMT
			    " %-12s %-14s %-8s %s",
			    i, RTE_ETHER_ADDR_BYTES(&mac_addr), name,
			    fw_version, (link.link_status) ? ("up") : ("down"),
			    rte_eth_link_speed_to_str(link.link_speed));
	}

	return 0;
}

static void str_delete(char*buf, const char*sub_str)
{
    char* pos = buf;
    size_t sub_len = strlen(sub_str);

    if (sub_len == 0) {
		return;
    }

    while ((pos = strstr(buf, sub_str)) != NULL) {
		rte_strlcpy(pos, " ", sub_len);
        buf = pos + sub_len;
    }
}


static void dump_buf_str_clean(char*buf)
{
	str_delete(buf,"\r");
	str_delete(buf,"\t");
	str_delete(buf,"[0m");
	str_delete(buf,"[32m");
}

static int do_dump(struct mce_hw *hw, uint32_t dump_v, struct mce_tel_ctx* ctx)
{
	int argc,err = 0;
	char *argv[50] = { 0 };
	char dump_buf[4096];

	if(!hw || !ctx){
		return -EINVAL;
	}


	if (mce_mbx_set_dump(hw, dump_v)) {
		tel_println(ctx, "set dump: 0x%x failed", dump_v);
		return 0;
	}

	memset(dump_buf, 0, sizeof(dump_buf));
	err = mce_mbx_get_dump(hw, dump_buf, sizeof(dump_buf));
	if (err) {
		tel_println(ctx, "get dump failed");
		return 0;
	}

	{
		char buf[4096];
		int i;
		argc = split_string(dump_buf, argv, buf, sizeof(buf), "\n");
		for (i = 0; i < argc; i++) {
			dump_buf_str_clean(argv[i]);
			tel_println(ctx, argv[i]);
		}
	}

	return 0;
}

static int
mce_dump(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	int argc;
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	char *argv[50] = { 0 }, buf[512];
	struct mce_tel_ctx ctx;
	uint32_t dump_v = 0;

	tel_ctx_init(&ctx, d);

	argc = split_string(params, argv, buf, sizeof(buf), NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc < 2) {
		tel_println(&ctx, "Usage:   /mce/dump,port dump_value|link|version|ncsi|port|sfp-info|sfp-rescan");
		return 0;
	}

	eth_dev = get_mce_port(atoi(argv[0]));
	if (!eth_dev) {
		tel_println(&ctx, "port_id not mce device");
		return 0;
	}

	hw = MCE_DEV_TO_HW(eth_dev);

	if (strcmp(argv[1], "link") == 0) {
		dump_v = 0x010d0000;
	} else if (strcmp(argv[1], "version") == 0) {
		dump_v = 0x01000000;
	} else if (strcmp(argv[1], "ncsi") == 0) {
		dump_v = 0x01410000;
	} else if (strcmp(argv[1], "port") == 0) {
		dump_v = 0x01020000;
	} else if (strcmp(argv[1], "sfp-info") == 0) {
		if (hw->nr_pf == 0) {
			dump_v = 0x01020001;
		} else {
			dump_v = 0x01020002;
		}
	} else if (strcmp(argv[1], "sfp-rescan") == 0) {
		if (hw->nr_pf == 0) {
			dump_v = 0x01020003;
		} else {
			dump_v = 0x01020004;
		}
	} else {
		dump_v = strtoul(argv[1], NULL, 0);
	}

	do_dump(hw, dump_v, &ctx);

	return 0;
}


static int
mce_fw_log_lvl(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	int argc;
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	uint32_t enable = 0, bit,dump_v=0;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc < 3) {
		tel_println(&ctx, "Usage:   /mce/fw_log,port speed");
		return 0;
	}

	eth_dev = get_mce_port(atoi(argv[0]));
	if (eth_dev == NULL) {
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}
	hw = MCE_DEV_TO_HW(eth_dev);

	bit = strtoul(argv[1],NULL, 0);
	enable = strtoul(argv[2],NULL, 0);

	dump_v = (0x07<<24) | (0x00 <<16)  | (bit <<8)| (enable);

	do_dump(hw,dump_v, &ctx);

	return 0;
}

static int
mce_force_speed(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	int argc;
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	uint32_t dump_v = 0;
	unsigned int speed ,i=0,speeds[] = {0,1000,10000,25000,40000,100000,100,10};

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc != 2) {
		tel_println(&ctx, "Usage:   /mce/force_speed,port speed");
		return 0;
	}
	eth_dev = get_mce_port(atoi(argv[0]));
	if (eth_dev == NULL) {
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}
	hw = MCE_DEV_TO_HW(eth_dev);

	speed = strtoul(argv[1],NULL, 0);
	for(i=0;i<sizeof(speeds)/sizeof(speeds[0]);i++){
		if(speeds[i] == speed){
			break;
		}
	}

	dump_v = (0x01<<24) | (0x15 <<16)  | (i <<8)| (1);

	do_dump(hw,dump_v, &ctx);

	return 0;
}

static int
mce_sfp_eeprom_read(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	int argc;
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	uint32_t dump_v = 0;
	int i2c_addr=0xa0,reg=0,cnt=1;

	tel_ctx_init(&ctx,d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc < 3) {
		tel_println(&ctx, "Usage:   /mce/sfp_eeprom,port sfp_i2c_addr reg [cnt]");
		return 0;
	}
	eth_dev = get_mce_port(atoi(argv[0]));
	if (eth_dev == NULL) {
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}
	hw = MCE_DEV_TO_HW(eth_dev);

	i2c_addr = strtoul(argv[1],NULL, 0);
	reg = strtoul(argv[2],NULL, 0);
	if(argc == 4){
		cnt = strtoul(argv[3],NULL, 0);
	}

	dump_v = (0x10<<24) | (i2c_addr <<16)  | (reg <<8)| (cnt -1);

	do_dump(hw,dump_v, &ctx);


	return 0;
}

static int sprint_n20_rx_debug4( struct mce_hw *hw, char *buf, int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	{
		cnt += SNPRINTF("\n== eth_editor_up ==\n");
		cnt += SNPRINTF_REG("rx_edtup_pkt_in", 0x861d0, D_32BIT);
		cnt += SNPRINTF_REG("rx_edtup_pkt_out", 0x861d4, D_32BIT);
		cnt += SNPRINTF_REG("rx_edtup_pkt_drop", 0x861d8, D_32BIT);
		cnt += SNPRINTF_REG("rx_edtup_rm_all_vlan", 0x861dc, D_32BIT);
		cnt += SNPRINTF_REG("rx_edtup_rm_ex1_vlan", 0x861e0, D_32BIT);
		cnt += SNPRINTF_REG("rx_edtup_rm_ex2_vlan", 0x861e4, D_32BIT);
		cnt += SNPRINTF_REG("rx_edtup_rm_ex3_vlan", 0x861e8, D_32BIT);
		cnt += SNPRINTF_REG("rx_swcup_pkt_out", 0x861ec, D_32BIT);
	}

	{
		cnt += SNPRINTF("\n== rx_switch_bus ==\n");
		cnt += SNPRINTF_REG("nic0_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(0));
		cnt += SNPRINTF_REG("nic0_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(9));
		cnt += SNPRINTF_REG("nic0_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(27));
		cnt += SNPRINTF_REG("nic0_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(36));
		cnt += SNPRINTF_REG("nic0_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(18));
		cnt += SNPRINTF_REG("nic0_l2drop", DBG_RX_SWITCH_BUS, FUNC_D32(45));
		cnt += SNPRINTF_REG("nic1_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(1));
		cnt += SNPRINTF_REG("nic1_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(10));
		cnt += SNPRINTF_REG("nic1_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(19));
		cnt += SNPRINTF_REG("nic1_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(28));
		cnt += SNPRINTF_REG("nic1_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(37));
		cnt += SNPRINTF_REG("nic1_l2drop", DBG_RX_SWITCH_BUS, FUNC_D32(46));
		cnt += SNPRINTF_REG("nic2_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(2));
		cnt += SNPRINTF_REG("nic2_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(11));
		cnt += SNPRINTF_REG("nic2_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(20));
		cnt += SNPRINTF_REG("nic2_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(29));
		cnt += SNPRINTF_REG("nic2_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(38));
		cnt += SNPRINTF_REG("nic3_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(3));
		cnt += SNPRINTF_REG("nic3_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(12));
		cnt += SNPRINTF_REG("nic3_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(21));
		cnt += SNPRINTF_REG("nic3_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(30));
		cnt += SNPRINTF_REG("nic3_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(39));
		cnt += SNPRINTF_REG("npu0_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(4));
		cnt += SNPRINTF_REG("npu0_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(13));
		cnt += SNPRINTF_REG("npu0_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(22));
		cnt += SNPRINTF_REG("npu0_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(31));
		cnt += SNPRINTF_REG("npu0_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(40));
		cnt += SNPRINTF_REG("npu1_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(5));
		cnt += SNPRINTF_REG("npu1_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(14));
		cnt += SNPRINTF_REG("npu1_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(23));
		cnt += SNPRINTF_REG("npu1_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(32));
		cnt += SNPRINTF_REG("npu1_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(41));
		cnt += SNPRINTF_REG("npu2_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(6));
		cnt += SNPRINTF_REG("npu2_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(15));
		cnt += SNPRINTF_REG("npu2_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(24));
		cnt += SNPRINTF_REG("npu2_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(33));
		cnt += SNPRINTF_REG("npu2_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(42));
		cnt += SNPRINTF_REG("npu3_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(7));
		cnt += SNPRINTF_REG("npu3_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(16));
		cnt += SNPRINTF_REG("npu3_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(25));
		cnt += SNPRINTF_REG("npu3_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(34));
		cnt += SNPRINTF_REG("npu3_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(43));
		cnt += SNPRINTF_REG("aux_pkt_in", DBG_RX_SWITCH_BUS, FUNC_D32(8));
		cnt += SNPRINTF_REG("aux_pkt_out", DBG_RX_SWITCH_BUS, FUNC_D32(17));
		cnt += SNPRINTF_REG("aux_pkt_drop", DBG_RX_SWITCH_BUS, FUNC_D32(26));
		cnt += SNPRINTF_REG("aut_pkt_in_sop", DBG_RX_SWITCH_BUS, FUNC_D32(35));
		cnt += SNPRINTF_REG("aut_pkt_in_eop", DBG_RX_SWITCH_BUS, FUNC_D32(44));
	}

	return cnt;
}

static int sprint_n20_rx_debug3( struct mce_hw *hw, char *buf, int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	{
		cnt += SNPRINTF_REG("parser IPV6 pkts", 0x86070, D_32BIT);
		cnt += SNPRINTF_REG("parser IPV4 pkts", 0x86074, D_32BIT);
		cnt += SNPRINTF_REG("parser 3-level-VLAN pkts", 0x86078, D_32BIT);
		cnt += SNPRINTF_REG("parser 2-level-vlan pkts", 0x8607c, D_32BIT);
		cnt += SNPRINTF_REG("parser 1-level-vlan pkts", 0x86080, D_32BIT);
		cnt += SNPRINTF_REG("parser SCTP-in-tunnel", 0x86084, D_32BIT);
		cnt += SNPRINTF_REG("parser TCP SYN in-tunnel", 0x86088, D_32BIT);
		cnt += SNPRINTF_REG("parser TCP in-tunnel", 0x8608c, D_32BIT);
		cnt += SNPRINTF_REG("parser UDP in-tunnel", 0x86090, D_32BIT);
		cnt += SNPRINTF_REG("parser ICMPV6 in-tunnel", 0x86094, D_32BIT);
		cnt += SNPRINTF_REG("parser ICMPV4 in-tunnel", 0x86098, D_32BIT);
		cnt += SNPRINTF_REG("parser fragments in-tunnel", 0x8609c, D_32BIT);
	}
	{
		cnt += SNPRINTF_REG("parser ARP in-tunnel", 0x860a0, D_32BIT);
		cnt += SNPRINTF_REG("parser IPV6 ext-hdr in-tunnel", 0x860a4, D_32BIT);
		cnt += SNPRINTF_REG("parser IPV6 in-tunnel", 0x860a8, D_32BIT);
		cnt += SNPRINTF_REG("parser IPV4 in-tunnel", 0x860ac, D_32BIT);
		cnt += SNPRINTF_REG("parser 3-lvl-VLAN in-tunnel", 0x860b0, D_32BIT);
		cnt += SNPRINTF_REG("parser 2-lvl-VLAN in-tunnel", 0x860b4, D_32BIT);
		cnt += SNPRINTF_REG("parser 1-lvl-VLAN in-tunnel", 0x860b8, D_32BIT);
		cnt += SNPRINTF_REG("parser lookup Write SOP", 0x86100, D_32BIT);
		cnt += SNPRINTF_REG("parser loopup Write EOP", 0x86104, D_32BIT);
		cnt += SNPRINTF_REG("parser_engine_pre in SOP", 0x86110, D_32BIT);
		cnt += SNPRINTF_REG("parser_engine_pre in EOP", 0x86118, D_32BIT);
		cnt += SNPRINTF_REG("parser_engine_pre out SOP", 0x86114, D_32BIT);
		cnt += SNPRINTF_REG("parser_engine_pre out EOP", 0x8612c, D_32BIT);
	}

	{
		cnt += SNPRINTF("\n== eth_fc_gat ==\n");
		cnt += SNPRINTF_REG("pfc0_gat_pkt_in", 0x86250, D_32BIT);
		cnt += SNPRINTF_REG("pfc1_gat_pkt_in ", 0x86254, D_32BIT);
		cnt += SNPRINTF_REG("rx drop pkt", 0x86258, D_32BIT);
		cnt += SNPRINTF_REG("tx2rx drop pkt", 0x8625c, D_32BIT);

		cnt += SNPRINTF("\n== eth_flow_ctrl ==\n");
		cnt += SNPRINTF_REG("emac_flow_ctrl_infifo_o_dma", 0x86260, D_32BIT);
		cnt += SNPRINTF_REG("emac_flow_ctrl_ofif_o_dma", 0x86264, D_32BIT);
		cnt += SNPRINTF_REG("emac_flow_ctrl_drop", 0x86268, D_32BIT);
	}

	{
		cnt += SNPRINTF("\n== eth_fwd_attr ==\n");
		cnt += SNPRINTF_REG("attr_rx_ingress_pkt_in", 0x86230, D_32BIT);
		cnt += SNPRINTF_REG("attr_rx_egress_pkt_out", 0x86234, D_32BIT);
		cnt += SNPRINTF_REG("attr_rx_egress_pkt_drop", 0x86238, D_32BIT);
		cnt += SNPRINTF_REG("rx_ingress_bypass", 0x8623c, D_32BIT);
		cnt += SNPRINTF_REG("rx_verb_backup_flow_cnt", 0x86240, D_32BIT);
		cnt += SNPRINTF_REG("rx_verb_backup_pkts", 0x86244, D_32BIT);

		cnt += SNPRINTF("\n== eth_fwd_proc ==\n");
		cnt += SNPRINTF_REG("rx_ingress_pkt_in", 0x861a0, D_32BIT);
		cnt += SNPRINTF_REG("rx_ingress_drop(mac l2_filter_drop)", 0x861a4, D_32BIT);
		cnt += SNPRINTF_REG("rx2bmc_pkt", 0x861a8, D_32BIT);
		cnt += SNPRINTF_REG("rx bmc_busy_drop", 0x861b8, D_32BIT);
		cnt += SNPRINTF_REG("rx2dma_pkt", 0x861ac, D_32BIT);
		cnt += SNPRINTF_REG("rx ups_dma_busy_drop", 0x861bc, D_32BIT);
		cnt += SNPRINTF_REG("rx2swich_pkt", 0x861b0, D_32BIT);
		cnt += SNPRINTF_REG("rx switch_busy_drop ", 0x861c0, D_32BIT);
		cnt += SNPRINTF_REG("rx2rdma_pkt", 0x861b4, D_32BIT);
		cnt += SNPRINTF_REG("rx rdma_busy_drop", 0x861c4, D_32BIT);
	}
	{
		cnt += SNPRINTF("\n== eth_rqa_top ==\n");
		cnt += SNPRINTF_REG("parser SCTP-in-tunnel", 0x86084, D_32BIT);
		cnt += SNPRINTF_REG(
			"rqa redir-flag(Etype:0x1 tcp_syn:0x2 tuple5:0x4,fd:0x8,rss:0x10)", 0x86170, D_32BIT);
		cnt += SNPRINTF_REG("RQA vport plicy_drop", 0x86174, D_32BIT);
		cnt += SNPRINTF_REG("RQA etype plicy_drop", 0x86178, D_32BIT);
		cnt += SNPRINTF_REG("RQA tcp_syn plicy_drop", 0x8617c, D_32BIT);
		cnt += SNPRINTF_REG("RQA tuple5 plicy_drop)", 0x86180, D_32BIT);
		cnt += SNPRINTF_REG("RQA fd  plicy_drop)", 0x86184, D_32BIT);
		cnt += SNPRINTF_REG("RQA rss plicy_drop)", 0x86188, D_32BIT);
		cnt += SNPRINTF_REG("RQA bypass sumary)", 0x8618c, D_32BIT);
		cnt += SNPRINTF_REG("RQA except-pkts)", 0x86190, D_32BIT);
		cnt += SNPRINTF_REG("RQA processing-pkts", 0x86194, D_32BIT);
		cnt += SNPRINTF_REG("RQA vf-filter group-drop", 0x86198, D_32BIT);
		cnt += SNPRINTF_REG("RQA vf-filter vlan drop", 0x8619c, D_32BIT);
	}

	{
		cnt += SNPRINTF("\n== eth_mux ==\n");
		cnt += SNPRINTF_REG("port0_rx_pkt", 0x86200, D_32BIT);
		cnt += SNPRINTF_REG("port1_rx_pkt", 0x86204, D_32BIT);
		cnt += SNPRINTF_REG("total_mux_rx_pkt", 0x8620c, D_32BIT);
	}

	{
		cnt += SNPRINTF("\n== rx_mux_bus ==\n");
		cnt += SNPRINTF_REG("rx-mux-fsm", DEBUG_RXMUX_BUS,
				    FUNC_FIELD(0, "fsm_cs", 2, 0, "%d"),
				    FUNC_FIELD(0, "fsm_ns", 5, 3, "%d"));

		cnt += SNPRINTF_REG("rx_mux_lerr_pkt_num", DEBUG_RXMUX_BUS, FUNC_D32(1));
		cnt += SNPRINTF_REG("rx_mux_drop_pkt_num", DEBUG_RXMUX_BUS, FUNC_D32(2));
		cnt += SNPRINTF_REG("rx_mux_recv_sop_pkts", DEBUG_RXMUX_BUS, FUNC_D32(3));
		cnt += SNPRINTF_REG("rx_mux_recv_eop_pkts", DEBUG_RXMUX_BUS, FUNC_D32(4));
		cnt += SNPRINTF_REG("rx_mux_send_sop_pkts", DEBUG_RXMUX_BUS, FUNC_D32(5));
		cnt += SNPRINTF_REG("rx_mux_send_eop_pkts", DEBUG_RXMUX_BUS, FUNC_D32(6));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num0", DEBUG_RXMUX_BUS, FUNC_D32(7));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num1", DEBUG_RXMUX_BUS, FUNC_D32(8));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num2", DEBUG_RXMUX_BUS, FUNC_D32(9));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num3", DEBUG_RXMUX_BUS, FUNC_D32(10));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num4", DEBUG_RXMUX_BUS, FUNC_D32(11));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num5", DEBUG_RXMUX_BUS, FUNC_D32(12));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num6", DEBUG_RXMUX_BUS, FUNC_D32(13));
		cnt += SNPRINTF_REG("rx_mux_send_pkts_num7", DEBUG_RXMUX_BUS, FUNC_D32(14));
		cnt += SNPRINTF_REG("channel_count_r[0]", DEBUG_RXMUX_BUS, FUNC_D32(15));
		cnt += SNPRINTF_REG("channel_count_r[1]", DEBUG_RXMUX_BUS, FUNC_D32(16));
		cnt += SNPRINTF_REG("channel_count_r[2]", DEBUG_RXMUX_BUS, FUNC_D32(17));
		cnt += SNPRINTF_REG("channel_count_r[3]", DEBUG_RXMUX_BUS, FUNC_D32(18));
		cnt += SNPRINTF_REG("channel_count_r[4]", DEBUG_RXMUX_BUS, FUNC_D32(19));
		cnt += SNPRINTF_REG("channel_count_r[5]", DEBUG_RXMUX_BUS, FUNC_D32(20));
		cnt += SNPRINTF_REG("channel_count_r[6]", DEBUG_RXMUX_BUS, FUNC_D32(21));
		cnt += SNPRINTF_REG("channel_count_r[7]", DEBUG_RXMUX_BUS, FUNC_D32(22));
	}

	return cnt;
}

static int sprint_n20_rx_debug2( struct mce_hw *hw, char *buf,
				int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	{
		cnt += SNPRINTF_REG(
			"emac_rx_fifo_progfull_status", 0x86418,
			D_FIELD("port_rx_info_fifo_progfull", 0, 0),
			D_FIELD("port_rx_fifo_progfull", 1, 1),
			D_FIELD("ovsb_rx_info_fifo_progfull", 2, 2),
			D_FIELD("ovsb_rx_fifo_progfull", 3, 3),
			D_FIELD("fwd_info_fifo_progfull", 4, 4),
			D_FIELD("fwd_data_fifo_progfull", 5, 5),
			D_FIELD("fwd_key_fifo_progfull", 6, 6),
			D_FIELD("ups_info_fifo_progfull", 7, 7),
			D_FIELD("ups_data_fifo_progfull", 8, 8),
			D_FIELD("ups_key_fifo_progfull", 9, 9),
			D_FIELD("attr_info_fifo_progfull", 10, 10),
			D_FIELD("attr_data_fifo_progfull", 11, 11),
			D_FIELD("attr_key_fifo_progfull", 12, 12),
			D_FIELD("rqa_cov_fifo_progfull", 13, 13),
			D_FIELD("swcup0_info_fifo_progfull", 14, 14),
			D_FIELD("swcup0_fifo_progfull", 15, 15),
			D_FIELD("swcup1_info_fifo_progfull", 16, 16),
			D_FIELD("swcup1_fifo_progfull", 17, 17),
			D_FIELD("emac_sw2fc_info_fifo_progfull", 18, 18),
			D_FIELD("emac_sw2fc_fifo_progfull", 19, 19),
			D_FIELD("edtup_info_fifo_progfull", 20, 20),
			D_FIELD("edtup_data_fifo_progfull", 21, 21),
			D_FIELD("pfc0_gat_fifo_progfull", 22, 22),
			D_FIELD("pfc1_gat_fifo_progfull", 23, 23),
			D_FIELD("pfc0_gat_info_fifo_progfull", 24, 24),
			D_FIELD("pfc1_gat_info_fifo_progfull", 25, 25),
			D_FIELD("bmc_gat_info_fifo_progfull", 26, 26),
			D_FIELD("bmc_gat_fifo_progfull", 27, 27),
			D_FIELD("emac_bmc_info_fifo_progfull", 28, 28),
			D_FIELD("emac_bmc_fifo_progfull", 29, 29));
	}
	{
		cnt += SNPRINTF_REG(
			"emac_rx_fifo_full_status", 0x8641c,
			D_FIELD("wr_port_rx_info_fifo_full", 0, 0),
			D_FIELD("wr_port_rx_fifo_full", 1, 1),
			D_FIELD("wr_ovsb_info_fifo_full", 2, 2),
			D_FIELD("wr_ovsb_fifo_full", 3, 3),
			D_FIELD("wr_fwd_info_full", 4, 4),
			D_FIELD("wr_fwd_data_full", 5, 5),
			D_FIELD("wr_fwd_key_full", 6, 6),
			D_FIELD("wr_ups_info_full", 7, 7),
			D_FIELD("wr_ups_data_full", 8, 8),
			D_FIELD("wr_ups_key_full", 9, 9),
			D_FIELD("wr_attr_info_full", 10, 10),
			D_FIELD("wr_attr_data_full", 11, 11),
			D_FIELD("wr_attr_key_full", 12, 12),
			D_FIELD("wr_rqa_cov_fifo_full", 13, 13),
			D_FIELD("wr_swcup0_info_fifo_full", 14, 14),
			D_FIELD("wr_swcup0_data_fifo_full", 15, 15),
			D_FIELD("wr_swcup1_info_fifo_full", 16, 16),
			D_FIELD("wr_swcup1_data_fifo_full", 17, 17),
			D_FIELD("wr_emac_sw2fc_info_fifo_full", 18, 18),
			D_FIELD("wr_emac_sw2fc_fifo_full", 19, 19),
			D_FIELD("wr_edtup_info_fifo_full", 20, 20),
			D_FIELD("wr_edtup_data_fifo_full", 21, 21),
			D_FIELD("wr_pfc0_gat_fifo_full", 22, 22),
			D_FIELD("wr_pfc1_gat_fifo_full", 23, 23),
			D_FIELD("wr_pfc0_gat_info_fifo_full", 24, 24),
			D_FIELD("wr_pfc1_gat_info_fifo_full", 25, 25),
			D_FIELD("wr_bmc_gat_info_fifo_full", 26, 26),
			D_FIELD("wr_bmc_gat_fifo_full", 27, 27),
			D_FIELD("wr_emac_bmc_info_fifo_full", 28, 28),
			D_FIELD("wr_emac_bmc_fifo_full", 29, 29));
	}

	{
		cnt += SNPRINTF("\n== eth_parse_module ==\n");
		cnt += SNPRINTF_REG("parser-SOP", 0x86000, D_32BIT);
		cnt += SNPRINTF_REG("parser-EOP", 0x86004, D_32BIT);
		cnt += SNPRINTF_REG("parser-len-err", 0x86008, D_32BIT);
		cnt += SNPRINTF_REG("parser-tunnel-exception", 0x8600c, D_32BIT);
		cnt += SNPRINTF_REG("parser-vlan-cnt-exception", 0x86010, D_32BIT);
		cnt += SNPRINTF_REG("parser-sctp csum err", 0x86014, D_32BIT);
		cnt += SNPRINTF_REG("parser-TCPorUDP-csum err", 0x86018, D_32BIT);
		cnt += SNPRINTF_REG("parser-IPV4csum err", 0x8601c, D_32BIT);
		cnt += SNPRINTF_REG("parser-pkt-len", 0x86020, D_32BIT);
		cnt += SNPRINTF_REG("parser IPV4 hdr-len-err", 0x86024, D_32BIT);
		cnt += SNPRINTF_REG("parser 802.3 pkts", 0x86028, D_32BIT);
		cnt += SNPRINTF_REG("parser PTP pkts", 0x8602c, D_32BIT);
		cnt += SNPRINTF_REG("parser RDMA pkts", 0x86030, D_32BIT);
	}
	{
		cnt += SNPRINTF_REG("parser GTP-U pkts", 0x86034, D_32BIT);
		cnt += SNPRINTF_REG("parser GTP-C pkts", 0x86038, D_32BIT);
		cnt += SNPRINTF_REG("parser GENEVE pkts", 0x8603c, D_32BIT);
		cnt += SNPRINTF_REG("parser VXLAN pkts", 0x86040, D_32BIT);
		cnt += SNPRINTF_REG("parser GRE pkts", 0x86044, D_32BIT);
		cnt += SNPRINTF_REG("parser ESP pkts", 0x86048, D_32BIT);
		cnt += SNPRINTF_REG("parser SCTP pkts", 0x8604c, D_32BIT);
		cnt += SNPRINTF_REG("parser TCP SYN pkts", 0x86050, D_32BIT);
		cnt += SNPRINTF_REG("parser TCP pkts", 0x86054, D_32BIT);
		cnt += SNPRINTF_REG("parser UDP pkts", 0x86058, D_32BIT);
		cnt += SNPRINTF_REG("parser ICMPV6 pkts", 0x8605c, D_32BIT);
		cnt += SNPRINTF_REG("parser ICMPV4 pkts", 0x86060, D_32BIT);
		cnt += SNPRINTF_REG("parser segment pkts", 0x86064, D_32BIT);
		cnt += SNPRINTF_REG("parser ARP pkts", 0x86068, D_32BIT);
		cnt += SNPRINTF_REG("parser IPV6 with ext-hdr", 0x8606c, D_32BIT);
	}

	return cnt;
}

static int sprint_n20_rx_debug( struct mce_hw *hw, char *buf, int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	{
		cnt += SNPRINTF("\n== rx_trans_bus ==\n");
		cnt += SNPRINTF_REG("rx_trans_ctrl", 0x80470, Hex_32BIT, D_FIELD("rx-disable", 0, 0));
		cnt += SNPRINTF_REG("rxtrans_pkt_drop_num", DEBUG_RXTRANS_BUS, FUNC_D32(0));
		cnt += SNPRINTF_REG("rxtrans_pkt_in", DEBUG_RXTRANS_BUS, FUNC_D32(1));
		cnt += SNPRINTF_REG("rxtrans_pkt_out", DEBUG_RXTRANS_BUS, FUNC_D32(2));
		cnt += SNPRINTF_REG(" rxtrans_other_err", DEBUG_RXTRANS_BUS, FUNC_D32(3));
		cnt += SNPRINTF_REG(" rx_trans_pkt_crc_err", DEBUG_RXTRANS_BUS, FUNC_D32(4));
		cnt += SNPRINTF_REG(" rx_trans_pkt_nosym_err", DEBUG_RXTRANS_BUS, FUNC_D32(5));
		cnt += SNPRINTF_REG(" rx_trans_pkt_undersize_err", DEBUG_RXTRANS_BUS, FUNC_D32(6));
		cnt += SNPRINTF_REG(" rx_trans_pkt_oversize_err", DEBUG_RXTRANS_BUS, FUNC_D32(7));
		cnt += SNPRINTF_REG(" rx_trans_pkt_len_err", DEBUG_RXTRANS_BUS, FUNC_D32(8));
		cnt += SNPRINTF_REG(" rx_trans_pkt_wpi_err", DEBUG_RXTRANS_BUS, FUNC_D32(9));
		cnt += SNPRINTF_REG(" rx_trans_pkt_magic_err", DEBUG_RXTRANS_BUS, FUNC_D32(10));
		cnt += SNPRINTF_REG(" rx_trans_pkt_unmatch_da_err", DEBUG_RXTRANS_BUS, FUNC_D32(11));
		cnt += SNPRINTF_REG(" rx_trans_pkt_slen_err", DEBUG_RXTRANS_BUS, FUNC_D32(12));
		cnt += SNPRINTF_REG(" rx_trans_pkt_glen_err", DEBUG_RXTRANS_BUS, FUNC_D32(13));
		cnt += SNPRINTF_REG("rx_trans_pkt_frag", DEBUG_RXTRANS_BUS, FUNC_D32(14));
		cnt += SNPRINTF_REG(" rx_trans_pkt_len_except", DEBUG_RXTRANS_BUS, FUNC_D32(15));
		cnt += SNPRINTF_REG("rxtrans_pkt_sop", DEBUG_RXTRANS_BUS, FUNC_D32(16));
		cnt += SNPRINTF_REG("rxtrans_pkt_eop", DEBUG_RXTRANS_BUS, FUNC_D32(17));
		cnt += SNPRINTF_REG("rxtrans_sop", DEBUG_RXTRANS_BUS, FUNC_D32(18));
		cnt += SNPRINTF_REG("rxtrans_eop", DEBUG_RXTRANS_BUS, FUNC_D32(19));
		cnt += SNPRINTF_REG("rxtrans_wpi_status", DEBUG_RXTRANS_BUS,
				    FUNC_FIELD(20, "", 31, 0, "0x%x"),
				    FUNC_FIELD(20, "wpi_flag", 1, 1, "%d"),
				    FUNC_FIELD(20, "magic_flag", 0, 0, "%d"));
		cnt += SNPRINTF_REG(" rx_trans_pri0_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(24));
		cnt += SNPRINTF_REG(" rx_trans_pri1_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(25));
		cnt += SNPRINTF_REG(" rx_trans_pri2_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(26));
		cnt += SNPRINTF_REG(" rx_trans_pri3_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(27));
		cnt += SNPRINTF_REG(" rx_trans_pri4_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(28));
		cnt += SNPRINTF_REG(" rx_trans_pri5_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(29));
		cnt += SNPRINTF_REG(" rx_trans_pri6_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(30));
		cnt += SNPRINTF_REG(" rx_trans_pri7_pkt_drop", DEBUG_RXTRANS_BUS, FUNC_D32(31));
	}

	{
		cnt += SNPRINTF_REG(
			"emac_rx_fifo_extend_states", 0x8640c,
			D_FIELD("wr_port_rx_info_fifo_pfull", 7, 0),
			D_FIELD("wr_port_rx_data_fifo_pfull", 15, 8),
			D_FIELD("wr_port_rx_info_fifo_full", 23, 16),
			D_FIELD("wr_port_rx_data_fifo_full", 31, 24));

		cnt += SNPRINTF_REG("emac_rx_fifo_empty_status0", 0x86410,
				    D_FIELD("port_rx_data_fifo_empty_w", 0, 0),
				    D_FIELD("port_rx_info_fifo_empty_w", 1, 1),
				    D_FIELD("port_rx_info_fifo_empty", 2, 2),
				    D_FIELD("port_rx_fifo_empty", 3, 3),
				    D_FIELD("ovsb_rx_info_fifo_empty", 4, 4),
				    D_FIELD("ovsb_rx_fifo_empty", 5, 5),
				    D_FIELD("fwd_info_fifo_empty", 6, 6),
				    D_FIELD("fwd_data_fifo_empty", 7, 7),
				    D_FIELD("fwd_key_fifo_empty", 8, 8),
				    D_FIELD("ups_info_fifo_empty", 9, 9),
				    D_FIELD("ups_data_fifo_empty", 10, 10),
				    D_FIELD("ups_key_fifo_empty", 11, 11),
				    D_FIELD("attr_info_fifo_empty", 12, 12),
				    D_FIELD("attr_data_fifo_empty", 13, 13),
				    D_FIELD("attr_key_fifo_empty", 14, 14),
				    D_FIELD("rqa_cov_fifo_empty", 15, 15),
				    D_FIELD("swcup0_info_fifo_empty", 16, 16),
				    D_FIELD("swcup0_data_fifo_empty", 17, 17));
	}
	{
		cnt += SNPRINTF_REG(
			"emac_rx_fifo_empty_status1", 0x86414,
			D_FIELD("swcpu1_info_fifo_empty", 0, 0),
			D_FIELD("swcpu1_data_fifo_empty", 1, 1),
			D_FIELD("emac_sw2fc_info_fifo_empty", 2, 2),
			D_FIELD("emac_sw2fc_fifo_empty", 3, 3),
			D_FIELD("edtup_info_fifo_empty", 4, 4),
			D_FIELD("edtup_data_fifo_empty", 5, 5),
			D_FIELD("pfc0_gat_info_fifo_empty", 6, 6),
			D_FIELD("pfc0_gat_fifo_empty", 7, 7),
			D_FIELD("pfc1_gat_info_fifo_empty", 8, 8),
			D_FIELD("pfc1_gat_fifo_empty", 9, 9),
			D_FIELD("bmc_gat_info_fifo_empty", 10, 10),
			D_FIELD("bmc_gat_fifo_empty", 11, 11),
			D_FIELD("emac_bmc_info_fifo_empty", 12, 12),
			D_FIELD("emac_bmc_fifo_empty", 13, 13),
			D_FIELD("rd_port_rx_info_fifo_empty", 16, 16),
			D_FIELD("rd_port_rx_fifo_empty", 17, 17),
			D_FIELD("rd_ovsb_rx_info_fifo_empty", 18, 18),
			D_FIELD("rd_ovsb_rx_fifo_empty", 19, 19),
			D_FIELD("rd_fwd_info_fifo_empty", 20, 20),
			D_FIELD("rd_fwd_data_fifo_empty", 21, 21),
			D_FIELD("rd_fwd_key_fifo_empty", 22, 22),
			D_FIELD("rd_ups_info_fifo_empty", 23, 23),
			D_FIELD("rd_ups_data_fifo_empty", 24, 24),
			D_FIELD("rd_ups_key_fifo_empty", 25, 25),
			D_FIELD("rd_attr_info_fifo_empty", 26, 26),
			D_FIELD("rd_attr_data_fifo_empty", 27, 27),
			D_FIELD("rd_attr_key_fifo_empty", 28, 28),
			D_FIELD("rd_arqa_cov_fifo_empty", 29, 29),
			D_FIELD("rd_swcup0_info_fifo_empty", 30, 30),
			D_FIELD("rd_swcup0_data_empty", 31, 31));
	}

	cnt += sprint_n20_rx_debug2( hw, buf + cnt, buf_sz - cnt);
	// cnt += sprint_n20_rx_debug3( hw, buf + cnt, buf_sz - cnt);
	// cnt += sprint_n20_rx_debug4( hw, buf + cnt, buf_sz - cnt);
	return cnt;
}

static int print_n20_rx_mac_regs(struct mce_hw *hw, char* buf, int buf_sz)
{
	int cnt = 0;

	cnt += SNPRINTF("\n----mac-rx---\n");
	cnt += SNPRINTF_REG( "mac-cfg", 0x64000, Hex_32BIT,
		D_FIELD("rx-en", 27, 27),
		D_FIELD("tx-en", 26, 26), D_FIELD("pause-disable", 20, 20),
		D_FIELD("pfc-rx-en", 12, 12), D_FIELD("pfc-tx-en", 11, 11),
		D_FIELD("pause-stop-en", 10, 10), D_FIELD("pause-en", 9, 9),
		D_FIELD("jumbo-en", 6, 6), D_FIELD("truncate-en", 5, 5),
		D_FIELD("mac-loopback", 3, 3));

	cnt += SNPRINTF_REG("RxOct", 0x64000 + 0x180, D_32BIT);
	cnt += SNPRINTF_REG("RxErrs", 0x64000 + 0x184, D_32BIT);
	cnt += SNPRINTF_REG(" oversize", 0x64000 + 0x1c0, D_32BIT);
	cnt += SNPRINTF_REG(" aFrameCheckSeqErrs", 0x64000 + 0x1a0, D_32BIT);
	cnt += SNPRINTF_REG(" aAlignErr", 0x64000 + 0x88, D_32BIT);
	cnt += SNPRINTF_REG(" aTooLongErr", 0x64000 + 0x98, D_32BIT);
	cnt += SNPRINTF_REG(" aInRangLenErr", 0x64000 + 0x9c, D_32BIT);
	cnt += SNPRINTF_REG(" smallDrop", 0x64000 + 0x1fc, D_32BIT);
	cnt += SNPRINTF_REG("jumbers", 0x64000 + 0x1c4, D_32BIT);
	cnt += SNPRINTF_REG("fragments", 0x64000 + 0x1c8, D_32BIT);
	cnt += SNPRINTF_REG("pause rx", 0x64000 + 0x94, D_32BIT);
	cnt += SNPRINTF_REG("vlan ok", 0x64000 + 0xA4, D_32BIT);
	cnt += SNPRINTF_REG("PFC0", 0x64000 + 0xe0 + 4 * 0, D_32BIT);
	cnt += SNPRINTF_REG("PFC1", 0x64000 + 0xe0 + 4 * 1, D_32BIT);
	cnt += SNPRINTF_REG("PFC2", 0x64000 + 0xe0 + 4 * 2, D_32BIT);
	cnt += SNPRINTF_REG("PFC3", 0x64000 + 0xe0 + 4 * 3, D_32BIT);
	cnt += SNPRINTF_REG("PFC4", 0x64000 + 0xe0 + 4 * 4, D_32BIT);
	cnt += SNPRINTF_REG("PFC5", 0x64000 + 0xe0 + 4 * 5, D_32BIT);
	cnt += SNPRINTF_REG("PFC6", 0x64000 + 0xe0 + 4 * 6, D_32BIT);
	cnt += SNPRINTF_REG("RxOk_hi", 0x64000 + 0xAC, D_32BIT);
	cnt += SNPRINTF_REG("RxOk_lo", 0x64000 + 0x84, D_32BIT);
	cnt += SNPRINTF_REG("rxtrans_sop", DEBUG_RXTRANS_BUS, FUNC_D32(18));
	cnt += SNPRINTF_REG("rxtrans_eop", DEBUG_RXTRANS_BUS, FUNC_D32(19));
	cnt += SNPRINTF_REG("rx_ingress_pkt_in", 0x861a0, D_32BIT);
	cnt += SNPRINTF_REG("rx_ingress_drop", 0x861a4, D_32BIT);
	cnt += SNPRINTF_REG("rx2dma_pkt", 0x861ac, D_32BIT);
	cnt += SNPRINTF_REG("rx2dma_busy_drop", 0x861bc, D_32BIT);
	cnt += SNPRINTF_REG("rx2bmc_pkt", 0x861a8, D_32BIT);
	cnt += SNPRINTF_REG("rx2bmc_busy_drop", 0x861b8, D_32BIT);
	cnt += SNPRINTF_REG("rx2swich_pkt", 0x861b0, D_32BIT);
	cnt += SNPRINTF_REG("rx switch_busy_drop ", 0x861c0, D_32BIT);
	cnt += SNPRINTF_REG("rx2rdma_pkt", 0x861b4, D_32BIT);
	cnt += SNPRINTF_REG("rx rdma_busy_drop", 0x861c4, D_32BIT);

	cnt += SNPRINTF_REG("rx_mux_recv_sop_pkts", DEBUG_RXMUX_BUS, FUNC_D32(3));
	cnt += SNPRINTF_REG("rx_mux_recv_eop_pkts", DEBUG_RXMUX_BUS, FUNC_D32(4));

	cnt += SNPRINTF("\n");
	cnt += SNPRINTF("\n==eth tx==\n");
	cnt += SNPRINTF_REG("tx_trans_send_sop", DEBUG_TXTRANS_BUS, FUNC_D32(0));
	cnt += SNPRINTF_REG("tx_trans_send_eop", DEBUG_TXTRANS_BUS, FUNC_D32(1));
	cnt += SNPRINTF_REG("tx_trans_recv_sop", DEBUG_TXTRANS_BUS, FUNC_D32(2));
	cnt += SNPRINTF_REG("tx_trans_recv_eop", DEBUG_TXTRANS_BUS, FUNC_D32(3));

	if (hw->nr_pf == 0) {
		cnt += SNPRINTF_REG("port0 tx sop", 0x86460, FUNC_D32(13));
		cnt += SNPRINTF_REG("port0 tx eop", 0x86464, FUNC_D32(13));
	} else {
		cnt += SNPRINTF_REG("port1 tx sop", 0x86468, FUNC_D32(13));
		cnt += SNPRINTF_REG("port1 tx eop", 0x8646c, FUNC_D32(13));
	}
	cnt += SNPRINTF_REG("TxOk_hi", 0x64000 + 0xA8, D_32BIT);
	cnt += SNPRINTF_REG("TxOk_lo", 0x64000 + 0x80, D_32BIT);
	cnt += SNPRINTF_REG("PauseTx", 0x64000 + 0x90, D_32BIT);
	cnt += SNPRINTF_REG("txErrs", 0x64000 + 0x104, D_32BIT);

	return cnt;
}

static int
mce_rx_counters(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	int argc,cnt = 0;
	char big_buf[RTE_TEL_MAX_SINGLE_STRING_LEN];
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	int idx = 0;

	memset(big_buf,0, sizeof(big_buf));

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	tel_ctx_init(&ctx, d);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help"))) {
		tel_println(&ctx,"Usage: /mce/rx_states,port_id [0,1,2]");
		return 0;
	}
	eth_dev = get_mce_port(atoi(argv[0]));
	if (!eth_dev){
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}
	if (argc >= 2)
		idx = atoi(argv[1]);
	hw = MCE_DEV_TO_HW(eth_dev);
	ctx.hw = hw;
	if (idx == 1) {
		cnt += sprint_n20_rx_debug(hw,  big_buf + cnt, sizeof(big_buf) - cnt);
	} else if (idx == 2) {
		cnt += sprint_n20_rx_debug3(hw, big_buf + cnt, sizeof(big_buf) - cnt);
		cnt += sprint_n20_rx_debug4(hw, big_buf + cnt, sizeof(big_buf) - cnt);
	} else {
		cnt += print_n20_rx_mac_regs(hw,  big_buf + cnt, sizeof(big_buf) - cnt);
	}

	rte_tel_data_string(ctx.d, big_buf);

	return 0;
}

static int sprint_n20_tx_debug2(struct mce_hw *hw, char *buf, int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	{
		cnt += SNPRINTF_REG(
			"tx_fifo_empty_statuse", 0x86400,
			D_FIELD("port_txmux_info_fifo_empty", 7, 0),
			D_FIELD("port_txmux_data_fifo_empty", 15, 8),
			D_FIELD("emac_sw2bmc_info_fifo_empty", 16, 16),
			D_FIELD("emac_sw2bmc_fifo_empty", 17, 17),
			D_FIELD("emac_swc_info_fifo_empty", 20, 20),
			D_FIELD("emac_swc_fifo_empty", 21, 21),
			D_FIELD("emac_port_info_fifo_empty", 22, 22),
			D_FIELD("emac_port_fifo_empty", 23, 23),
			D_FIELD("emac_bmc_info_fifo_empty", 24, 24),
			D_FIELD("emac_bmc_fifo_empty", 25, 25),
			D_FIELD("emac_rdma_info_fifo_empty", 26, 26),
			D_FIELD("emac_rdma_fifo_empty", 27, 27),
			D_FIELD("emac_host_info_fifo_empty", 28, 28),
			D_FIELD("emac_host_fifo_empty", 29, 29));
	}
	{
		cnt += SNPRINTF_REG(
			"debug_tx_fifo_progfull_status", 0x86404,
			D_FIELD("port_txmux_info_fifo_progfull", 7, 0),
			D_FIELD("port_txmux_data_fifo_progfull", 15, 8),
			D_FIELD("emac_sw2bmc_info_fifo_progfull", 16, 16),
			D_FIELD("emac_sw2bmc_fifo_progfull", 17, 17),
			D_FIELD("emac_sw2dma_info_fifo_progfull", 18, 18),
			D_FIELD("emac_sw2dma_fifo_progfull", 19, 19),
			D_FIELD("emac_swc_tx1_info_fifo_progfull", 20, 20),
			D_FIELD("emac_swc_tx1_fifo_progfull_tmp", 21, 21),
			D_FIELD("emac_swc_tx0_info_fifo_progfull", 22, 22),
			D_FIELD("emac_swc_tx0_fifo_progfull", 23, 23),
			D_FIELD("emac_bmc_info_fifo_progfull", 24, 24),
			D_FIELD("emac_bmc_fifo_progfull", 25, 25),
			D_FIELD("emac_rdma_info_fifo_progfull", 26, 26),
			D_FIELD("emac_rdma_fifo_progfull", 27, 27),
			D_FIELD("emac_fd_fifo_progfull", 28, 28),
			D_FIELD("emac_tso_key_fifo_afull", 29, 29),
			D_FIELD("emac_tso_fifo_afull", 30, 30),
			D_FIELD("emac_host_fifo_afull", 31, 31));
	}
	{
		cnt += SNPRINTF_REG(
			"debug_tx_fifo_full_status", 0x86408,
			D_FIELD("port_txmux_info_fifo_full", 7, 0),
			D_FIELD("port_txmux_data_fifo_full", 15, 8),
			D_FIELD("emac_sw2bmc_info_fifo_full", 16, 16),
			D_FIELD("emac_sw2bmc_fifo_full", 17, 17),
			D_FIELD("emac_sw2dma_info_fifo_full", 18, 18),
			D_FIELD("emac_sw2dma_fifo_full", 19, 19),
			D_FIELD("emac_swc_tx1_info_fifo_full", 20, 20),
			D_FIELD("emac_swc_tx1_fifo_full_tmp", 21, 21),
			D_FIELD("emac_swc_tx0_info_fifo_full", 22, 22),
			D_FIELD("emac_swc_tx0_fifo_full", 23, 23),
			D_FIELD("emac_bmc_info_fifo_full", 24, 24),
			D_FIELD("emac_bmc_fifo_full", 25, 25),
			D_FIELD("emac_rdma_info_fifo_full", 26, 26),
			D_FIELD("emac_rdma_fifo_full", 27, 27),
			D_FIELD("emac_fd_fifo_full", 28, 28),
			D_FIELD("emac_tso_key_fifo_full", 29, 29),
			D_FIELD("emac_tso_fifo_full", 30, 30),
			D_FIELD("emac_host_fifo_full", 31, 31));
	}
	{
		cnt += SNPRINTF_REG("debug_tx_tso", 0x86508,
				    D_FIELD("frame_segment_dfifo_full", 0, 0),
				    D_FIELD("frame_segment_dfifo_afull", 1, 1),
				    D_FIELD("frame_segment_ififo_afull", 2, 2),
				    D_FIELD("pkt_fd_data_ofifo_progfull", 3, 3),
				    D_FIELD("pkt_data_ofifo_afull", 4, 4),
				    D_FIELD("pkt_key_ofifo_afull", 5, 5));
	}
	{
		cnt += SNPRINTF_REG("tso_gather_debug_0", 0x86500, FUNC_D32(0));
		cnt += SNPRINTF_REG("tso_gather_debug_1", 0x86504, FUNC_D32(0));
		cnt += SNPRINTF_REG("tso_segment_pre_0", 0x86500, FUNC_D32(1));
		cnt += SNPRINTF_REG("tso_segment_pre_1", 0x86504, FUNC_D32(1));
		cnt += SNPRINTF_REG("tso_segment_ctrl_0", 0x86500, FUNC_D32(2));
		cnt += SNPRINTF_REG("tso_segment_ctrl_1", 0x86504, FUNC_D32(2));
		cnt += SNPRINTF_REG("tso_checksum_p0", 0x86500, FUNC_D32(3));
		cnt += SNPRINTF_REG("tso_checksum_p1", 0x86504, FUNC_D32(3));
		cnt += SNPRINTF_REG("tso_modify_p0", 0x86500, FUNC_D32(4));
		cnt += SNPRINTF_REG("tso_modify_p1", 0x86504, FUNC_D32(4));
		cnt += SNPRINTF_REG("tso_debug", 0x86508,
				    FUNC_FIELD(4, "cmd_l3_ver", 1, 0, "%d"),
				    FUNC_FIELD(4, "cmd_l4_type", 7, 4, "%d"),
				    FUNC_FIELD(4, "cmd_out_l3_ver", 9, 8, "%d"),
				    FUNC_FIELD(4, "cmd_out_l4_type", 15, 12,"%d"),
				    FUNC_FIELD(4, "tunnel_type", 19, 16, "%d"));

		cnt += SNPRINTF_REG("tso_debug", 0x86508,
				    FUNC_FIELD(5, "ip_len/in_ip_len", 8, 0, "%d"),
				    FUNC_FIELD(5, "cmd_l4_len", 15, 9, "%d"),
				    FUNC_FIELD(5, "out_ip_len", 24, 16, "%d"),
				    FUNC_FIELD(5, "out_mac_len", 31, 25, "%d"));

		cnt += SNPRINTF_REG("tso_debug", 0x86508,
				    FUNC_FIELD(6, "mdy_tunnel_len", 7, 0, "%d"),
				    FUNC_FIELD(6, "cmd_l4_len", 15, 8, "%d"),
				    FUNC_FIELD(6, "mss", 31, 16, "%d"));
	}

	return cnt;
}

static int sprint_n20_tx_mac( struct mce_hw *hw, char *buf, int buf_sz)
{
	int cnt = 0;
	if (buf_sz <= 0)
		return 0;

	cnt += SNPRINTF("\n==eth tx==\n");
	if (hw->nr_pf == 0) {
		cnt += SNPRINTF_REG("port0 tx sop", 0x86460, FUNC_D32(13));
		cnt += SNPRINTF_REG("port0 tx eop", 0x86464, FUNC_D32(13));
	} else {
		cnt += SNPRINTF_REG("port1 tx sop", 0x86468, FUNC_D32(13));
		cnt += SNPRINTF_REG("port1 tx eop", 0x8646c, FUNC_D32(13));
	}

	cnt += SNPRINTF("\n==mac-tx==\n");
	cnt += SNPRINTF_REG(
		"mac-cfg", 0x64000, Hex_32BIT, D_FIELD("rx-en", 27, 27),
		D_FIELD("tx-en", 26, 26), D_FIELD("pause-disable", 20, 20),
		D_FIELD("pfc-rx-en", 12, 12), D_FIELD("pfc-tx-en", 11, 11),
		D_FIELD("pause-stop-en", 10, 10), D_FIELD("pause-en", 9, 9),
		D_FIELD("jumbo-en", 6, 6), D_FIELD("truncate-en", 5, 5),
		D_FIELD("mac-loopback", 3, 3));

	cnt += SNPRINTF_REG("txOct", 0x64000 + 0x100, D_32BIT);
	cnt += SNPRINTF_REG("txErrs", 0x64000 + 0x104, D_32BIT);
	cnt += SNPRINTF_REG("PauseTx", 0x64000 + 0x90, D_32BIT);
	cnt += SNPRINTF_REG("vlanOk", 0x64000 + 0xA0, D_32BIT);
	cnt += SNPRINTF_REG("PFC0", 0x64000 + 0xC0 + 4 * 0, D_32BIT);
	cnt += SNPRINTF_REG("PFC1", 0x64000 + 0xC0 + 4 * 1, D_32BIT);
	cnt += SNPRINTF_REG("PFC2", 0x64000 + 0xC0 + 4 * 2, D_32BIT);
	cnt += SNPRINTF_REG("PFC3", 0x64000 + 0xC0 + 4 * 3, D_32BIT);
	cnt += SNPRINTF_REG("PFC4", 0x64000 + 0xC0 + 4 * 4, D_32BIT);
	cnt += SNPRINTF_REG("PFC5", 0x64000 + 0xC0 + 4 * 5, D_32BIT);
	cnt += SNPRINTF_REG("PFC6", 0x64000 + 0xC0 + 4 * 6, D_32BIT);

	cnt += SNPRINTF_REG("TxOk_hi", 0x64000 + 0xA8, D_32BIT);
	cnt += SNPRINTF_REG("TxOk_lo", 0x64000 + 0x80, D_32BIT);

	cnt += SNPRINTF("\n");
	cnt += SNPRINTF_REG("RxOk_lo", 0x64000 + 0x84, D_32BIT);
	cnt += SNPRINTF_REG("RxErrs", 0x64000 + 0x184, D_32BIT);
	cnt += SNPRINTF_REG("RxOk_hi", 0x64000 + 0xAC, D_32BIT);

	return cnt;
}

static int sprint_n20_tx_debug(struct mce_hw *hw, char *buf, int buf_sz)
{
	int cnt = 0;

	if (buf_sz <= 0)
		return 0;

	{
		cnt += SNPRINTF_REG("dma_axi_state_p0", 0x86488,
				    D_FIELD("cesoc_tx_timestamp_val", 0, 0),
				    D_FIELD("emac_rxfifo_full", 1, 1),
				    D_FIELD("emac_txfifo_full", 2, 2),
				    D_FIELD("emac_rxfifo_empty", 3, 3),
				    D_FIELD("emac_txfifo_empty", 4, 4),
				    D_FIELD("emac_txfifo_ecc", 5, 5),
				    D_FIELD("emac_rxfifo_ecc", 6, 6),
				    D_FIELD("cesoc_tx_rdy", 7, 7),
				    D_FIELD("tx_timestamp_wptr", 11, 8),
				    D_FIELD("tx_timestamp_rptr", 15, 12));
	}
	{
		cnt += SNPRINTF_REG("tx_trans_ctrl", 0x80474, Hex_32BIT, D_FIELD("tx-disable", 0, 0));
		cnt += SNPRINTF_REG("tx_trans_send_sop", DEBUG_TXTRANS_BUS, FUNC_D32(0));
		cnt += SNPRINTF_REG("tx_trans_send_eop", DEBUG_TXTRANS_BUS, FUNC_D32(1));
		cnt += SNPRINTF_REG("tx_trans_recv_sop", DEBUG_TXTRANS_BUS, FUNC_D32(2));
		cnt += SNPRINTF_REG("tx_trans_recv_eop", DEBUG_TXTRANS_BUS, FUNC_D32(3));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num0", DEBUG_TXTRANS_BUS, FUNC_D32(4));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num1", DEBUG_TXTRANS_BUS, FUNC_D32(5));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num2", DEBUG_TXTRANS_BUS, FUNC_D32(6));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num3", DEBUG_TXTRANS_BUS, FUNC_D32(7));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num4", DEBUG_TXTRANS_BUS, FUNC_D32(8));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num5", DEBUG_TXTRANS_BUS, FUNC_D32(9));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num6", DEBUG_TXTRANS_BUS, FUNC_D32(10));
		cnt += SNPRINTF_REG("tx_trans_send_pkt_num7", DEBUG_TXTRANS_BUS, FUNC_D32(11));
		cnt += SNPRINTF_REG("tx_trans_port_tx_status_reg_num", DEBUG_TXTRANS_BUS, FUNC_D32(12));
		cnt += SNPRINTF_REG("tx_trans_port_tx_timestamp_hreg",
				    DEBUG_TXTRANS_BUS, FUNC_D32(13));
		cnt += SNPRINTF_REG("tx_trans_port_tx_timestamp_lreg", DEBUG_TXTRANS_BUS, FUNC_D32(14));
		cnt += SNPRINTF_REG("tx_trans_port_tx_timestamp_val", DEBUG_TXTRANS_BUS, FUNC_D32(15));
		cnt += SNPRINTF_REG("tx_trans_fsm_ns fsm_cs", DEBUG_TXTRANS_BUS, FUNC_D32(16));
		cnt += SNPRINTF_REG("tx_trans_len_mon", DEBUG_TXTRANS_BUS,
				    FUNC_FIELD(17, "", 31, 0, "0x%x"),
				    FUNC_FIELD(17, "len-getted", 15, 0, "%u"),
				    FUNC_FIELD(17, "cal-len", 30, 16, "%u"),
				    FUNC_FIELD(17, "len-no-match", 31, 31, "%u"));
		cnt += SNPRINTF_REG("tx_trans_lerr_pkt_num", DEBUG_TXTRANS_BUS, FUNC_D32(18));
		cnt += SNPRINTF_REG("tx_trans_pkt_len_max", DEBUG_TXTRANS_BUS, FUNC_D32(19));
		cnt += SNPRINTF_REG("tx_trans_fsm_cnt_max", DEBUG_TXTRANS_BUS, FUNC_D32(20));
		cnt += SNPRINTF_REG("tx_trans_len_is_zero", DEBUG_TXTRANS_BUS, FUNC_D32(21));
		cnt += SNPRINTF_REG("pause xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(23));
		cnt += SNPRINTF_REG("pfc-pri0 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(24));
		cnt += SNPRINTF_REG("pfc-pri1 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(25));
		cnt += SNPRINTF_REG("pfc-pri2 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(26));
		cnt += SNPRINTF_REG("pfc-pri3 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(27));
		cnt += SNPRINTF_REG("pfc-pri4 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(28));
		cnt += SNPRINTF_REG("pfc-pri5 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(29));
		cnt += SNPRINTF_REG("pfc-pri6 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(30));
		cnt += SNPRINTF_REG("pfc-pri7 xon2xoff", DEBUG_TXTRANS_BUS, FUNC_D32(31));
	}
	{
		cnt += SNPRINTF_REG("debug_input_pkt_count", 0x86500, D_32BIT);
		cnt += SNPRINTF_REG("debug_output_pkt_count", 0x86504, D_32BIT);
		cnt += SNPRINTF_REG("debug_state_status", 0x86508, D_32BIT);
		cnt += SNPRINTF_REG("debug_fifo_status", 0x8650c, D_32BIT);
		cnt += SNPRINTF_REG("post:to txtrans", 0x86510, D_32BIT);
		cnt += SNPRINTF_REG("post:to down_uplink", 0x86514, D_32BIT);
		cnt += SNPRINTF_REG("post:to SWC_bridge", 0x86518, D_32BIT);
		cnt += SNPRINTF_REG("post:from host/tso", 0x8651c, D_32BIT);
		cnt += SNPRINTF_REG("post:from bmc", 0x86520, D_32BIT);
		cnt += SNPRINTF_REG("post:from rdma", 0x86524, D_32BIT);
		cnt += SNPRINTF_REG("post:from switch", 0x86528, D_32BIT);
		cnt += SNPRINTF_REG("post:drop from host/tso", 0x86530, D_32BIT);
		cnt += SNPRINTF_REG("post:drop from bmc", 0x86534, D_32BIT);
		cnt += SNPRINTF_REG("post:drop from rdma", 0x86538, D_32BIT);
		cnt += SNPRINTF_REG("post:drop from switch", 0x8653c, D_32BIT);
	}
	{
		cnt += SNPRINTF_REG("tx_post_bus", DEBUG_TXTRANS_BUS, FUNC_D32(0));
		cnt += SNPRINTF_REG("port0_antispoof_drop", 0x86460, FUNC_D32(1));
		cnt += SNPRINTF_REG("port2_antispoof_drop", 0x86464, FUNC_D32(1));
		cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x86460, FUNC_D32(5));
		cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x86464, FUNC_D32(5));
		cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x86468, FUNC_D32(5));
		cnt += SNPRINTF_REG("port_0_cmd_dim_p0", 0x8646c, FUNC_D32(5));

		cnt += SNPRINTF_REG("pkt0_drop_nosop_num", 0x86460, FUNC_D32(9));
		cnt += SNPRINTF_REG("pkt1_drop_nosop_num", 0x86464, FUNC_D32(9));
		cnt += SNPRINTF_REG("pkt2_drop_nosop_num", 0x86468, FUNC_D32(9));
		cnt += SNPRINTF_REG("pkt3_drop_nosop_num", 0x8646c, FUNC_D32(9));

		cnt += SNPRINTF_REG(
			"host_len_com_result_counter", 0x86460,
			FUNC_FIELD(10, "host_cmd_count_lock", 15, 0, "%u"),
			FUNC_FIELD(10, "host_rden_count_lock", 31, 16, "%u"));
		cnt += SNPRINTF_REG("tx_post_debug_10_p0", 0x86464, FUNC_D32(10));
		cnt += SNPRINTF_REG(
			"host2_len_com_result_counter", 0x86468,
			FUNC_FIELD(10, "host_cmd_count_lock", 15, 0, "%u"),
			FUNC_FIELD(10, "host_rden_count_lock", 31, 16, "%u"));
		cnt += SNPRINTF_REG("tx_post_debug_10_p1", 0x8646c, FUNC_D32(10));
		cnt += SNPRINTF_REG("pkt0_sop_num", 0x86460, FUNC_D32(11));
		cnt += SNPRINTF_REG("pkt0_eop_num", 0x86464, FUNC_D32(11));
		cnt += SNPRINTF_REG("pkt1_sop_num", 0x86468, FUNC_D32(11));
		cnt += SNPRINTF_REG("pkt1_eop_num", 0x8646c, FUNC_D32(11));
		cnt += SNPRINTF_REG("pkt2_sop_num", 0x86460, FUNC_D32(12));
		cnt += SNPRINTF_REG("pkt2_eop_num", 0x86464, FUNC_D32(12));
		cnt += SNPRINTF_REG("pkt3_sop_num", 0x86468, FUNC_D32(12));
		cnt += SNPRINTF_REG("pkt3_eop_num", 0x8646c, FUNC_D32(12));
		cnt += SNPRINTF_REG("port0_sop_num", 0x86460, FUNC_D32(13));
		cnt += SNPRINTF_REG("port0_eop_num", 0x86464, FUNC_D32(13));
		cnt += SNPRINTF_REG("port1_sop_num", 0x86468, FUNC_D32(13));
		cnt += SNPRINTF_REG("port1_eop_num", 0x8646c, FUNC_D32(13));
		cnt += SNPRINTF_REG("port2_sop_num", 0x86460, FUNC_D32(14));
		cnt += SNPRINTF_REG("port2_eop_num", 0x86464, FUNC_D32(14));
	}

	cnt += sprint_n20_tx_debug2(hw, buf + cnt, buf_sz - cnt);
	cnt += sprint_n20_tx_mac( hw, buf + cnt, buf_sz - cnt);
	return cnt;
}

static int do_sprint_tx_states_registers(struct mce_hw *hw, char *buf, int buf_sz)
{
	int cnt = 0;

	if (buf == NULL || buf_sz == 0)
		return 0;
	cnt += sprint_n20_tx_debug(hw, buf + cnt, buf_sz - cnt);
	return cnt;
}

static int
mce_ncsi_regs(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	int cnt = 0;
	char buf[RTE_TEL_MAX_SINGLE_STRING_LEN];
	struct mce_tel_ctx ctx;
	int buf_sz = sizeof(buf);

	if(params == NULL){
		tel_println(&ctx,"Usage: /mce/ncsi_regs,port_id");
		return 0;
	}

	memset(buf,0, sizeof(buf));
	tel_ctx_init(&ctx,d);

	eth_dev = get_mce_port(atoi(params));
	if (!eth_dev){
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}

	hw = MCE_DEV_TO_HW(eth_dev);
	ctx.hw = hw;

	cnt += SNPRINTF("\n----mac-rx---\n");
	cnt += SNPRINTF_REG("mac-cfg", 0x64000, Hex_32BIT, D_FIELD("rx-en", 27, 27), D_FIELD("tx-en", 26, 26),
				    D_FIELD("pause-disable", 20, 20), D_FIELD("pfc-rx-en", 12, 12), D_FIELD("pfc-tx-en", 11, 11),
				    D_FIELD("pause-stop-en", 10, 10), D_FIELD("pause-en", 9, 9), D_FIELD("jumbo-en", 6, 6),
				    D_FIELD("truncate-en", 5, 5), D_FIELD("mac-loopback", 3, 3));
	cnt += SNPRINTF_REG("RxOk_lo", 0x64000 + 0x84, D_32BIT);
	cnt += SNPRINTF_REG("RxErrs", 0x64000 + 0x184, D_32BIT);

	cnt += SNPRINTF("\n== rx_trans_bus ==\n");
	cnt += SNPRINTF_REG("rxtrans_pkt_in", DEBUG_RXTRANS_BUS, FUNC_D32(1));
	cnt += SNPRINTF_REG("rxtrans_pkt_drop_num", DEBUG_RXTRANS_BUS, FUNC_D32(0));
	cnt += SNPRINTF_REG("rxtrans_pkt_out", DEBUG_RXTRANS_BUS, FUNC_D32(2));
	cnt += SNPRINTF_REG("!! rxtrans_ctrl !!", 0x80470, Hex_32BIT, D_FIELD("disable eth rx", 0, 0));

	cnt += SNPRINTF("\n== eth_mux ==\n");
	cnt += SNPRINTF_REG("rx in pkts", DEBUG_RXTRANS_BUS, FUNC_D32(1));


	cnt += SNPRINTF("\n== rx host_l2_filter ==\n");
	cnt += SNPRINTF_REG("l2_filter(l2-ctrl0)", 0x88010, Hex_32BIT,
			D_FIELD("l2_filter_en", 31, 31),
			D_FIELD("dmac_filter_en", 30, 30),
			D_FIELD("mng_filter_en", 25, 25),
			D_FIELD("brdcast_bypass", 20, 20));
	cnt += SNPRINTF_REG("fwd_ctrl_reg", 0x8801c, Hex_32BIT, D_FIELD("drop-en", 2, 2));
	cnt += SNPRINTF_REG("dmac_filter_drop", 0x94920, D_32BIT);
	cnt += SNPRINTF_REG("vlan_filter_drop", 0x94924, D_32BIT);
	cnt += SNPRINTF_REG("smac_antispoof_drop", 0x94934, D_32BIT);
	cnt += SNPRINTF_REG("dmac_antispoof_drop", 0x94938, D_32BIT);
	cnt += SNPRINTF_REG("vlan_antispoof_drop", 0x9493c, D_32BIT);

	cnt += SNPRINTF("\n== eth_fwd_proc ==\n");
	cnt += SNPRINTF_REG("rx_ingress_pkt_in", 0x861a0, D_32BIT);
	cnt += SNPRINTF_REG("rx_ingress_drop(mac l2_filter_drop)", 0x861a4, D_32BIT);
	cnt += SNPRINTF_REG("!! to_bmc_pkt!!", 0x861a8, D_32BIT);
	cnt += SNPRINTF_REG("rx bmc_busy_drop", 0x861b8, D_32BIT);
	cnt += SNPRINTF_REG("!! to_dma_pkt !!", 0x861ac, D_32BIT);
	cnt += SNPRINTF_REG("rx ups_dma_busy_drop", 0x861bc, D_32BIT);
	cnt += SNPRINTF_REG("rx2swich_pkt", 0x861b0, D_32BIT);
	cnt += SNPRINTF_REG("rx switch_busy_drop ", 0x861c0, D_32BIT);
	cnt += SNPRINTF_REG("rx2rdma_pkt", 0x861b4, D_32BIT);
	cnt += SNPRINTF_REG("rx rdma_busy_drop", 0x861c4, D_32BIT);
	cnt += SNPRINTF_REG("!! fwd_ctrl_reg !!", 0x8801c, Hex_32BIT,D_FIELD("congest_drop_en", 2, 2));

	cnt += SNPRINTF("\n== eth_rqa_top ==\n");
	cnt += SNPRINTF_REG("parser SCTP-in-tunnel", 0x86084, D_32BIT);
	cnt += SNPRINTF_REG("rqa redir-flag(Etype:0x1 tcp_syn:0x2 tuple5:0x4,fd:0x8,rss:0x10)", 0x86170, D_32BIT);
	cnt += SNPRINTF_REG("RQA vport plicy_drop", 0x86174, D_32BIT);
	cnt += SNPRINTF_REG("RQA etype plicy_drop", 0x86178, D_32BIT);
	cnt += SNPRINTF_REG("RQA tcp_syn plicy_drop", 0x8617c, D_32BIT);
	cnt += SNPRINTF_REG("RQA tuple5 plicy_drop)", 0x86180, D_32BIT);
	cnt += SNPRINTF_REG("RQA fd  plicy_drop)", 0x86184, D_32BIT);
	cnt += SNPRINTF_REG("RQA rss plicy_drop)", 0x86188, D_32BIT);
	cnt += SNPRINTF_REG("RQA bypass sumary)", 0x8618c, D_32BIT);
	cnt += SNPRINTF_REG("RQA except-pkts)", 0x86190, D_32BIT);
	cnt += SNPRINTF_REG("RQA processing-pkts", 0x86194, D_32BIT);
	cnt += SNPRINTF_REG("RQA vf-filter group-drop", 0x86198, D_32BIT);
	cnt += SNPRINTF_REG("RQA vf-filter vlan drop", 0x8619c, D_32BIT);

	cnt += SNPRINTF_REG("rx_edtup_pkt_drop", 0x861d8, D_32BIT);

	cnt += SNPRINTF("\n== eth_fc_gat ==\n");
	cnt += SNPRINTF_REG("pfc0_gat_pkt_in", 0x86250, D_32BIT);
	cnt += SNPRINTF_REG("pfc1_gat_pkt_in ", 0x86254, D_32BIT);
	cnt += SNPRINTF_REG("rx drop pkt(len err)", 0x86258, D_32BIT);
	cnt += SNPRINTF_REG("tx2rx drop pkt(len err)", 0x8625c, D_32BIT);

	cnt += SNPRINTF("\n== eth_bmc_gat ==\n");
	cnt += SNPRINTF_REG("bmc_gat0_pkt", 0x86470, D_32BIT);
	cnt += SNPRINTF_REG("bmc_gat1_pkt", 0x86474, D_32BIT);
	cnt += SNPRINTF_REG("bmc_drop(len err)", 0x86478, D_32BIT);

	cnt += SNPRINTF("\n===== tx ====\n");

	cnt += SNPRINTF_REG("!! txtrans_ctrl !!", 0x80474, Hex_32BIT, D_FIELD("disable eth tx", 0, 0));

	cnt += SNPRINTF("\n== mac tx ==\n");
	cnt += SNPRINTF_REG("TxOk_lo", 0x64000 + 0x80, D_32BIT);


	rte_tel_data_string(ctx.d, buf);

	return 0;
}


static int
mce_tx_counters(const char *cmd __rte_unused, const char *params __rte_unused,
		     struct rte_tel_data *d)
{
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	int cnt = 0;
	char big_buf[RTE_TEL_MAX_SINGLE_STRING_LEN];
	struct mce_tel_ctx ctx;

	if(params == NULL){
		tel_println(&ctx,"Usage: /mce/tx_states,port_id");
		return 0;
	}

	memset(big_buf,0, sizeof(big_buf));
	tel_ctx_init(&ctx,d);

	eth_dev = get_mce_port(atoi(params));
	if (!eth_dev){
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}

	hw = MCE_DEV_TO_HW(eth_dev);
	ctx.hw = hw;

	cnt += do_sprint_tx_states_registers(hw,  big_buf + cnt, sizeof(big_buf) - cnt);

	rte_tel_data_string(ctx.d, big_buf);

	return 0;
}

static int
mce_loglvl(const char *cmd __rte_unused, const char *params __rte_unused,
	   struct rte_tel_data *d)
{
	char *argv[50] = {0}, buf[512];
	struct mce_tel_ctx ctx;
	uint32_t enable = 0, bit=0;
	int argc;

	tel_ctx_init(&ctx, d);

	argc = split_string(params, argv, buf, sizeof(buf),NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help")) || argc != 2) {
		tel_println(&ctx, "Usage:   /mce/loglvl,bit enable");
		return 0;
	}

	if (argc == 2) {
		bit = strtoul(argv[0], NULL, 0);
		enable = strtoul(argv[1], NULL, 0);
		if (enable)
			mce_loglevel |= 1<<bit;
		else
			mce_loglevel &= ~(1<<bit);
	} else {
		mce_loglevel = strtoul(argv[0], NULL, 0);
	}

	tel_println(&ctx, "loglevel:0x%x", mce_loglevel);

	return 0;
}

static int mce_file_exists(const char *filename) {
	return access(filename, F_OK) == 0;
}
static char *mce_find_firmware_path(const char *firmware_name) {
	static char full_path[1024];
	const char *search_paths[] = {
		"/lib/firmware/",
		"/usr/lib/firmware/",
		"",
		NULL
	};
	int i = 0;

	for (i = 0; search_paths[i] != NULL; i++) {
		snprintf(full_path, sizeof(full_path), "%s%s",
				search_paths[i], firmware_name);
		if (mce_file_exists(full_path)) {
			return full_path;
		}
	}

	return NULL;
}
static int
mce_firmware_update(const char *cmd __rte_unused,
		    const char *params, struct rte_tel_data *d)
{
	char *argv[50] = {0}, buf[512];
	struct rte_eth_dev *eth_dev;
	struct mce_hw *hw = NULL;
	struct mce_tel_ctx ctx;
	const char *file_name;
	char *full_path = NULL;
	int ret = -EINVAL;
	int argc;

	tel_ctx_init(&ctx, d);
	argc = split_string(params, argv, buf, sizeof(buf), NULL);
	if (argc <= 0) {
		tel_println(&ctx, "Error: Failed to parse parameters");
		return 0;
	}
	if ((argc == 1 && !strcmp(argv[0], "help"))) {
		tel_println(&ctx,"Usage: /mce/update_firemware,port_id firmare_name");
		return 0;
	}
	eth_dev = get_mce_port(atoi(argv[0]));
	if (!eth_dev) {
		tel_println(&ctx, "error: port num isn't mce(n20)");
		return 0;
	}
	hw = MCE_DEV_TO_HW(eth_dev);
	if (argc >= 2) {
		file_name = argv[1];
		full_path = mce_find_firmware_path(file_name);
		if (full_path == NULL) {
			tel_println(&ctx, "update filename not found");

			return 0;
		}
		ret = mce_download_fw(hw, full_path);
		if (ret < 0)
			tel_println(&ctx, "update fw failed");
		else
			tel_println(&ctx, "update fw success please reboot");
	} else {
		tel_println(&ctx, "update fw failed filename not exist");
	}

	return 0;
}

RTE_INIT(mce_ethdev_init_telemetry)
{
	rte_telemetry_register_cmd("/mce/rx_ring_desc", mce_rx_ring_desc_handle_info,
			"debug n20 rx_hw desc state");
	rte_telemetry_register_cmd("/mce/tx_ring_desc", mce_tx_ring_desc_handle_info,
			"debug n20 tx_hw desc state");
	rte_telemetry_register_cmd("/mce/reg_read", mce_reg_read_handle_info,
			"read n20 reg");
	rte_telemetry_register_cmd("/mce/reg_write", mce_reg_write_handle_info,
			"write n20 reg");
	rte_telemetry_register_cmd("/mce/dump_rxq_info", mce_dump_rxq_info_handle_info,
			"debug n20 rxq_hw info");
	rte_telemetry_register_cmd("/mce/dump_txq_info", mce_dump_txq_info_handle_info,
			"debug n20 txq_hw info");
	rte_telemetry_register_cmd("/mce/nic_info_summary", mce_nic_info_summary,
			"summary mce n20 port info");
	rte_telemetry_register_cmd("/mce/rx_states", mce_rx_counters, "mce n20 rx counters");
	rte_telemetry_register_cmd("/mce/tx_states", mce_tx_counters, "mce n20 tx counters");
	rte_telemetry_register_cmd("/mce/ncsi_regs", mce_ncsi_regs, "mce n20 ncsi regs");
	rte_telemetry_register_cmd("/mce/dump", mce_dump, "mce n20 dump");
	rte_telemetry_register_cmd("/mce/sfp_eeprom", mce_sfp_eeprom_read, "mce n20 sfp eeprom read");
	rte_telemetry_register_cmd("/mce/force_speed", mce_force_speed, "mce n20 sfp force speed");
	rte_telemetry_register_cmd("/mce/fw_loglvl", mce_fw_log_lvl, "mce n20 fw log level");
	rte_telemetry_register_cmd("/mce/loglvl", mce_loglvl, "mce n20 log level");
	rte_telemetry_register_cmd("/mce/update_fw", mce_firmware_update, "mce update firemware");
}
#endif /* RTE_VERSION >= 21.05 */
