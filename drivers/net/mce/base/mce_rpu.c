#include "mce_osdep.h"
#include "mce_hw.h"
#include "mailbox.h"
#include "mce_rpu.h"

#define write_reg(reg, val) rte_write32(val, reg)
#define read_reg(reg)	    rte_read32((reg))

#define IOWRITE32_CFG_ARRAY(offset, array, size)                            \
	do {                                                                \
		for (i = 0; i < (size);) {                                  \
			write_reg(hw->npu_base + (offset) + (array)[i + 0], \
				  (u32)(array)[i + 1]);                     \
			i += 2;                                             \
		}                                                           \
	} while (0)

#define CHECK_CFG_ARRAY(offset, array, size)                       \
	do {                                                       \
		for (i = 0; i < (size);) {                         \
			uint32_t tmp = 0;                          \
			tmp = read_reg(hw->npu_base + (offset) +   \
				       (array)[i + 0]);            \
			if ((array)[i + 1] != tmp) {               \
				printf("addr %08x: val_base=%08x " \
				       "val_read=%08x\n",          \
				       (offset) + (array)[i + 0],  \
				       (array)[i + 1], tmp);       \
				break;                             \
			}                                          \
			i += 2;                                    \
		}                                                  \
	} while (0)

void download_n20_rpu_firmware(struct mce_hw *hw)
{
	int i = 0;
	uint32_t val = 0;
#define N20_START_REG 0x400000

#if 1
#define RPU_FW_BORAD_OFFSET 0x400000
#define RPU_FW_CHECK_OFFSET 0x000000

#define cluster_offset	    0x490000
#define switch_offset	    0x520000
#define core_offset	    0x00000

	if (hw->npu_base == NULL) {
		printf("[%s] [%d] npu bar is null\n", __func__, __LINE__);
		return;
	}

	val = read_reg(hw->npu_base + 0x6060);
	printf("[%s] [%d] npu version val=0x%x\n", __func__, __LINE__, val);

	/*  bar0_w32(hw, N20_START_REG, (u32)0x00); */
	printf("%s %d N20_START_REG=%x val=%x\n", __func__, __LINE__,
	       N20_START_REG, 0x00);
	write_reg(hw->npu_base + 0x6000 + N20_START_REG, 0x00);

	write_reg(hw->npu_base + cluster_offset + 0x10, 0x1); /* core_en_mask */
	write_reg(hw->npu_base + cluster_offset + 0x20, 0x0); /* close parser */
	write_reg(hw->npu_base + switch_offset + 0x8028, 0x1); /* cluster_en */

	/* write_reg(RPU_BASE+cluster_offset+0x18,0x80);*/
	write_reg(hw->npu_base + 0x490000 + 0x18, 0x7b);
	val = read_reg(hw->npu_base + 0x490000 + 0x18);
	printf("%s %d addr=%x val=%x\n", __func__, __LINE__, 0x490000 + 0x18,
	       0x00);
	write_reg(hw->npu_base + 0x490000 + 0x1c, 0x82);
	val = read_reg(hw->npu_base + 0x490000 + 0x1c);
	printf("%s %d addr=%x val=%x\n", __func__, __LINE__, 0x490000 + 0x1c,
	       0x00);
	IOWRITE32_CFG_ARRAY(RPU_FW_BORAD_OFFSET, cfg_inst, INST_SIZE);

	CHECK_CFG_ARRAY(RPU_FW_CHECK_OFFSET, cfg_inst, INST_SIZE);

	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x0, 0xa3b1bac6);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x4, 0x56aa3350);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x8, 0x677d9197);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0xc,
		  0xb27022dc); /* fk */
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x10 + 0x0, 0x7380166f);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x10 + 0x4, 0x4914b2b9);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x10 + 0x8, 0x172442d7);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x10 + 0xc, 0xda8a0600);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x20 + 0x0, 0xa96f30bc);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x20 + 0x4, 0x163138aa);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x20 + 0x8, 0xe38dee4d);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x20 + 0xc,
		  0xb0fb0e4e); /* sm3_iv */
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x30 + 0x0,
		  0x36363636); /* ipad */
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x30 + 0x4,
		  0x5c5c5c5c); /* opad */

	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x30 + 0xc, 0x67452301);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x40 + 0x0, 0xefcdab89);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x40 + 0x4, 0x98badcfe);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x40 + 0x8, 0x10325476);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x40 + 0xc,
		  0xc3d2e1f0); /* ht */
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x50 + 0x0, 0x5a827999);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x50 + 0x4, 0x6ed9eba1);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x50 + 0x8, 0x8f1bbcdc);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x50 + 0xc,
		  0xca62c1d6); /* kt */
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x60 + 0x0, 0xa96f30bc);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x60 + 0x4, 0x163138aa);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x60 + 0x8, 0xe38dee4d);
	write_reg(hw->npu_base + RPU_FW_BORAD_OFFSET + 0x60 + 0xc, 0xb0fb0e4e);

	/* iowrite32((u32)0x03, adapter->bars[0].addr + RPU_ENDIAN_REG); */
	/* bar0_w32(hw, RPU_ENDIAN_REG, (u32)0x03); */

	/* bar0_w32(hw, N20_START_REG, (u32)0x01); */

	/*  cluster_if/BYTE_CTRL */
	write_reg(hw->npu_base + cluster_offset + 0xc, 0x3);
	write_reg(hw->npu_base + 0x6000 + N20_START_REG, 0x01);

	for (i = 0; i < 512 * 1024; i++) {
		write_reg(hw->npu_base + 0x800000 + i * 16 + 0x0, i * 16 + 0x0);
		write_reg(hw->npu_base + 0x800000 + i * 16 + 0x4, i * 16 + 0x4);
		write_reg(hw->npu_base + 0x800000 + i * 16 + 0x8, i * 16 + 0x8);
		write_reg(hw->npu_base + 0x800000 + i * 16 + 0xc, i * 16 + 0xc);
	}

#else
	val = read_reg(hw->npu_base + 0x6060);
	printf("[%s] [%d] npu version val=0x%x\n", __func__, __LINE__, val);
#endif
	printf("HardWare Start\n");
	/* mailbox_ring tcm entry start address */
	write_reg(hw->npu_base + 0x41001c, 0x7c);
}
