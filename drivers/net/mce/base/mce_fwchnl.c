/**
 * @file mce_fwchnl.c
 * @brief Firmware channel communication implementation
 *
 * Implements PF-to-Firmware communication protocol through shared memory
 * channel. Supports firmware operations including:
 * - Port capability queries
 * - EEPROM read/write operations
 * - Register access operations
 * - Loopback and PHY control
 * - LED control
 * - Firmware update operations
 *
 * Firmware operations are initiated by PF and handled asynchronously
 * by firmware with response status delivery.
 *
 * @see mce_fwchnl.h for public API and opcodes
 * @see mce_mbx.c for mailbox communication
 */

#include <rte_ethdev.h>

#include "../mce.h"
#include "mce_common.h"
#include "mce_fwchnl.h"
#include "mce_mbx.h"
#include "mce_pf2vfchnl.h"

#define MBX_REQ_1MS  1000
#define MBX_REQ_100MS (100 * MBX_REQ_1MS)
#define MBX_REQ_50MS (50 * MBX_REQ_1MS)
#define MBX_REQ_5MS  (5 * MBX_REQ_1MS)
#define MBX_REQ_1S   (1000 * MBX_REQ_1MS)

#define N20_FW_MAGIC 0x4E323046

#define mce_wait_reg_timeout_ms(reg, cond, timeout_ms) \
	({                                             \
		unsigned int _v;                       \
		int timeout_us = (timeout_ms) * 1000;  \
		int ret = 0;                           \
		while (1) {                            \
			_v = rte_read32((reg));        \
			if ((cond))                    \
				break;                 \
			if (timeout_us < 0) {          \
				ret = -ETIMEDOUT;      \
				break;                 \
			}                              \
			rte_delay_us(10);              \
			timeout_us -= 10;              \
		}                                      \
		ret;                                   \
	})

/**
 * @brief Get physical address for an rte_memzone.
 *
 * Returns the physical/I/O virtual address for the provided memory zone.
 *
 * @param rz Pointer to rte_memzone
 * @return Physical/I/O virtual address or 0 on error
 */
static u64 mce_rte_memzone_phy_addr(const struct rte_memzone *rz)
{
	u64 phy_addr;

	if (!rz) {
		return 0;
	}
#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
#ifndef RTE_LIBRTE_XEN_DOM0
	phy_addr = (uint64_t)rz->phys_addr;
#else
	phy_addr = rte_mem_phy2mch((rz)->memseg_id, (rz)->phys_addr);
#endif
#else
	phy_addr = rz->iova;
#endif
	return phy_addr;
}

/**
 * @brief Read a 32-bit SOC register via firmware channel.
 *
 * Sends a READ_REG request to firmware and returns the 32-bit value.
 *
 * @param hw Pointer to MCE hardware structure
 * @param soc_addr SOC register address to read
 * @param pvalue Pointer to store read value (optional)
 * @return 0 on success, negative error code on failure
 */
int mce_soc_ioread32(struct mce_hw *hw, int soc_addr, int *pvalue)
{
	union mbx_fw_cmd_resp_data *resp_data = NULL;
	union mbx_fw_cmd_req_data req_data;
	int ret = 0, try_cnt = 3;
	struct mbx_resp resp = {};

	resp_data = (union mbx_fw_cmd_resp_data *)resp.data;
	req_data.r_reg.addr = soc_addr;
	req_data.r_reg.bytes = 4;

	while (try_cnt--) {
		ret = mce_mbx_send_req(&hw->pf2fw_mbx, READ_REG, req_data.data,
				       sizeof(req_data.r_reg), &resp,
				       MBX_REQ_100MS);
		if (ret == 0)
			break;
	}

	if (ret == 0 && pvalue) {
		if (resp.cmd.err_code == 0) {
			*pvalue = (int)resp_data->r_reg.value[0];
		} else {
			PMD_HW_ERR(hw,
				   "%s() read addr:0x%x faield!, err_code:%d\n",
				   __func__, soc_addr, resp.cmd.err_code);
			ret = -EIO;
		}
	}

	return ret;
}

/**
 * @brief Write a 32-bit SOC register via firmware channel.
 *
 * Sends a WRITE_REG request to firmware to program SOC register.
 *
 * @param hw Pointer to MCE hardware structure
 * @param soc_addr SOC register address to write
 * @param value Value to write
 * @return 0 on success, negative error code on failure
 */
int mce_soc_iowrite32(struct mce_hw *hw, int soc_addr, int value)
{
	union mbx_fw_cmd_req_data req_data;
	int ret = 0, try_cnt = 3;
	struct mbx_resp resp = {};

	req_data.w_reg.addr = soc_addr;
	req_data.w_reg.bytes = 4;
	req_data.w_reg.data[0] = value;

	while (try_cnt--) {
		ret = mce_mbx_send_req(&hw->pf2fw_mbx, WRITE_REG, req_data.data,
				       sizeof(req_data.w_reg), &resp,
				       MBX_REQ_100MS);
		if (ret == 0)
			break;
	}

	if (ret == 0) {
		if (resp.cmd.err_code != 0) {
			PMD_HW_ERR(
				hw,
				"%s() write addr:0x%x <- 0x%x faield!, err_code:%d\n",
				__func__, soc_addr, value, resp.cmd.err_code);
			ret = -EIO;
		}
	}

	return ret;
}

/**
 * @brief Modify bits of a SOC register atomically via firmware.
 *
 * Uses MODIFY_REG command to change only the bits specified by `mask`.
 *
 * @param hw Pointer to MCE hardware structure
 * @param soc_addr SOC register address to modify
 * @param mask Bitmask indicating which bits to change
 * @param value New value for masked bits
 * @return 0 on success, negative error code on failure
 */
int mce_soc_modify32(struct mce_hw *hw, int soc_addr, unsigned int mask,
			 int value)
{
	int ret = 0, try_cnt = 3;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_req_data req_data;

	memset(&req_data, 0, sizeof(req_data));
	req_data.modify_reg.addr = soc_addr;
	req_data.modify_reg.mask = mask;
	req_data.modify_reg.data = (unsigned int)value;

	while (try_cnt--) {
		ret = mce_mbx_send_req(&hw->pf2fw_mbx, MODIFY_REG,
				       req_data.data,
				       sizeof(req_data.modify_reg), &resp,
				       MBX_REQ_100MS);
		if (ret == 0)
			break;
	}

	if (ret == 0) {
		if (resp.cmd.err_code != 0) {
			PMD_HW_ERR(
				hw,
				"%s() modify addr:0x%x <- 0x%x (mask:0x%x) failed!, err_code:%d\n",
				__func__, soc_addr, value, mask,
				resp.cmd.err_code);
			ret = -EIO;
		}
	}

	return ret;
}

/**
 * @brief Request a memory dump from firmware.
 *
 * Issues a GET_DUMP mailbox request and copies up to `bytes` of the
 * returned dump into `buf` if provided. Allocates a DMA buffer if the
 * dump size is larger than inline response.
 *
 * @param hw Pointer to MCE hardware structure
 * @param buf Output buffer to receive dump data (may be NULL)
 * @param bytes Maximum number of bytes to copy into `buf`
 * @return 0 on success, negative error code on failure
 */
int mce_mbx_get_dump(struct mce_hw *hw, char*buf, int bytes)
{
	int err = 0;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_req_data req_data;
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;
	const struct rte_memzone *rz = NULL;
	u64 phy_addr = 0;
#define MAX_DUMP_BUF 4096

	memset(&req_data, 0, sizeof(req_data));

	if (bytes > (int)(sizeof(resp_data->get_dump.data))) {
		/* get dma */
		rz = rte_memzone_reserve_aligned("get_dump", MAX_DUMP_BUF,
						 SOCKET_ID_ANY,
						 RTE_MEMZONE_IOVA_CONTIG, 4096);
		if (rz == NULL) {
			PMD_HW_ERR(hw, " %s: not memory:%d\n", __func__, MAX_DUMP_BUF);
			return -EFBIG;
		}
		memset(rz->addr, 0x0, rz->len);

		phy_addr = mce_rte_memzone_phy_addr(rz);
	}

	req_data.get_dump.bytes = bytes;
	req_data.get_dump.bin_phy_lo = (unsigned int)(phy_addr & 0xFFFFFFFF);
	req_data.get_dump.bin_phy_hi =
		(unsigned int)((phy_addr >> 32) & 0xFFFFFFFF);

	err = mce_mbx_send_req(&hw->pf2fw_mbx, GET_DUMP, req_data.data,
			       sizeof(req_data.get_dump), &resp,
			       MBX_REQ_1S * 1);
	if (err || resp.cmd.err_code) {
		err = -EIO;
		goto quit;
	}

	if(buf){
		int rbytes = resp_data->get_dump.bytes ;
		if(rbytes > bytes)
			rbytes = bytes;
		if(rz){
			memcpy(buf, rz->addr,rbytes);
		}else{
			memcpy(buf, resp_data->get_dump.data,rbytes);
		}
	}

quit:
	if(rz)
		rte_memzone_free(rz);
	return err;
}

/**
 * @brief Set dump control flags in firmware via mailbox.
 *
 * @param hw Pointer to MCE hardware structure
 * @param dump_v Flag value to set in firmware
 * @return 0 on success, -EIO on failure
 */
int mce_mbx_set_dump(struct mce_hw *hw, int dump_v)
{
	int err = 0;
	union mbx_fw_cmd_req_data req_data;

	memset(&req_data, 0, sizeof(req_data));

	req_data.set_dump.flag = dump_v;

	err = mce_mbx_send_req(&hw->pf2fw_mbx, SET_DUMP, req_data.data,
			       sizeof(req_data.set_dump), NULL,
			       MBX_REQ_1MS * 500);
	if (err)
		return -EIO;

	return 0;
}

/**
 * @brief Configure AXI clock frequency via firmware mailbox.
 *
 * Validates `clk_mhz` range and uses `mce_mbx_set_dump` helper to
 * send the appropriate firmware command.
 *
 * @param hw Pointer to MCE hardware structure
 * @param clk_mhz Desired AXI clock in MHz (200-500)
 * @return 0 on success, -EINVAL on invalid argument, or negative on failure
 */
int mce_mbx_axi_clk_set(struct mce_hw *hw, int clk_mhz)
{
	if(clk_mhz < 200 || clk_mhz >500 ){
		return -EINVAL;
	}

	return mce_mbx_set_dump(hw, 0x0E010000 | (clk_mhz));
}

/**
 * @brief Notify firmware that interface is up or down.
 *
 * Sends an IFUP_DOWN request to firmware indicating interface state.
 *
 * @param hw Pointer to MCE hardware structure
 * @param up True to signal interface up, false for down
 * @return 0 on success, negative error code on failure
 */
int mce_mbx_ifup_down(struct mce_hw *hw, bool up)
{
	int err = 0;

	union mbx_fw_cmd_req_data req_data;

	memset(&req_data, 0, sizeof(req_data));

	req_data.ifup.up = !!up;

	err = mce_mbx_send_req(&hw->pf2fw_mbx, IFUP_DOWN, req_data.data,
			       sizeof(req_data.ifup), NULL, MBX_REQ_1MS * 50);
	if (err)
		return -EIO;

	return 0;
}

int mce_mbx_set_phy_func(struct mce_hw *hw, int func, int arg0, int arg1)
{
	int err = 0;
	union mbx_fw_cmd_req_data req_data;

	memset(&req_data, 0, sizeof(req_data));

	req_data.set_phy_fun.func = func;
	req_data.set_phy_fun.value0 = arg0;
	req_data.set_phy_fun.value1 = arg1;

	err = mce_mbx_send_req(&hw->pf2fw_mbx, SET_PHY_FUNC, req_data.data,
			       sizeof(req_data.set_phy_fun), NULL,
			       MBX_REQ_1MS * 500);
	if (err)
		return -EIO;
	return 0;
}

int mce_mbx_set_link_traning_en(struct mce_hw *hw, int enable)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_LINK_TRAING, !!enable, 0);
}

int mce_mbx_set_autoneg(struct mce_hw *hw, int enable)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_AN, !!enable, 0);
}

int mce_mbx_set_fec(struct mce_hw *hw, enum FEC_TYPE fec_type)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_FEC, fec_type, 0);
}

int mce_mbx_set_link_restart_autoneg(struct mce_hw *hw)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_AN_RESTART, 0, 0);
}

int mce_mbx_wol_set(struct mce_hw *hw, bool enable)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_WOL_SET, enable, 0);
}

int mce_fw_set_led(struct mce_hw *hw, enum LED_ACTION action)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_LED_IDENTIFY, action, 0);
}

/**
 * @brief Set SGMII duplex mode via firmware.
 *
 * Updates local firmware statistics then programs the PHY duplex
 * setting through the mailbox helper. Only valid for SGMII lanes.
 *
 * @param hw Pointer to MCE hardware structure
 * @param full Non-zero to set full duplex, zero for half
 * @return 0 on success, negative errno on failure
 */
int mce_mbx_set_duplex(struct mce_hw *hw, int full)
{
	mce_update_fw_stat(hw);

	if (!hw->fw_stat.stat0.is_sgmii)
		return -EINVAL;

	return mce_mbx_set_phy_func(hw, PHY_FUN_SET_SGMII_DUPLEX, full, 0);
}

/**
 * @brief Enable or disable forcing link active on close.
 *
 * Requests the PHY to hold the link up when the driver closes the port,
 * useful for certain cable/diagnostic scenarios.
 *
 * @param hw Pointer to MCE hardware structure
 * @param force True to force link on close, false to disable
 * @return 0 on success or negative errno
 */
int mce_mbx_set_force_link_on_close(struct mce_hw *hw, bool force)
{
	return mce_mbx_set_phy_func(hw, PHY_FUN_FORCE_LINK_ON_CLOSE, force, 0);
}

/**
 * @brief Force PHY speed via firmware mailbox.
 *
 * Maps the abstract `FORCE_SPEED` to an actual link rate and
 * issues a PHY function request to enforce the setting.
 *
 * @param hw Pointer to MCE hardware
 * @param speed_type Enumerated forced speed selection
 * @param duplex Duplex mode when forcing speed
 * @return 0 on success, -EINVAL for invalid parameters
 */
int mce_mbx_set_force_speed(struct mce_hw *hw,
			    enum FORCE_SPEED speed_type, int duplex)
{
	u32 speed_map[] = {
		[FORCE_1G] = 1000,
		[FORCE_10G] = 10000,
		[FORCE_25G] = 25000,
		[FORCE_40G] = 40000,
		[FORCE_100G] = 100000,
		[FORCE_100M] = 100,
		[FORCE_10M] = 10,
	};

	if (speed_type >= FORCE_NUM)
		return -EINVAL;

	hw->saved_force_speed = speed_type;

	if (speed_type != NO_FORCE_SPEED) {
		if (speed_map[speed_type] > hw->max_speed)
			return -EINVAL;
	}

	return mce_mbx_set_phy_func(hw, PHY_FUN_FORCE_SPEED, speed_type, duplex);
}

/**
 * @brief Read SFP/I2C bytes via firmware mailbox (internal helper).
 *
 * Performs a single mailbox SFP read limited by MBX_SFP_READ_MAX_CNT.
 * This helper is internal and retries are handled by callers.
 *
 * @param hw Hardware context
 * @param sfp_i2c_addr I2C address of the SFP/QSFP module
 * @param sfp_reg EEPROM offset to read
 * @param buf Destination buffer to store read bytes
 * @param bytes Number of bytes to read (<= MBX_SFP_READ_MAX_CNT)
 * @return 0 on success or negative errno
 */
static int mce_mbx_sfp_read(struct mce_hw *hw, int sfp_i2c_addr, int sfp_reg,
			    char *buf, int bytes)
{
	int err = 0;
	struct mbx_resp resp = { 0 };
	union mbx_fw_cmd_req_data req_data;
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;

	memset(&req_data, 0, sizeof(req_data));

	if (bytes > MBX_SFP_READ_MAX_CNT)
		return -EINVAL;

	req_data.sfp_read.nr_phy = hw->nr_pf;
	req_data.sfp_read.cnt = bytes;
	/* 0xA0 0xA2 0xAC */
	req_data.sfp_read.sfp_i2c_adr = sfp_i2c_addr;
	req_data.sfp_read.reg = sfp_reg;

	err = mce_mbx_send_req(&hw->pf2fw_mbx, SFP_MODULE_READ, req_data.data,
			       sizeof(req_data.sfp_read), &resp,
			       MBX_REQ_1MS * 1000);
	if (err || resp.cmd.err_code != 0)
		return -EIO;
	memcpy(buf, resp_data->sfp_read.value, bytes);

	return 0;
}

/**
 * @brief Read SFP/I2C bytes via firmware mailbox (internal helper).
 *
 * Performs a single mailbox SFP read limited by MBX_SFP_READ_MAX_CNT.
 * This helper is internal and retries are handled by callers.
 *
 * @param hw Hardware context
 * @param sfp_i2c_addr I2C address of the SFP/QSFP module
 * @param sfp_reg EEPROM offset to read
 * @param buf Destination buffer to store read bytes
 * @param bytes Number of bytes to read (<= MBX_SFP_READ_MAX_CNT)
 * @return 0 on success or negative errno
 */
int mce_read_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr, int sfp_reg,
			       char *buf, int bytes)
{
	int left = bytes;
	int cnt, err;

	do {
		cnt = (left < MBX_SFP_READ_MAX_CNT) ? left :
						      MBX_SFP_READ_MAX_CNT;
		err = mce_mbx_sfp_read(hw, sfp_i2c_addr, sfp_reg, buf, cnt);
		if (err) {
			PMD_HW_ERR(
				hw,
				"%s: sfp eeprom failed! addr:0x%x reg:0x%x bytes:%d\n",
				__func__, sfp_i2c_addr, sfp_reg, cnt);
			return err;
		}
		sfp_reg += cnt;
		buf += cnt;
		left -= cnt;
	} while (left > 0);

	return 0;
}

/**
 * @brief Write a single SFP/I2C EEPROM byte via firmware mailbox.
 *
 * Issues an SFP_MODULE_WRITE request to write a single 16-bit value.
 *
 * @param hw Hardware context
 * @param sfp_i2c_addr I2C address of the SFP module
 * @param sfp_reg EEPROM register offset
 * @param val Value to write
 * @return 0 on success or negative errno
 */
int mce_write_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr,
				int sfp_reg, short val)
{
	int err = 0;
	union mbx_fw_cmd_req_data req_data;

	memset(&req_data, 0, sizeof(req_data));

	req_data.sfp_write.nr_phy = hw->nr_pf;
	req_data.sfp_write.sfp_i2c_adr = sfp_i2c_addr;
	req_data.sfp_write.reg = sfp_reg;
	req_data.sfp_write.val = val;

	err = mce_mbx_send_req(&hw->pf2fw_mbx, SFP_MODULE_WRITE, req_data.data,
			       sizeof(req_data.sfp_write), NULL,
			       MBX_REQ_1MS * 500);
	if (err)
		return -EIO;

	return 0;
}

/**
 * @brief Dump EEPROM contents into a provided buffer via DMA.
 *
 * Allocates a DMA buffer, requests an EEPROM dump from firmware and
 * copies the returned data into the caller buffer.
 *
 * @param hw Hardware context
 * @param offset EEPROM offset to start dump
 * @param buf Destination buffer to receive dump
 * @param bytes Number of bytes to dump
 * @return 0 on success, -EFBIG if DMA allocation fails, -EIO on IO error
 */
int mce_mbx_dump_eeprom(struct mce_hw *hw, int offset, char *buf, int bytes)
{
	int err = 0;
	union mbx_fw_cmd_req_data req_data;
	const struct rte_memzone *rz = NULL;
	u64 dma_phy = 0;
	char *dma_buf;

	memset(&req_data, 0, sizeof(req_data));

	rz = rte_memzone_reserve_aligned("dump_eeprom", bytes, SOCKET_ID_ANY,
					 RTE_MEMZONE_IOVA_CONTIG, 4096);
	if (rz == NULL) {
		PMD_HW_ERR(hw, " %s: not memory:%d\n", __func__, bytes);
		return -EFBIG;
	}
	memset(rz->addr, 0x0, rz->len);
	dma_phy = mce_rte_memzone_phy_addr(rz);
	dma_buf = rz->addr;

	req_data.dump_eeprom.bytes = bytes;
	req_data.dump_eeprom.ddr_lo = (unsigned int)(dma_phy & 0xFFFFFFFF);
	req_data.dump_eeprom.ddr_hi =
		(unsigned int)((dma_phy >> 32) & 0xFFFFFFFF);
	req_data.dump_eeprom.offset = offset;

	err = mce_mbx_send_req(&hw->pf2fw_mbx, DUMP_EEPROM, req_data.data,
			       sizeof(req_data.dump_eeprom), NULL,
			       MBX_REQ_1S * 50);
	if (err == 0)
		memcpy(buf, dma_buf, bytes);

	rte_memzone_free(rz);

	return (err) ? -EIO : 0;
}

/**
 * @brief Internal helper to perform the firmware update sequence.
 *
 * Validates firmware image magic and issues FW_EEPROM commands to
 * initiate firmware programming from a DMA buffer.
 *
 * @param hw Hardware context
 * @param fw_bin Pointer to firmware image in DMA-able memory
 * @param fw_phy Physical address of the firmware DMA buffer
 * @param bytes Size of the firmware image in bytes
 * @return 0 on success or negative errno
 */
static int do_update_fw(struct mce_hw *hw, char *fw_bin, u64 fw_phy, int bytes)
{
	int ret = 0, try_cnt = 3;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_req_data req_data;

	if (*((unsigned int *)(fw_bin + 0x1C)) != N20_FW_MAGIC) {
		PMD_HW_ERR(hw, " not valid firmware img bin\n");
		return -EINVAL;
	}

	req_data.eeprom.cmd = 1;
	req_data.eeprom.bytes = bytes;
	req_data.eeprom.ddr_lo = (unsigned int)(fw_phy & 0xFFFFFFFF);
	req_data.eeprom.ddr_hi = (unsigned int)((fw_phy >> 32) & 0xFFFFFFFF);
	req_data.eeprom.partion = 1;
	/* 	printf("%s: %lx, %x,%x len:%d\n", __func__, (unsigned long)fw_phy,
	       req_data.eeprom.ddr_hi, req_data.eeprom.ddr_lo, bytes); */

	while (try_cnt--) {
		ret = mce_mbx_send_req(&hw->pf2fw_mbx, FW_EEPROM, req_data.data,
				       sizeof(req_data.eeprom), &resp,
				       MBX_REQ_1S * 50);
		if (ret == 0)
			break;
	}

	return ret;
}

 /**
 * @brief Download firmware file and program device via DMA.
 *
 * Reads the firmware file into a DMA-able memzone and calls the
 * internal update helper to program it into the device.
 *
 * @param hw Hardware context
 * @param fw_path Path to firmware image file
 * @return 0 on success or negative errno
 */
int mce_download_fw(struct mce_hw *hw, const char *fw_path)
{
	const struct rte_memzone *rz = NULL;
	u64 phy_addr = 0;
	FILE *fp;
	int fw_sz, ret;
#define MAX_FW_BIN_SZ (1 * 1024 * 1024)

	printf("%s: %s() fw-path: %s\n", hw->device_name, __func__, fw_path);

	fp = fopen(fw_path, "rb");
	if (!fp) {
		PMD_HW_ERR(hw, " [%s] %s can't open for read\n", __func__,
			   fw_path);
		return -ENOENT;
	}

	/* get dma */
	rz = rte_memzone_reserve_aligned("fw_update", MAX_FW_BIN_SZ,
					 SOCKET_ID_ANY, RTE_MEMZONE_IOVA_CONTIG,
					 4096);
	if (rz == NULL) {
		PMD_HW_ERR(hw, " %s: not memory:%d\n", __func__, MAX_FW_BIN_SZ);
		fclose(fp);
		return -EFBIG;
	}
	memset(rz->addr, 0x0, rz->len);

	/* read data */
	fw_sz = fread(rz->addr, 1, rz->len, fp);
	if (fw_sz <= 0) {
		PMD_HW_INFO(hw, " %s: read failed! err:%d\n", __func__, fw_sz);
		fclose(fp);
		rte_memzone_free(rz);
		return -EIO;
	}
	fclose(fp);

	phy_addr = mce_rte_memzone_phy_addr(rz);
	printf("%s: fw updating bytes:%d ...\n", hw->device_name, fw_sz);
	ret = do_update_fw(hw, rz->addr, phy_addr, fw_sz);

	printf("%s: done\n", hw->device_name);
	rte_memzone_free(rz);

	return ret;
}

/**
 * @brief Read a SOC register without shared-memory mailbox protection.
 *
 * Performs a direct register read using the event interface and a
 * request lock to avoid concurrent register operations.
 *
 * @param hw Hardware context
 * @param soc_reg Register address to read (will be aligned)
 * @return Register value on success or 0xdeadbeaf on failure
 */
int mce_soc_ioread32_noshm(struct mce_hw *hw, int soc_reg)
{
	int err, ret = 0xdeadbeaf;
	struct mce_mbx_info *mbx = &hw->pf2fw_mbx;
	char __iomem *p_reg = (char *)hw->nic_base + 0x33000 + 0x14;
	char __iomem *p_dat = (char *)hw->nic_base + 0x33000 + 0x18;

	soc_reg = soc_reg & ~3;

	rte_spinlock_lock(&mbx->req_lock);

	rte_write32(0, p_dat);
	rte_write32(soc_reg, p_reg);
	err = mce_mbx_send_event(mbx, EVT_REG_OP, 0);
	if (err != 0) {
		PMD_HW_ERR(hw, "%s: failed read 0x%x err:%d\n", __func__,
			   soc_reg, err);
		goto quit;
	}
	/* wait request done: p_reg BIT(1) = 1 */
	if (mce_wait_reg_timeout_ms(p_reg, (_v & BIT(1)), MBX_REQ_1MS * 40) ==
	    0) {
		ret = rte_read32(p_dat);
	} else {
		PMD_HW_ERR(hw, "%s: failed read 0x%x timeout\n", __func__,
			   soc_reg);
	}

quit:
	rte_spinlock_unlock(&mbx->req_lock);
	return ret;
}

/**
 * @brief Write a SOC register without shared-memory mailbox protection.
 *
 * Uses the event interface and request lock to write a register.
 *
 * @param hw Hardware context
 * @param soc_reg Register address to write (aligned)
 * @param v Value to write
 * @return 0 on success or negative errno
 */
int mce_soc_iowrite32_noshm(struct mce_hw *hw, int soc_reg, int v)
{
	int ret = -EIO;
	struct mce_mbx_info *mbx = &hw->pf2fw_mbx;
	char __iomem *p_reg = (char *)hw->nic_base + 0x33000 + 0x14;
	char __iomem *p_dat = (char *)hw->nic_base + 0x33000 + 0x18;

	soc_reg = soc_reg & ~3;

	rte_spinlock_lock(&mbx->req_lock);

	rte_write32(v, p_dat);
	rte_write32(soc_reg | BIT(0), p_reg);
	ret = mce_mbx_send_event(mbx, EVT_REG_OP, 0);
	/* wait request done: p_reg BIT(1) = 1 */
	if (mce_wait_reg_timeout_ms(p_reg, (_v & BIT(1)), MBX_REQ_1MS * 40) ==
	    0) {
		ret = 0;
	}

	rte_spinlock_unlock(&mbx->req_lock);
	return ret;
}

/**
 * @brief Retrieve firmware-reported supported PHY speeds.
 *
 * Populates the provided structure with firmware-reported capabilities.
 *
 * @param hw Hardware context
 * @param speed Output structure to receive supported speed mask
 * @return 0 on success or -EINVAL for bad args
 */
int mce_get_fw_supported_speed(struct mce_hw *hw,
			       struct phy_speed_ablity *speed)
{
	u32 v;
	if (!speed) {
		return -EINVAL;
	}
	mce_update_fw_stat(hw);

	v = hw->fw_stat.stat2.ext.phy_speed_ablity;
	memcpy(speed, &v, sizeof(*speed));

	return 0;
}


/**
 * @brief Request NIC reset via firmware and wait for completion.
 *
 * Sends a reset event and polls firmware status to detect reset
 * completion within a timeout window.
 *
 * @param hw Hardware context
 * @return 0 on success, -EIO on timeout or failure
 */
int mce_mbx_fw_nic_reset(struct mce_hw *hw)
{
	int timeout_us = 30 * MBX_REQ_1MS;
	int ret = 0;

	/*  send  reset cmd */
	ret = mce_mbx_send_event(&hw->pf2fw_mbx, EVT_NIC_RESET,
				 10 * MBX_REQ_1MS);
	if (ret) {
		PMD_HW_ERR(hw, "nic reset cmd timeout\n");
		return -EIO;
	}

	/*  wait reset done by poll fw2pf done flag */
	while (timeout_us > 0) {
		ret = mce_pf_mbx_get_fw_stat(&hw->pf2fw_mbx,
					     FW_NIC_RESET_DONE_STAT);
		if (ret < 0)
			break;
		else if (ret == 1)
			return 0;
		timeout_us -= 10;
		rte_delay_us(10);
	}

	PMD_HW_ERR(hw, "nic reset timeout\n");
	return -EIO;
}

/**
 * @brief Notify firmware that the interface is up or down.
 *
 * Sets local state and sends IFUP_DOWN command to firmware.
 *
 * @param hw Hardware context
 * @param up True for interface up, false for down
 * @return 0 on success or negative errno
 */
int mce_mbx_fw_ifup(struct mce_hw *hw, bool up)
{
	int err;
	union mbx_fw_cmd_req_data req_data;

	req_data.ifup.up = up;
	hw->ifup_status = up;
	if(up == false){
		hw->link_status = 0;
	}

	err = mce_mbx_send_req(&hw->pf2fw_mbx, IFUP_DOWN, req_data.data,
			       sizeof(req_data.ifup), NULL, MBX_REQ_50MS);

	return err;
}

/**
 * @brief Query firmware for port ability/capabilities and cache them.
 *
 * Sends GET_PORT_ABALITY request and stores returned values into
 * the `ablity` structure and into the hw context.
 *
 * @param hw Hardware context
 * @param ablity Output structure to receive port capabilities
 * @return 0 on success or negative errno
 */
int mce_fw_get_ablity(struct mce_hw *hw, struct port_ablity *ablity)
{
	int err;
	union mbx_fw_cmd_req_data req_data;
	int try_cnt = 3;
	struct mbx_resp resp = {};
	union mbx_fw_cmd_resp_data *resp_data =
		(union mbx_fw_cmd_resp_data *)resp.data;
	req_data.get_port_ablity.whoami = I_AM_DPDK;

	while (try_cnt--) {
		err = mce_mbx_send_req(&hw->pf2fw_mbx, GET_PORT_ABALITY,
				       req_data.data,
				       sizeof(req_data.get_port_ablity), &resp,
				       MBX_REQ_100MS);
		if (err == 0)
			break;
	}
	if (err != 0)
		return -EIO;

	memcpy(ablity, resp.data, sizeof(*ablity));

	hw->fw_version = resp_data->ablity.fw_version;
	if (hw->nr_pf != ablity->nr_pf) {
		PMD_HW_ERR(hw, "%s: nr_pf:%d,%d error\n", __func__, hw->nr_pf,
			   ablity->nr_pf);
		return -EIO;
	}

	if (ablity->vf_max_ring < hw->vf_min_ring_cnt) {
		PMD_HW_INFO(hw, "%s: change vf_max_ring from %d to %d\n",
			    __func__, ablity->vf_max_ring, hw->vf_min_ring_cnt);
		ablity->vf_max_ring = hw->vf_min_ring_cnt;
	}
	hw->max_speed = speed_unzip(ablity->max_speed);
	hw->vf_bar_isolate_on = !ablity->vf_isolation_disabled;
	hw->vf_max_ring = ablity->vf_max_ring;
	hw->nb_qpair_per_vf = hw->vf_max_ring;
	hw->is_ocp_card = ablity->ncsi_en;
	PMD_HW_INFO(hw,
		    "%s: pcie isolate on:%d vf_max_ring:%d fw-version:0x%08x "
		    "max-speed:%d ncsi-en:%d\n",
		    __func__, hw->vf_bar_isolate_on, ablity->vf_max_ring,
		    hw->fw_version, ablity->max_speed, hw->is_ocp_card);
	return 0;
}

/**
 * @brief Set maximum per-VF queue count via firmware mailbox.
 *
 * Validates that the requested count is a power-of-two and requests
 * firmware to configure VF queue limits.
 *
 * @param hw Hardware context
 * @param vf_max_queue_cnt Desired max queues per VF (power of two)
 * @return 0 on success or -EINVAL on invalid parameter
 */
int mce_mbx_set_vf_max_queue_cnt(struct mce_hw *hw, u32 vf_max_queue_cnt)
{
	int err = 0;
	union mbx_fw_cmd_req_data req_data;

	if (!rte_is_power_of_2(vf_max_queue_cnt)) {
		PMD_HW_ERR(hw, "%s: vf_max_queue_cnt:%d should be power of 2\n",
			   hw->pf2fw_mbx.name, vf_max_queue_cnt);
		return -EINVAL;
	}

	req_data.vf_max_queue_cnt.max_cnt = vf_max_queue_cnt;
	req_data.vf_max_queue_cnt.vf_isolation_disable = 0;

	err = mce_mbx_send_req(&hw->pf2fw_mbx, SET_VF_MAX_QUEUE, req_data.data,
			       sizeof(req_data.vf_max_queue_cnt), NULL,
			       MBX_REQ_100MS);

	return err;
}

/**
 * @brief ISR handler for firmware-initiated mailbox requests.
 *
 * Called from interrupt context to acknowledge and respond to
 * firmware requests directed to the PF.
 *
 * @param mbx Pointer to mailbox info
 * @param req Pointer to incoming request
 */
void mce_mbx_fw2pf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req)
{
	int opcode __maybe_unused = req->cmd.opcode;
	enum MBX_REQ_STAT stat = RESP_OR_ACK;
	struct mbx_resp resp = {};

	resp.cmd.v = req->cmd.v;
	resp.cmd.err_code = 0;
	resp.cmd.flag_no_resp = 1; /* default no resp */

	logd(LOG_MBX_IN_REQ, "%s: req-opcode:%d 0x%08x 0x%08x 0x%08x 0x%08x\n",
	     mbx->name, req->cmd.opcode, req->data[0], req->data[1],
	     req->data[2], req->data[3]);
	mce_mbx_send_resp_isr(mbx, &resp);

	mce_mbx_clear_peer_req_irq_with_stat(mbx, stat);
}

/**
 * @brief Handle link-up/link-down events reported by firmware.
 *
 * Updates local link state, reports the change to the system and
 * notifies VFs when required.
 *
 * @param mbx Mailbox context containing hw pointer
 * @param linkup Non-zero when link is up, zero when down
 * @return 0 on success
 */
static int mce_mbx_fw_handle_link_event(struct mce_mbx_info *mbx, int linkup)
{
	struct mce_hw *hw = mbx->hw;
	struct fw_stat *fwstat = &hw->fw_stat;

	mce_update_fw_stat(hw);

	hw->link_status = !!linkup;
	if (hw->link_status)
		hw->link_speed = speed_unzip(fwstat->stat0.s_speed);
	else
		hw->link_speed = 0;
	hw->link_duplex = fwstat->stat0.duplex;
	hw->link_autoneg = fwstat->stat0.autoneg;

	mce_report_link(hw);

	mce_mbx_set_pf_stat_reg(hw);

	if (hw->max_vfs > 0)
		mce_pf_notify_all_vf_link_state(hw);

	PMD_HW_INFO(hw, "%s: linkup:%d speed:%d duplex:%d\n", __func__,
		    hw->link_status, hw->link_speed, hw->link_duplex);
	return 0;
}

/**
 * @brief Dispatch firmware event notifications to handlers.
 *
 * Called from IRQ context when firmware signals asynchronous events
 * such as link up/down or SFP plugin/plugout.
 *
 * @param mbx Mailbox context
 * @param event_id Firmware event identifier
 */
void mce_mbx_fw2pf_event_req_isr(struct mce_mbx_info *mbx, int event_id)
{
	logd(LOG_MBX_IN_REQ, "%s: event_id:%d\n", mbx->name, event_id);
	switch (event_id) {
	case EVT_PORT_LINK_UP:
		mce_mbx_fw_handle_link_event(mbx, 1);
		break;
	case EVT_PORT_LINK_DOWN:
		mce_mbx_fw_handle_link_event(mbx, 0);
		break;
	case EVT_SFP_PLUGIN_OUT:
		break;
	case EVT_SFP_PLUGIN_IN:
		break;
	}
}
