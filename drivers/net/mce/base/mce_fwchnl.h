/**
 * @file mce_fwchnl.h
 * @brief MCE Firmware Channel Communication
 *
 * Defines the protocol for communication with MCE firmware via dedicated
 * channels, including opcodes for various operations like port ability query,
 * register access, EEPROM operations, loopback, and statistics.
 *
 * @details
 * Supported operations:
 * - Port capability and ability queries
 * - EEPROM read/write and dump
 * - Register read/write/modify
 * - Interface up/down notifications
 * - PHY configuration
 * - Loopback testing
 * - Statistics collection
 * - Temperature and power management
 *
 * @see mce_fwchnl.c for implementation
 */

#ifndef MCE_FWCHNL_H
#define MCE_FWCHNL_H

#include "mce_hw.h"
#include "mce_mbx.h"

#ifndef _PACKED_ALIGN4
#define _PACKED_ALIGN4 __attribute__((packed, aligned(4)))
#endif

/**
 * @brief Update firmware statistics from hardware.
 *
 * Queries and caches firmware statistics and status information.
 *
 * @param hw Pointer to MCE hardware structure
 */
void mce_update_fw_stat(struct mce_hw *hw);

enum PF2FW_OPCODE {
	GET_PORT_ABALITY = 1,
	FW_EEPROM = 2,

	READ_REG = 3,
	WRITE_REG = 4,
	MODIFY_REG = 5,

	IFUP_DOWN = 6,

	SET_PHY_FUNC = 10,

	SET_LOOPBACK_MODE = 14,

	SET_PMA_SI = 17,
	GET_PMA_SI = 18,

	DUMP_EEPROM = 19,

	SFP_MODULE_READ = 20,
	SFP_MODULE_WRITE = 21,

	GET_DUMP = 24,
	SET_DUMP = 25,

	LLDP_TX_CTL = 27,
	SET_DDR_CSL = 28,

	SET_VF_MAX_QUEUE = 29,

	SRIOV_SET = 32,

	WRITE_SGMII_PHY_REG = 40,
	READ_SGMII_PHY_REG = 41,
	MODIFY_SGMII_PHY_REG = 42,
};

struct port_ablity {
	unsigned int fw_version;
	unsigned short axi_mhz;
	unsigned short phy_type;

	unsigned int vf_isolation_disabled : 1;
	unsigned int vf_max_ring : 7;
	unsigned int nr_pf : 1;
	unsigned int link_stat : 1;
	unsigned int max_speed : 3;
	unsigned int wol_supported : 1;
	unsigned int wol_enabled : 1;
	unsigned int is_sgmii : 1;
	unsigned int is_10g_phy : 1;
	unsigned int rpu_availble : 1;
	unsigned int only_1g : 1;
	unsigned int has_rdma : 1;
	unsigned int rdma_disabled : 1;
	unsigned int rpu_en : 1;
	unsigned int ncsi_en : 1;
} _PACKED_ALIGN4;

union mbx_fw_cmd_req_data {
	unsigned int data[0];

	struct {
		int whoami;
#define I_AM_DPDK 0xa1
#define I_AM_DRV  0xa2
#define I_AM_PXE  0xa3
	} get_port_ablity;
	int rev2[32 / 4];

	struct {
		unsigned int max_cnt;
		int vf_isolation_disable;
	} vf_max_queue_cnt;

	struct {
		unsigned int addr;
		unsigned int bytes;
	} r_reg;

	struct {
		unsigned int addr;
		unsigned int bytes;
		int data[4];
	} w_reg;

	struct {
		unsigned int addr;
		unsigned int data;
		unsigned int mask;
	} modify_reg;

	struct {
		int cmd;
		int partion;
		int bytes;
		unsigned int ddr_lo;
		unsigned int ddr_hi;
	} eeprom;

	struct {
		unsigned int lanes;
	} ptp;

	struct {
		int up;
	} ifup;

	struct {
		int nr_lane;
#define LLDP_TX_ALL_LANES 0xFF
		int op;
#define LLDP_TX_SET 0x0
#define LLDP_TX_GET 0x1
		int enable;
	} lldp_tx;

	struct {
		int nr_lane;
	} get_lane_st;

	struct {
		int func;
#define PHY_FUN_AN		    0
#define PHY_FUN_LINK_TRAING	    1
#define PHY_FUN_FEC		    2
#define PHY_FUN_SI		    3
#define PHY_FUN_SFP_TX_DISABLE	    4
#define PHY_FUN_PCI_LANE	    5
#define PHY_FUN_PRBS		    6
#define PHY_FUN_SPEED_CHANGE	    7
#define PHY_FUN_AN_RESTART	    8
#define PHY_FUN_LINK_TRAING_RESTART 9
#define PHY_FUN_WOL_SET		    10
#define PHY_FUN_LED_IDENTIFY	    11
#define PHY_FUN_FORCE_SPEED	    12
#define PHY_FUN_SET_SGMII_DUPLEX    13
#define PHY_FUN_FORCE_LINK_ON_CLOSE 14

		int value0;
		int value1;
	} set_phy_fun;

	struct {
		int flag;
	} set_dump;

	struct {
		unsigned int bytes;
		unsigned int bin_phy_lo;
		unsigned int bin_phy_hi;
	} get_dump;

	struct {
		int offset;
		int bytes;

		unsigned int ddr_lo;
		unsigned int ddr_hi;
	} dump_eeprom;

	struct {
		int action;
#define LED_IDENTIFY_INACTIVE 0
#define LED_IDENTIFY_ACTIVE   1
#define LED_IDENTIFY_ON	      2
#define LED_IDENTIFY_OFF      3
	} led_set;

	struct {
		unsigned int adv_speed_mask;
		unsigned int autoneg;
		unsigned int speed;
		unsigned int duplex;
		int nr_lane;
		unsigned int tp_mdix_ctrl;
	} phy_link_set;

	struct {
		unsigned int pause_mode;
		int nr_lane;
	} phy_pause_set;

	struct {
		unsigned int nr_phy;
		unsigned int sfp_i2c_adr;
		unsigned int reg;
		unsigned int cnt;
	} sfp_read;

	struct {
		unsigned int nr_phy;
		unsigned int sfp_i2c_adr;
		unsigned int reg;
		unsigned int val;
	} sfp_write;

	struct { /* set loopback */
		unsigned char loopback_level;
		unsigned char loopback_type;
		unsigned char loopback_force_speed;

		char loopback_force_speed_enable : 1;
	} loopback;

	struct {
		int cmd;
		int arg0;
		int req_bytes;
		int reply_bytes;
		int ddr_lo;
		int ddr_hi;
	} fw_update;

	struct { /* set phy register */
		char phy_interface;
		union {
			char page_num;
			char external_phy_addr;
		};
		int phy_reg_addr;
		int phy_w_data;
		int reg_addr;
		int w_data;
		/* 1 = ignore page_num, use last QSFP */
		char recall_qsfp_page : 1;
	} set_phy_reg;

	struct {
		char phy_interface;
		union {
			char page_num;
			char external_phy_addr;
		};
		int phy_reg_addr;
		char nr_lane;
	} get_phy_reg;

	struct {
		unsigned int nr_lane;
	} phy_statistics;

} _PACKED_ALIGN4;

/* firmware -> driver */
union mbx_fw_cmd_resp_data {
	int data[0];

	struct port_ablity ablity;

	struct {
		unsigned int value[4];
	} r_reg;

	struct {
		unsigned int new_value;
	} modify_reg;

	struct {
#define MBX_SFP_READ_MAX_CNT 32
		char value[MBX_SFP_READ_MAX_CNT];
	} sfp_read;

	struct get_dump_reply {
		int flags;
		int version;
		int bytes;
		int data[4];
	} get_dump;

} _PACKED_ALIGN4;
/* EEPROM byte offsets */
#define SFF_MODULE_ID_OFFSET	0x00
#define SFF_DIAG_SUPPORT_OFFSET 0x5c
#define SFF_MODULE_ID_SFP	0x3
#define SFF_MODULE_ID_QSFP	0xc
#define SFF_MODULE_ID_QSFP_PLUS 0xd
#define SFF_MODULE_ID_QSFP28	0x11

enum MBX_ID;

/**
 * @brief Retrieve firmware-reported port ability.
 *
 * Queries the firmware for port capabilities and fills the provided
 * `port_ablity` structure.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param ablity Pointer to output port ability structure
 * @return 0 on success, negative error code on failure
 */
int mce_fw_get_ablity(struct mce_hw *hw, struct port_ablity *ablity);

/**
 * @brief Get per-lane statistics from firmware/mbox.
 *
 * @param hw Pointer to the MCE hardware structure
 * @return 0 on success, negative error code on failure
 */
int mce_mbx_get_lane_stat(struct mce_hw *hw);

/**
 * @brief Set maximum queue count for VFs via mailbox.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param val Desired max queue count
 * @return 0 on success, negative error code on failure
 */
int mce_mbx_set_vf_max_queue_cnt(struct mce_hw *hw, u32 val);

/**
 * @brief Mailbox ISR for firmware->PF event notifications.
 *
 * Called from IRQ context when firmware signals an event to PF.
 *
 * @param mbx Pointer to mailbox info structure
 * @param event_id Firmware event identifier
 */
void mce_mbx_fw2pf_event_req_isr(struct mce_mbx_info *mbx, int event_id);

/**
 * @brief Mailbox ISR for firmware->PF request completions.
 *
 * @param mbx Pointer to mailbox info structure
 * @param req Pointer to mailbox request data
 */
void mce_mbx_fw2pf_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req);

/**
 * @brief Notify firmware interface up/down.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param up True to notify interface up, false for down
 * @return 0 on success, negative error code on failure
 */
int mce_mbx_fw_ifup(struct mce_hw *hw, bool up);

/**
 * @brief Reset NIC via firmware mailbox.
 *
 * @param hw Pointer to the MCE hardware structure
 * @return 0 on success, negative error code on failure
 */
int mce_mbx_fw_nic_reset(struct mce_hw *hw);

/**
 * @brief Query firmware for supported PHY speeds.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param speed Pointer to output phy_speed_ablity structure
 * @return 0 on success, negative error code on failure
 */
int mce_get_fw_supported_speed(struct mce_hw *hw,
							   struct phy_speed_ablity *speed);

/**
 * @brief Download firmware binary to device.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param fw_path Filesystem path to firmware binary
 * @return 0 on success, negative error code on failure
 */
int mce_download_fw(struct mce_hw *hw, const char *fw_path);

/* read write soc addr */
/**
 * @brief Modify a SOC register atomically (mask/value).
 *
 * @param hw Pointer to the MCE hardware structure
 * @param soc_addr SOC register address
 * @param mask Bitmask of bits to modify
 * @param value New value for masked bits
 * @return 0 on success, negative error code on failure
 */
int mce_soc_modify32(struct mce_hw *hw, int soc_addr, unsigned int mask,
			 int value);

/**
 * @brief Write a 32-bit SOC register via mailbox.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param soc_addr SOC register address
 * @param value Value to write
 * @return 0 on success, negative error code on failure
 */
int mce_soc_iowrite32(struct mce_hw *hw, int soc_addr, int value);

/**
 * @brief Read a 32-bit SOC register via mailbox.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param soc_addr SOC register address
 * @param pvalue Pointer to receive read value
 * @return 0 on success, negative error code on failure
 */
int mce_soc_ioread32(struct mce_hw *hw, int soc_addr, int *pvalue);

/**
 * @brief Read SFP module EEPROM via mailbox/I2C.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param sfp_i2c_addr I2C address of SFP module
 * @param sfp_reg EEPROM register offset
 * @param buf Output buffer to receive data
 * @param bytes Number of bytes to read
 * @return 0 on success, negative error code on failure
 */
int mce_read_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr, int sfp_reg,
			   char *buf, int bytes);

/**
 * @brief Write SFP module EEPROM via mailbox/I2C.
 *
 * @param hw Pointer to the MCE hardware structure
 * @param sfp_i2c_addr I2C address of SFP module
 * @param sfp_reg EEPROM register offset
 * @param val Value to write
 * @return 0 on success, negative error code on failure
 */
int mce_write_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr,
				int sfp_reg, short val);

enum LED_ACTION {
	LED_INACTIVE,
	LED_ACTIVE,
	LED_ACT_ON,
	LED_ACT_OFF,
	LED_ACT_KEEP_BLINK,
};
int mce_fw_set_led(struct mce_hw *hw, enum LED_ACTION action);

enum FEC_TYPE {
	FEC_NONE,
	FEC_BASER,
	FEC_RS,
	FEC_AUTO,
};

enum FORCE_SPEED {
	NO_FORCE_SPEED = 0,
	FORCE_1G = 1,
	FORCE_10G = 2,
	FORCE_25G = 3,
	FORCE_40G = 4,
	FORCE_100G = 5,
	FORCE_100M = 6,
	FORCE_10M = 7,
	FORCE_NUM
};

int mce_mbx_set_phy_func(struct mce_hw *hw, int func, int arg0, int arg1);
int mce_mbx_wol_set(struct mce_hw *hw, bool enable);
int mce_mbx_set_link_restart_autoneg(struct mce_hw *hw);
int mce_mbx_set_fec(struct mce_hw *hw, enum FEC_TYPE fec_type);
int mce_mbx_set_autoneg(struct mce_hw *hw, int enable);
int mce_mbx_set_link_traning_en(struct mce_hw *hw, int enable);
int mce_mbx_set_dump(struct mce_hw *hw, int dump_v);
int mce_mbx_get_dump(struct mce_hw *hw, char*buf, int bytes);
int mce_mbx_dump_eeprom(struct mce_hw *hw, int offset, char *buf, int bytes);
int mce_mbx_set_force_speed(struct mce_hw *hw, enum FORCE_SPEED speed, int duplex);
int mce_mbx_set_duplex(struct mce_hw *hw, int full);
int mce_mbx_ifup_down(struct mce_hw *hw, bool up);
int mce_mbx_set_force_link_on_close(struct mce_hw *hw, bool force);
int mce_mbx_axi_clk_set(struct mce_hw *hw, int clk_mhz);

/**
 * @name PHY/firmware helper APIs
 *
 * Helper functions that wrap mailbox commands for PHY, link, and
 * firmware-level configuration and diagnostics.
 */
/*@{*/

/**
 * @brief Send a generic PHY function request to firmware.
 *
 * @param hw Hardware context
 * @param func PHY function opcode
 * @param arg0 First argument
 * @param arg1 Second argument
 * @return 0 on success, negative errno on error
 */
int mce_mbx_set_phy_func(struct mce_hw *hw, int func, int arg0, int arg1);

/**
 * @brief Enable or disable Wake-on-LAN via firmware.
 */
int mce_mbx_wol_set(struct mce_hw *hw, bool enable);

/**
 * @brief Restart autonegotiation via firmware.
 */
int mce_mbx_set_link_restart_autoneg(struct mce_hw *hw);

/**
 * @brief Configure FEC type via firmware.
 */
int mce_mbx_set_fec(struct mce_hw *hw, enum FEC_TYPE fec_type);

/**
 * @brief Enable or disable autoneg via firmware.
 */
int mce_mbx_set_autoneg(struct mce_hw *hw, int enable);

/**
 * @brief Enable link training via firmware.
 */
int mce_mbx_set_link_traning_en(struct mce_hw *hw, int enable);

/**
 * @brief Set firmware dump control flags.
 */
int mce_mbx_set_dump(struct mce_hw *hw, int dump_v);

/**
 * @brief Retrieve a firmware dump into a buffer.
 */
int mce_mbx_get_dump(struct mce_hw *hw, char*buf, int bytes);

/**
 * @brief Dump EEPROM contents to a buffer.
 */
int mce_mbx_dump_eeprom(struct mce_hw *hw, int offset, char *buf, int bytes);

/**
 * @brief Force a specific link speed via firmware.
 */
int mce_mbx_set_force_speed(struct mce_hw *hw, enum FORCE_SPEED speed, int duplex);

/**
 * @brief Set SGMII duplex mode via firmware.
 */
int mce_mbx_set_duplex(struct mce_hw *hw, int full);

/**
 * @brief Notify firmware interface up/down.
 */
int mce_mbx_ifup_down(struct mce_hw *hw, bool up);

/**
 * @brief Force link active when closing the device.
 */
int mce_mbx_set_force_link_on_close(struct mce_hw *hw, bool force);

/**
 * @brief Set AXI clock frequency via firmware.
 */
int mce_mbx_axi_clk_set(struct mce_hw *hw, int clk_mhz);

/*@}*/

#define MCE_LG_SOC_BASE	       0x3f000000
#define MCE_LG_SOC_VOLTAGE_REG (MCE_LG_SOC_BASE + 0x0)
#define MCE_LG_SOC_PCI_SPEED   (MCE_LG_SOC_BASE + 0x8)
int mce_soc_ioread32_noshm(struct mce_hw *hw, int soc_reg);
int mce_soc_iowrite32_noshm(struct mce_hw *hw, int soc_reg, int v);
#endif /* MCE_FWCHNL_H */
