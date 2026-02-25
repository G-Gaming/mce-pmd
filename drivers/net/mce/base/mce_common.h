/**
 * @file mce_common.h
 * @brief MCE Common Definitions and Hardware Initialization
 *
 * This header file provides common definitions, macros, and basic hardware
 * initialization functions used across the MCE driver.
 *
 * @details
 * Provides:
 * - Hardware reset operations
 * - Basic utility functions (hexdump, speed conversion)
 * - Common macros (ARRAY_SIZE, round_up)
 * - Hardware register access definitions
 *
 * @see mce_hw.h for hardware structure definitions
 */

#ifndef _MCE_COMMON_H_
#define _MCE_COMMON_H_
#include "mce_hw.h"

#define MCE_HW_RESET	  (0x70010)
#define MCE_FLOW_ADD	  (1)
#define MCE_FLOW_DEL	  (0)
#define MCE_HW_RESET_DONE (0x70008)

/**
 * @brief Initialize MCE hardware.
 *
 * Performs hardware initialization including reset, clock setup,
 * and basic configuration.
 *
 * @param hw Pointer to the MCE hardware structure
 *
 * @return 0 on successful initialization
 * @return Negative error code on failure
 */
int mce_init_hw(struct mce_hw *hw);

/**
 * @brief Convert speed value to 3-bit encoding.
 *
 * Encodes link speed into 3-bit hardware representation.
 *
 * @param speed Link speed value (e.g., RTE_ETH_LINK_SPEED_1G, RTE_ETH_LINK_SPEED_10G)
 *
 * @return 3-bit encoded speed value
 * @return Negative error if speed is not supported
 */
int speed_zip_to_bit3(int speed);

/**
 * @brief Decode 3-bit speed encoding to speed value.
 *
 * Decodes hardware 3-bit speed encoding back to standard speed value.
 *
 * @param speed_3bit 3-bit encoded speed value
 *
 * @return Link speed value
 * @return Negative error if encoding is invalid
 */
int speed_unzip(int speed_3bit);

/**
 * @brief Dump memory contents in hexadecimal format.
 *
 * Prints memory contents for debugging purposes with formatted hex output.
 *
 * @param msg Message prefix to display before hex dump
 * @param _ptr Pointer to memory to dump
 * @param bytes Number of bytes to dump
 */
void mce_hexdump(const char *msg, void *_ptr, int bytes);
struct mce_pf;

enum mce_udp_tunnel_type {
	MCE_TUNNEL_TYPE_VXLAN,
	MCE_TUNNEL_TYPE_VXLAN_GPE,
	MCE_TUNNEL_TYPE_GENEVE,
	MCE_TUNNEL_TYPE_GPU_C,
	MCE_TUNNEL_TYPE_GPU_U,
	MCE_TUNNEL_TYPE_MPLSoUDP,
	MCE_TUNNEL_TYPE_MAX,
};
int mce_tunnel_udp_port_remove(struct mce_pf *pf,
			       enum mce_udp_tunnel_type tunnel_type,
			       u16 udp_port);
int mce_tunnel_udp_port_add(struct mce_pf *pf,
			    enum mce_udp_tunnel_type tunn_type,
			    u16 udp_port);
#ifndef ARRAY_SIZE
/** @def ARRAY_SIZE(arr) Macro to calculate array size */
#define ARRAY_SIZE(arr) ((int)(sizeof(arr) / sizeof((arr)[0])))
#endif

#ifndef round_up
/** @def round_up(val, align) Macro to round value up to alignment */
#define round_up(val, align) (((val) + (align) - 1) & ~((align) - 1))
#endif

#endif /* _MCE_COMMON_H_ */
