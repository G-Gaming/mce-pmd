#ifndef _MCE_OSDEP_H_
#define _MCE_OSDEP_H_
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>

#include <rte_bitmap.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>
#include <rte_time.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>

#include "../mce_compat.h"
#include "../mce_logs.h"

#ifndef __maybe_unused
#define __maybe_unused __rte_unused
#endif

#define BITS_PER_LONG (__SIZEOF_LONG__ * 8)
#ifndef GENMASK_U32
#define GENMASK_U32(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#endif
#define _RING_(off)	      ((off) + 0x00000)
#define _SRIOV_(off)	      ((off) + 0x00000)
#define _MSIX_(off)	      ((off) + 0x20000)
#define _MSIX_EX_(off)	      ((off) + (0x20000 + 0x10000))
#define _MAC_(off)	      ((off) + (0x60000 + 0x4000))
#define _DMA_(off)	      ((off) + 0x40000)
#define _NIC_(off)	      ((off) + 0x70000)
#define _ETH_(off)	      ((off) + 0x80000)
#define _ETH_GBL_(off)	      ((off) + 0x80000)
#define _E_L2_F_(off)	      ((off) + 0x90000)
#define _E_SW_F_(off)	      ((off) + 0x90000)
#define _E_ATTR_(off)	      ((off) + 0xa0000)
#define _E_RQA_F_(off)	      ((off) + 0xb0000)
#define _E_RQA_ETYPE_F_(off)  ((off) + 0xb0000)
#define _E_RQA_SYNC_F_(off)   ((off) + 0xc0000)
#define _E_RQA_NTUPLE_F_(off) ((off) + 0xd0000)
#define _E_RSS_(off)	      ((off) + 0xe0000)
#define _E_FDIR_F(off)	      ((off) + 0xf0000)

#define MODIFY_BITFIELD(reg, val, width, offset)                     \
	(reg = (((reg) & (~((((1U << (width)) - 1U)) << (offset)))) | \
	((((val) & ((1U << (width)) - 1U)) << (offset)))))
#define DIV_ROUND_UP(n, d)    (((n) + (d) - 1) / (d))
#define BIT_TO_BYTES(bit)     ((bit) / 8)
#define __iomem

#ifndef ETH_ALEN
#define ETH_ALEN (6)
#endif

#define mb()	  rte_mb()
#define wmb()	  rte_wmb()
#define rmb()	  rte_rmb()

#define DELAY(x)  rte_delay_us(x)
#define udelay(x) DELAY(x)
#define mdelay(x) rte_delay_ms(x)
static inline uint64_t
div_u64_rem(uint64_t dividend, uint32_t divisor, uint32_t *remainder)
{
        *remainder = dividend % divisor;

        return dividend / divisor;
}

static inline uint64_t
div_u64(uint64_t dividend, uint32_t divisor)
{
        uint32_t remainder;

        return div_u64_rem(dividend, divisor, &remainder);
}
#define dev_printf(level, logtype, fmt, ...) \
	rte_log(RTE_LOG_##level, logtype, "rte_mce_pmd: " fmt, ##__VA_ARGS__)
#define dev_err(x, fmt, ...) \
	dev_printf(ERR, mce_logtype_driver, fmt, ##__VA_ARGS__)
#define dev_info(x, fmt, ...) \
	dev_printf(INFO, mce_logtype_driver, fmt, ##__VA_ARGS__)
#define dev_warn(x, fmt, ...) \
	dev_printf(WARNING, mce_logtype_driver, fmt, ##__VA_ARGS__)
#define dev_debug(x, fmt, ...) \
	dev_printf(DEBUG, mce_logtype_driver, fmt, ##__VA_ARGS__)
#define mcevf_hw_to_dev(hw) MCE_HW_T0_DEV(hw)
#define DIV_ROUND_UP(n, d)  (((n) + (d) - 1) / (d))
/* generate variable name with line */
#define _CONCAT_(a, b)	    a##b
#define _CONCAT(a, b)	    _CONCAT_(a, b)
#define BUILD_BUG_ON_SIZE_NOT_EQUAL(obj, sz) \
	typedef char _CONCAT(_v, __LINE__)[(!!(sizeof(obj) != (sz))) ? -1 : 0]
/* Little Endian defines */
#ifndef __le16
#define __le16 u16
#endif
#ifndef __le32
#define __le32 u32
#endif
#ifndef __le64
#define __le64 u64
#endif
/* Little Endian defines */
#ifndef __le16
#define __le16 u16
#endif
#ifndef __le32
#define __le32 u32
#endif
#ifndef __le64
#define __le64 u64
#endif
#ifndef __be16
/* Big Endian defines */
#define __be16 u16
#define __be32 u32
#define __be64 u64
#endif
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#endif /* _MCE_OSDEP_H_ */
