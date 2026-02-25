/* SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _MCE_LOGS_H_
#define _MCE_LOGS_H_
#include <rte_log.h>

extern int mce_logtype_init;
extern int mce_logtype_driver;

#define PMD_INIT_LOG(level, fmt, args...)                             \
	rte_log(RTE_LOG_##level, mce_logtype_init, "%s(): " fmt "\n", \
		__func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#define PMD_DRV_LOG_RAW(level, fmt, args...)                                 \
	rte_log(RTE_LOG_##level, mce_logtype_driver, "%s(): " fmt, __func__, \
		##args)
#define PMD_DRV_LOG(level, fmt, args...) \
	PMD_DRV_LOG_RAW(level, fmt "\n", ##args)

#define PMD_HW_ERR(hw, fmt, args...)                                \
	rte_log(RTE_LOG_ERR, mce_logtype_driver, "[%s] %s(): " fmt, \
		(hw)->device_name, __func__, ##args)

#define PMD_HW_DBG(hw, fmt, args...)                                  \
	rte_log(RTE_LOG_DEBUG, mce_logtype_driver, "[%s] %s(): " fmt, \
		(hw)->device_name, __func__, ##args)

#define PMD_HW_INFO(hw, fmt, args...)                                \
	rte_log(RTE_LOG_INFO, mce_logtype_driver, "[%s] %s(): " fmt, \
		(hw)->device_name, __func__, ##args)

#ifdef RTE_LIBRTE_MCE_DEBUG
#define MCE_PMD_REG_LOG(level, fmt, args...)                          \
	rte_log(RTE_LOG_##level, mce_logtype_init, "%s(): " fmt "\n", \
		__func__, ##args)
#else
#define MCE_PMD_REG_LOG(level, fmt, args...) \
	do {                                 \
	} while (0)
#endif

enum MCE_NET_LOG {
	LOG_MBX_IN_REQ,
	LOG_MBX_REQ_OUT,
	LOG_VECTOR_ALLOC,
	LOG_LINK,
	LOG_MISC_IRQ,
	LOG_PTP_HW,
	LOG_PTP_WORK,
};

#define TRACE() printf("%s: %d\n", __func__, __LINE__)

extern unsigned int mce_loglevel;

#define logd(bit, fmt, args...)                    \
	do {                                       \
		if ((1 << (bit)) & mce_loglevel) { \
			printf(fmt, ##args);       \
		}                                  \
	} while (0)

#define IF_CAT(a, b)	       a##b

#define logd_if(bit, input...) IF_CAT(i, f)((1 << (bit)) & mce_loglevel)##input

#endif /* _MCE_LOHS_H_ */
