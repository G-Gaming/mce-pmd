# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2017 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_mce.a

CFLAGS += -O3
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS)

#CFLAGS += -DMCE_DEBUG_PCAP
CFLAGS += -I$(SRCDIR)
LIBABIVER := 2

LIBABIVER := 1


# CFLAGS += -DDEBUG_VECTOR
# CFLAGS += -DMCE_DEBUG_RSS
# CFLAGS += -DRX_PERFORMANCE_DEBUG
# CFLAGS += -DMCE_DEBUG_RX_DESC
# CFLAGS += -DMCE_DEBUG_TX_DESC
# CFLAGS += -DRX_PERFORMANCE_DEBUG
# CFLAGS += -DMCE_TM_TC
# CFLAGS += -DMCE_COMMIT_QUEUE
# CFLAGS += -D
# CFLAGS += -D
# CFLAGS += -D
# CFLAGS += -D
# CFLAGS += -D
# CFLAGS += -D
# CFLAGS += -D
# CFLAGS += -D

LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_hash
LDLIBS += -lrte_bus_pci

EXPORT_MAP := rte_pmd_mce_version.map
#
# Add extra flags for base driver files (also known as shared code)
# to disable warnings
#
ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS_BASE_DRIVER = -diag-disable 593
else ifeq ($(CONFIG_RTE_TOOLCHAIN_CLANG),y)
CFLAGS_BASE_DRIVER += -Wno-sign-compare
CFLAGS_BASE_DRIVER += -Wno-unused-value
CFLAGS_BASE_DRIVER += -Wno-unused-parameter
CFLAGS_BASE_DRIVER += -Wno-strict-aliasing
CFLAGS_BASE_DRIVER += -Wno-format
CFLAGS_BASE_DRIVER += -Wno-pointer-to-int-cast
CFLAGS_BASE_DRIVER += -Wno-format-nonliteral
CFLAGS_BASE_DRIVER += -Wno-unused-but-set-variable
CFLAGS_BASE_DRIVER += -Wno-unused-variable
else
CFLAGS_BASE_DRIVER  = -Wno-sign-compare
CFLAGS_BASE_DRIVER += -Wno-unused-value
CFLAGS_BASE_DRIVER += -Wno-unused-parameter
CFLAGS_BASE_DRIVER += -Wno-unused-but-set-variable
CFLAGS_BASE_DRIVER += -Wno-strict-aliasing
CFLAGS_BASE_DRIVER += -Wno-format
CFLAGS_BASE_DRIVER += -Wno-pointer-to-int-cast
CFLAGS_BASE_DRIVER += -Wno-format-nonliteral
CFLAGS_BASE_DRIVER += -Wno-format-security
CFLAGS_BASE_DRIVER += -Wno-unused-variable

ifeq ($(shell test $(GCC_VERSION) -ge 44 && echo 1), 1)
CFLAGS_BASE_DRIVER += -Wno-unused-but-set-variable
endif
endif
CFLAGS_BASE_DRIVER += -Wno-missing-field-initializers

CFLAGS_BASE_DRIVER += -Wno-unused-function

CFLAGS += -Wno-missing-field-initializers
#
# all source are stored in SRCS-y
#
#
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_ethdev_vf.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_pf.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_rxtx.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_rss.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_intr.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_parse.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_generic_flow.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_fdir_flow.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_switch_flow.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_flow.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_tm.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_vf_representor.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_service.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_route_proxy.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_telemetry.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_mp.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += rte_pmd_mce.c

SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_common.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_fdir.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_irq.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_mbx.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_pfvf.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_rpu.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_switch.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_vp_reg.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_fwchnl.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_l2_filter.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_pf2vfchnl.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_profile_mask.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_sched.c
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += base/mce_vf.c
SRCS-$(CONFIG_RTE_LIBRTE_IEEE1588) += base/mce_ptp.c

VPATH += $(SRCDIR)/base

ifeq ($(CONFIG_RTE_ARCH_ARM64),y)
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_rxtx_vec_neon.c
else ifeq ($(CONFIG_RTE_ARCH_PPC_64),y)
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_rxtx_vec_dummy.c
else ifeq ($(CONFIG_RTE_ARCH_X86_64),y)
SRCS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce_rxtx_vec_sse.c
endif

ifeq ($(CONFIG_RTE_LIBRTE_MCE_PMD),y)
ifeq ($(findstring RTE_MACHINE_CPUFLAG_AVX2,$(CFLAGS)),RTE_MACHINE_CPUFLAG_AVX2)
	CC_AVX2_SUPPORT=1
else
	CC_AVX2_SUPPORT=\
	$(shell $(CC) -march=core-avx2 -dM -E - </dev/null 2>&1 | \
	grep -q AVX2 && echo 1)
	ifeq ($(CC_AVX2_SUPPORT), 1)
		ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
			CFLAGS_mce_rxtx_vec_avx2.o += -march=core-avx2
		else
			CFLAGS_mce_rxtx_vec_avx2.o += -mavx2
		endif
	endif
endif
endif

ifeq ($(CC_AVX2_SUPPORT), 1)
# 	SRCS-$(CONFIG_RTE_LIBRTE_MCE_INC_VECTOR) += mce_rxtx_vec_avx2.c
	CFLAGS_mce_rxtx.o += -DCC_AVX2_SUPPORT
endif

# install this header file
SYMLINK-$(CONFIG_RTE_LIBRTE_MCE_PMD)-include := rte_pmd_mce.h

include $(RTE_SDK)/mk/rte.lib.mk
