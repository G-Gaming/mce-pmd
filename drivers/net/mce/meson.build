# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Mucse IC Design Ltd.
#
if host_machine.system() != 'linux'
	euild = false
	reason = 'only supported on Linux'
endif

#if cc.has_function('rte_eth_dev_is_repr', prefix: '#include <rte_ethdev.h>')
  #	cflags += '-DHAVE_RTE_ETH_DEV_IS_REPR'
#endif

subdir('base')
sources = base_sources
sources += files(
		'mce_ethdev.c',
		'mce_ethdev_vf.c',
		'mce_pf.c',
		'mce_rxtx.c',
		'mce_rss.c',
		'mce_intr.c',
		'mce_parse.c',
		'mce_generic_flow.c',
		'mce_fdir_flow.c',
		'mce_switch_flow.c',
		'mce_flow.c',
		'mce_tm.c',
		'mce_vf_representor.c',
		'mce_service.c',
		'mce_route_proxy.c',
                'mce_telemetry.c',
		'mce_mp.c',
		'rte_pmd_mce.c',
)

testpmd_sources = files('mce_testpmd.c')
deps += ['hash']
includes += include_directories('base')
if arch_subdir == 'x86'
	sources += files('mce_rxtx_vec_sse.c')

	#if host_machine.system() =='windows' and cc.get_id() != 'clang'
	#	cflags += ['-fno-asynchronous-unwind-tables']
	#endif
	#sources_avx2 += files('mce_rxtx_vec_avx2.c')
	# compile AVX2 version if either:
	# a. we have AVX supported in minimum instruction set baseline
	# b. it's not minimum instruction set, but supported by compiler
        #
elif arch_subdir == 'arm'
       sources += files('mce_rxtx_vec_neon.c')
else
       sources += files('mce_rxtx_vec_dummy.c')
endif

eaders = files('rte_pmd_mce.h')
