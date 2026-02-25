#!/bin/bash

dpdk_core_path=$(readlink -f $1)
mce_path=$(readlink -f $(dirname $(readlink -f $0))/../)

build_for_debug="--buildtype=release"
messon_build="1"

if [ -z "$dpdk_core_path" ];then
    echo "Usage: $0 <dpdk-core-src-path> [debug]"
    exit -1
fi

if [ "$2" == "debug" ];then
    build_for_debug=" --buildtype=debug  -Dc_args='-O0' "
fi

if [ "$2" == "makefile" ] || [ "$3" == "makefile" ];then
    messon_build="0"
fi

if [ ! -f $dpdk_core_path/meson.build ];then
    echo "can't find  $dpdk_core_path/meson.build"
    exit -1
fi

echo "dpdk-core: $dpdk_core_path"
echo "mce_pmd: $mce_path"

dpdk_core_mce="$dpdk_core_path/drivers/net/mce"

echo "link $dpdk_core_mce -> $mce_path/drivers/net/mce"
if [ ! -e ${dpdk_core_mce} ];then
    echo "ln -s  \"$mce_path/drivers/net/mce\" $dpdk_core_mce"
    rm  $dpdk_core_mce 2>/dev/null
    ln -s  "$mce_path/drivers/net/mce" $dpdk_core_mce
fi

abs_mce=$(readlink -f $dpdk_core_mce)
if [ "$abs_mce" != "$mce_path/drivers/net/mce" ];then
    echo "del $dpdk_core_mce => $abs_mce "
    rm $dpdk_core_mce
    echo "ln -s  \"$mce_path/drivers/net/mce\" $dpdk_core_mce"
    ln -s  "$mce_path/drivers/net/mce" $dpdk_core_mce
fi

if [ -f ${dpdk_core_path}drivers/net/Makefile ];then
    echo "append mce/ to ${dpdk_core_path}drivers/net/Makefile"
    c=$(grep CONFIG_RTE_LIBRTE_MCE_PMD ${dpdk_core_path}/drivers/net/Makefile | wc -l)
    if [ "c" == "0" ];then
        sed -i '11i DIRS-$(CONFIG_RTE_LIBRTE_MCE_PMD) += mce' ${dpdk_core_path}/drivers/net/Makefile
    fi
fi

if [ -f ${dpdk_core_path}/drivers/net/meson.build ];then
    echo "append mce/ to ${dpdk_core_path}/drivers/net/meson.build"
    c=$(grep mce ${dpdk_core_path}/drivers/net/meson.build | wc -l)
    if [ "$c" == "0" ];then
        line=$(awk '/i40e/ {print NR}' ${dpdk_core_path}/drivers/net/meson.build)
        sed -i "${line}i       'mce',"  ${dpdk_core_path}/drivers/net/meson.build
    fi
fi

if [ -f ${dpdk_core_path}/config/common_base ];then
    echo "append CONFIG_RTE_LIBRTE_MCE_PMD to ${dpdk_core_path}/config/common_base"
    c=$(grep CONFIG_RTE_LIBRTE_MCE_PMD ${dpdk_core_path}/config/common_base|wc -l)
    if [ "c" == "0" ];then
        sed -i '2000i CONFIG_RTE_LIBRTE_MCE_PMD=y' ${dpdk_core_path}/config/common_base
    fi
fi

if [ -f ${dpdk_core_path}/mk/rte.app.mk ];then
    echo "append CONFIG_RTE_LIBRTE_MCE_PMD to ${dpdk_core_path}/mk/rte.app.mk"
    c=$(grep CONFIG_RTE_LIBRTE_MCE_PMD ${dpdk_core_path}/mk/rte.app.mk | wc -l)
    if [ "c" == "0" ];then
        line=$(awk '/CONFIG_RTE_LIBRTE_ICE_PMD/ {print NR}' ${dpdk_core_path}/mk/rte.app.mk)
        sed -i "${line}i _LDLIBS-$(CONFIG_RTE_LIBRTE_MCE_PMD)        += -lrte_pmd_mce" ${dpdk_core_path}/mk/rte.app.mk
    fi
fi


if [ -f ${dpdk_core_path}/config/common_base ];then
    echo "disable compile other nic drivers.."
    sed -i 's/CONFIG_RTE_LIBRTE_ICE_PMD=y/CONFIG_RTE_LIBRTE_ICE_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_ATLANTIC_PMD=y/CONFIG_RTE_LIBRTE_ATLANTIC_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_BNXT_PMD=y/CONFIG_RTE_LIBRTE_BNXT_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_CXGBE_PMD=y/CONFIG_RTE_LIBRTE_CXGBE_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_ENA_PMD=y/CONFIG_RTE_LIBRTE_ENA_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_ENIC_PMD=y/CONFIG_RTE_LIBRTE_ENIC_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_EM_PMD=y/CONFIG_RTE_LIBRTE_EM_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_IGB_PMD=y/CONFIG_RTE_LIBRTE_IGB_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_IONIC_PMD=y/CONFIG_RTE_LIBRTE_IONIC_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_IXGBE_PMD=y/CONFIG_RTE_LIBRTE_IXGBE_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_I40E_PMD=y/CONFIG_RTE_LIBRTE_I40E_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_FM10K_PMD=y/CONFIG_RTE_LIBRTE_FM10K_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_ICE_PMD=y/CONFIG_RTE_LIBRTE_ICE_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_IAVF_PMD=y/CONFIG_RTE_LIBRTE_IAVF_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_QEDE_PMD=y/CONFIG_RTE_LIBRTE_QEDE_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_SFC_EFX_PMD=y/CONFIG_RTE_LIBRTE_SFC_EFX_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_THUNDERX_NICVF_PMD=y/CONFIG_RTE_LIBRTE_THUNDERX_NICVF_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_LIO_PMD=y/CONFIG_RTE_LIBRTE_LIO_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_OCTEONTX_PMD=y/CONFIG_RTE_LIBRTE_OCTEONTX_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_OCTEONTX2_PMD=y/CONFIG_RTE_LIBRTE_OCTEONTX2_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_VMXNET3_PMD=y/CONFIG_RTE_LIBRTE_VMXNET3_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_ARK_PMD=y/CONFIG_RTE_LIBRTE_ARK_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_APP_TEST=y/CONFIG_RTE_APP_TEST=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_PMD_NITROX=y/CONFIG_RTE_LIBRTE_PMD_NITROX=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_SECURITY=y/CONFIG_RTE_LIBRTE_SECURITY=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_COMPRESSDEV=y/CONFIG_RTE_LIBRTE_COMPRESSDEV=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_PMD_OCTEONTX2_DMA_RAWDEV=y/CONFIG_RTE_LIBRTE_PMD_OCTEONTX2_DMA_RAWDEV=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_PMD_OCTEONTX2_EP_RAWDEV=y/CONFIG_RTE_LIBRTE_PMD_OCTEONTX2_EP_RAWDEV=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_OCTEONTX_MEMPOOL=y/CONFIG_RTE_LIBRTE_OCTEONTX_MEMPOOL=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_OCTEONTX2_MEMPOOL=y/CONFIG_RTE_LIBRTE_OCTEONTX2_MEMPOOL=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_COMMON_DPAAX=y/CONFIG_RTE_LIBRTE_COMMON_DPAAX=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_DPAA_BUS=y/CONFIG_RTE_LIBRTE_DPAA_BUS=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_DPAA_MEMPOLL=y/CONFIG_RTE_LIBRTE_DPAA_MEMPOLL=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_DPAA2_MEMPOLL=y/CONFIG_RTE_LIBRTE_DPAA2_MEMPOLL=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_DPAA_PMD=y/CONFIG_RTE_LIBRTE_DPAA_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_DPAA2_PMD=y/CONFIG_RTE_LIBRTE_DPAA2_PMD=n/' ${dpdk_core_path}/config/common_base
    # sed -i 's/CONFIG_RTE_LIBRTE_VMBUS=y/CONFIG_RTE_LIBRTE_VMBUS=n/' ${dpdk_core_path}/config/common_base
    # sed -i 's/CONFIG_RTE_LIBRTE_VMBUS=y/CONFIG_RTE_LIBRTE_VMBUS=n/' ${dpdk_core_path}/config/common_linux
    # sed -i 's/CONFIG_RTE_LIBRTE_VDEV_BUS=y/CONFIG_RTE_LIBRTE_VDEV_BUS=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_VDEV_NETVSC_PMD=y/CONFIG_RTE_LIBRTE_VDEV_NETVSC_PMD=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_FSLMC_BUS=y/CONFIG_RTE_LIBRTE_FSLMC_BUS=n/' ${dpdk_core_path}/config/common_base
    sed -i 's/CONFIG_RTE_LIBRTE_FSLMC_BUS=y/CONFIG_RTE_LIBRTE_FSLMC_BUS=n/' ${dpdk_core_path}/config/common_linux
fi

if [ -f ${dpdk_core_path}/drivers/net/meson.build ];then
    sed -i "s/'nfb'/#'nfb'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'mlx4'/#'mlx4'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'mlx5'/#'mlx5'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'ixgbe'/#'ixgbe'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'iavf'/#'iavf'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'ice'/#'ice'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'i40e'/#'i40e'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'dpaa'/#'dpaa'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'dpaa2'/#'dpaa2'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'bnx2x'/#'bnx2x'/" ${dpdk_core_path}/drivers/net/meson.build
    sed -i "s/'bnxt'/#'bnxt'/" ${dpdk_core_path}/drivers/net/meson.build

fi
sed -i "s%'common/mlx5'%#'common/mlx5'%" ${dpdk_core_path}/drivers/meson.build


meson_build(){
    if [ -f ${dpdk_core_path}/meson.build ];then
        disabe_driver="-Ddisable_drivers=net/ipn3ke,net/mvneta,crypto/mlx5,crypto/ipsec_mb,crypto/mvsam,crypto/uadk,compress/mlx5,regex/mlx5,vdpa/mlx5,net/dpaa,net/dpaa2,net/bnx2x,net/bnxt,net/i40e,net/iavf,net/ixgbe,net/mlx4,net/mlx5"
        disabe_driver="$disabe_driver,event/dpaa,event/dpaa2,net/sfc/,net/enetc,net/e1000,net/enetfec,net/cxgbe,net/cpfl,net/axgbe,net/ark,net/txgbe,net/pfe"
        disabe_driver="$disabe_driver,common/dpaax,common/octeontx,common/qat,bus/ifpga,common/sfc_efx,common/cnxk,crypto/bcmfs,crypto/octeontx,crypto/nitrox"
        meson_arg="setup build  -Dtests=false    $build_for_debug "

        HAS_ENABLE_APPS=$(grep  "get_option('enable_apps')" ${dpdk_core_path}/app/meson.build  | wc -l)
        meson_app=""
        if [ "$HAS_ENABLE_APPS" != "0" ];then
            meson_app="-Denable_apps"
        else
            meson_app="-Dexamples"
        fi
        meson_app="${meson_app}=test-pmd,pdump,proc-info"
        
        echo ""
        echo "meson  $meson_arg $disabe_driver $meson_app"
        echo ""


        meson $meson_arg $disabe_driver $meson_app
        cd ..
        echo "append done. now you can build testpmd use bellow commands"
        echo "  cd $dpdk_core_path/build"
        #echo "  export EXTRA_CFLAGS='-g'"
        echo "  ninja -j4 -v"
        echo "  $dpdk_core_path/build/app/dpdk-testpmd "

    fi
}

makefile_build() {
    if [ -f ${dpdk_core_path}/Makefile ];then
        # makefile
        make config T=x86_64-native-linux-gcc
        cd ..
        echo "append done. now you can build testpmd use bellow commands"
        echo "  cd $dpdk_core_path/build"
        echo "  export EXTRA_CFLAGS='-g'"
        echo "  make -j4"
    fi
}

export RTE_SDK=$dpdk_core_path

echo "export RTE_SDK=$dpdk_core_path" > "$mce_path/.rte_sdk.sh"

is_x86=$(lscpu |grep Architecture |grep x86 | wc -l)
if [ "$is_x86" == "1" ];then
    cd $dpdk_core_path
    rm -rf $dpdk_core_path/build 2> /dev/null

    if [ "$messon_build" == "0" ];then
        makefile_build
        exit $?
    fi

    if [ -f ${dpdk_core_path}/meson.build ];then
        meson_build
    else
        makefile_build
    fi
fi
