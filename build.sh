#!/bin/bash

cwd=$(dirname $(readlink -f $0))

if [ -e "$cwd/.rte_sdk.sh" ];then
    source $cwd/.rte_sdk.sh 
fi

if [ -z "$RTE_SDK" ];then
    if [ -e "$1/ABI_VERSION" ];then
        export RTE_SDK=$1
        shift
    fi
fi

echo "RTE_SDK=$RTE_SDK"

if [ ! -e "$RTE_SDK/drivers/net/mce" ];then
    $cwd/script/link_mce_drv_to_dpdk_core.sh $RTE_SDK debug
    export RTE_SDK=$RTE_SDK
fi

if [ ! -e "$RTE_SDK" ];then
    echo "Usage $0 [rdma-core sourc path] or RTE_SDK env needed"
fi

cd $RTE_SDK/build

ninja -j4 -v $@

ret=$?

cd -

exit $ret

