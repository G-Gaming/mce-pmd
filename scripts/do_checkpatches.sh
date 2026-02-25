#!/bin/bash
cwd=$(dirname $(readlink -f $0))

if [ -e "$cwd/../.rte_sdk.sh" ];then
    source $cwd/../.rte_sdk.sh 
fi

if [ -z "$RTE_SDK" ];then
    if [ -e "$1/ABI_VERSION" ];then
        export RTE_SDK=$1
        shift
    fi
fi

if [ ! -e "$RTE_SDK" ];then
    echo "Usage $0 [rdma-core sourc path] or RTE_SDK env needed"
fi

no_format="0"
if [ "$1" == "nofmt" ];then
	no_format="1"
	shift
fi

echo "RTE_SDK=$RTE_SDK"

if [ "$no_format" == "0" ];then
	$cwd/format-srcs.sh
fi

cd $cwd/../
./release.sh 0.0.1 $RTE_SDK
cd -

$RTE_SDK/devtools/checkpatches.sh $cwd/../release/mce-pmd/23.11/0001-net-mce-add-PMD-skeleton.patch