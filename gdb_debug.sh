#!/bin/bash
cwd=$(dirname $(readlink -f $0))

if [ -e $cwd/.rte_sdk.sh  ];then
	source $cwd/.rte_sdk.sh
fi

if [ "$1" == "run" ];then
    shift
    args=" -- -i "
    if [ ! -z "$1" ];then
        args="$@"
    fi
    $RTE_SDK/build/app/dpdk-testpmd -- -i $@
    exit 0
fi

if [ "$1" == "axi" ];then
    shift
    $RTE_SDK/build/app/dpdk-testpmd -a 01:00.0,axi_mhz=500 -- -i
    exit 0
fi

if [ "$1" == "fw" ];then
    shift
    $RTE_SDK/build/app/dpdk-testpmd -a b3:00.0,fw_path=$1 
    exit 0
fi

if [ "$1" == "gdb" ];then
    shift
    kill -TRAP  $(pidof dpdk-testpmd) 
    #kill -SIGINT $(pidof dpdk-testpmd)
    exit 0
fi

if [ "$1" == "attach" ];then
    shift

    pid=$(pidof dpdk-testpmd)

    gdb -q -tui -ex "set confirm off" -ex "attach $pid" -ex "symbol-file $RTE_SDK/build/app/dpdk-testpmd" 
    exit 0
fi


gdb -q -tui -ex "file $RTE_SDK/build/app/dpdk-testpmd" -ex "source $cwd/gdb.init"
