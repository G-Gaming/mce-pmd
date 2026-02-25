#!/bin/bash

cwd=$(dirname $(readlink -f $0))

echo 1 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
echo 500 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

V=$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages)
if [ "$V" -eq "0" ];then
    echo -e  'please append: \n default_hugepagesz=1G hugepagesz=1G hugepages=1 hugepagesz=2M hugepages=500 \n to bootargs '
fi

if [ -f /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages ];then
    echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
fi
if [ -f /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages ];then
    echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
fi

dpdklib=$(dirname $(find /usr/local/share/dpdk/ -name ".config"))/lib
echo ${dpdklib} > /etc/ld.so.conf.d/dpdk.conf
ldconfig

mkdir /mnt/huge_2M /mnt/huge_1GB 2>/dev/null || true

mount -t hugetlbfs -o  pagesize=2M nodev /mnt/huge_2M
mount -t hugetlbfs -o  pagesize=1GB nodev /mnt/huge_1GB

echo "depmod..."
#depmod

modprobe igb_uio
#insmod /root/igb_uio_custom.ko || modprobe igb_uio
#modprobe rte_kni carrier=on

sysctl -w net.ipv6.conf.all.autoconf=0
sysctl -w net.ipv6.conf.all.disable_ipv6=1

#cpupower frequency-set -g  performance 1>/dev/null || true

echo 0 > /proc/sys/kernel/randomize_va_space


DEV=${1:-"8848:"}

#lspci -n |grep 15b3
#if [ $? -eq 0 ];then
#    DEV="15b3:"
#    exit 0
#fi

#lspci -n |grep  10fb
#if [ $? -eq 0 ];then
#    DEV="8086:10fb"
#    rmmod ixgbe
#fi

echo "bind igb_uio to $DEV"

export PATH=$PATH:/usr/local/share/dpdk/usertools/:$cwd
dpdk-devbind.py -b igb_uio $(lspci -d $DEV | awk '{ print $1}')
