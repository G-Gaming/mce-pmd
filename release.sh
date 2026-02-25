#!/bin/bash

Usage="<version> [dpdk-core-git-code] [out_dir]"

scripts_dir=$(dirname $(readlink -f $0))

if [ -z "$RTE_SDK" ];then
	if [  -z "$2" ];then
		echo "$Usage"
		exit -1
	else
		export RTE_SDK=$(readlink -f $2)
	fi
fi

FBDIR=${3:-.}
FBDIR=$(readlink -f $FBDIR)
export FBDIR

find $scripts_dir/drivers/net/mce -name "*.o" -exec rm {} \;

mkdir $FBDIR/release/mce-pmd -p 

#support="2.1.0, 2.2.0, 16.02, 16.11, 23.11"

support="2.1.0,2.2.0,16.04,16.07,16.11,17.02,17.05,17.08,17.11,18.02,18.05,18.08,18.11,19.02,19.05,19.08,19.11,20.02,20.05,20.08,20.11,21.02,21.05,21.08,21.11,
	22.03,22.07,22.11,23.03,23.07,23.11,24.03,24.07,24.11,25.03,25.07, 25.11"

RED='\e[1;31m'
NC='\e[0m'
fbprint_e() {
    echo -e "${RED} $1 ${NC}"
}
argc=$#
#fbprint_e "your input is too less ./release.sh ./release.sh phytium"
ARCH=x86_64
if [ -n "$1" ];then
	if [ "$1" == "phytium" ];then
		ARCH=aarch64
	fi
fi

git_commit=$(git rev-parse --short HEAD)

OLD_IFS="$IFS"
IFS=","
array=($support)
IFS="$OLD_IFS"
for version in  ${array[@]}
do
	echo $version -----
	cd $RTE_SDK
	git checkout v$version -f
	cd $FBDIR
	if [ -z "$1" ];then
		${scripts_dir}/flexbuild.sh -j 8  --bit=asic --target=$version --arch=$ARCH --output=patch
	else
		${scripts_dir}/flexbuild.sh -j 8  --bit=asic --target=$version --arch=$ARCH --output=patch --version=$1
	fi
	mkdir $FBDIR/release/mce-pmd/$version -p

	mv $RTE_SDK/0001-net-mce-add-PMD-skeleton.patch $FBDIR/release/mce-pmd/$version 

done
cd $FBDIR/release/
tar -zcf ./mce-pmd-$1-${git_commit}.tar.gz ./mce-pmd

echo "$(readlink -f  ./mce-pmd-$1-${git_commit}.tar.gz  )"
