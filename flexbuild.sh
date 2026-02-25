#!/bin/bash

#set default env
JOBS=4
ARCH=x86_64
OUTPUT="bin"

FLEXBUILD_DIR=$(dirname $(readlink -f $0))

if [ -z "$FBDIR" ];then
	FBDIR=$FLEXBUILD_DIR
fi

NIC_OFF=0x100000
QUEUES_PEER_FUN=8
FPGA=1
PV=1
VERBO=
DPDK=v20.02
DEFAULT_DPDK_TARGET="x86_64-native-linuxapp-gcc"
DPDK_BUILD_ARG=()
DPDK_DRV_SUPPORT=0
DPDK_TARGET=0
BUILD_KERNEL_MODULE=false
KERNEL_PATH=" "
LONGSON_FTP_URL="http://ftp.loongnix.org/toolchain/gcc/release/"
LONGSON_MIPSEL64_TOOL="cross-gcc-4.9.3-n64-loongson-rc6.1.tar.bz2"
LONGSON_MIPS_TOOL="mips-loongson-gcc4.9-2019.06-29-linux-gnu.tar.gz"
LONGSON_MIPSEL_TOOL=
PATCH_VERSION=""
DEFAULT_CROSS_TOOL_PATH=/opt/
DESTDIR="/usr/local/"
usage_help () {
cat <<EOF
 -j, --job compile jobs num
 -a, --arch required option cpu_arch such as loongson-3A R4 -- mipsel64 normal intel --- x86_64
 -b, --bit  required option the fpag bit feature-version
 -t, --target required option with the dpdk version for compile
 -m, --mode optional option the driver feature mode
	Ex: rx-off,io,no-tx-irq,no-rx-irq,skbdump,hi_dma,tx-off,rx-off,tx-debug,rx-debug,no-pf1
 -o, --output bin,patch, build output file patch or compile with dpdk output executable binary

command most used example:
  flexbuild.sh -j 8 --arch=x86_64 --bit=uv3p --target=20.02
  flexbuild.sh -j 8 --arch=x86_64 --bit=uv3p --target=20.02 --output=patch
  flexbuild.sh -j 8 --arch=x86_64 --bit=uv440 --target=20.02
  flexbuild.sh -j 8 --arch=x86_64 --bit=uv440 --target=20.02 --output=patch
  flexbuild.sh -j 8 --arch=aarch64 --bit=uv3p --target=18.05
  flexbuild.sh -j 8 --arch=mipsel64 --bit=uv3p --target=20.02
  flexbuild.sh -j 8 --mode="tx-debug,rx-debug" --arch=x86_64 --bit=uv3p --target=20.02
  flexbuild.sh -j 8 --mode="2pf" --bit=uv440 --target=20.02
EOF
   exit
}
#set -e #"Exit immediately if a simple command exits with a non-zero status."
#set -x
#set -xv
hostarch=`uname -m`
red='\e[0;41m'
RED='\e[1;31m'
GREEN='\e[1;32m'
green='\e[0;32m'
yellow='\e[5;43m'
YELLOW='\e[1;33m'
NC='\e[0m'

username=`whoami`
hostarch=`uname -m`

fbprint_e() {
    echo -e "${RED} $1 ${NC}"
}

fbprint_n() {
    echo -e "${green} $1 ${NC}"
}

fbprint_w() {
    echo -e "${YELLOW} $1 ${NC}"
}

fbprint_d() {
    echo -e "${GREEN} $@    [Done] ${NC}"
}

calc_dpdk_version_num() {
	log=$1
	year=`echo $log |awk -F "." '{print $1}'`
	mon=`echo $log |awk -F "." '{print int($2)}'|sed -r 's/([^0-9])0([1-9])/\1\2/g'`
	#ver_min=
	#ver_release=
	version_num=$((year << 24)) #$((mon << 16))
	version_num=`expr $version_num + $((mon << 16))`
	echo $version_num
	#return $version_num
}
get_dpdk_release_version() {
	#####VERSION add to v19.02 so change version get method
	year=`cat $RTE_SDK/lib/librte_eal/common/include/rte_version.h|grep "define RTE_VER_YEAR"|awk -F ' ' '{print $3}'`
	mon=`cat $RTE_SDK/lib/librte_eal/common/include/rte_version.h|grep "define RTE_VER_MON"|awk -F ' ' '{print $3}'`
	if [ -z "$year" ];then
		year=`cat $RTE_SDK/VERSION|awk -F "." '{print $1}'`
		mon=`cat $RTE_SDK/VERSION|awk -F "." '{print int($2)}'`
	fi
	echo $year.$mon

}
install_dpdk_kmod() {
	if test -e "$RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko"
	then
		mkdir -p /usr/lib/modules/`uname -r`/extra/dpdk
		cp -rf $RTE_SDK/$RTE_TARGET/kmod/* /usr/lib/modules/`uname -r`/extra/dpdk
		mkdir -p /usr/local/lib/modules/`uname -r `/extra/dpdk
                cp -rf $RTE_SDK/$RTE_TARGET/kmod/* /usr/local/lib/modules/`uname -r`/extra/dpdk
	fi
}

patch_for_fireware_type() {
	cd $RTE_SDK
	if [ "$DESTARCH" == "aarch64" ];then
		sed -i 17a\ "#define PHYTIUM_SUPPORT\n" $RTE_SDK/drivers/net/mce/mce.h
	fi

	if [ -n "$PATCH_VERSION" ];then
		sed -i 18a\ "#define PATCH_RELEASE_VERSION \"$PATCH_VERSION\"\n" $RTE_SDK/drivers/net/mce/mce.h
	fi
}

generate_dpdk_patch() {
	cd $RTE_SDK
	git add $RTE_SDK/drivers/net/mce
	git add $RTE_SDK/drivers/net/meson.build
        git add $RTE_SDK/config/common_linux*
        git add $RTE_SDK/config/common_base
        git add $RTE_SDK/drivers/net/Makefile
        git add $RTE_SDK/mk/rte.app.mk
        git add $RTE_SDK/config/rte_config.h


	git commit -m "net/mce: add PMD skeleton

Signed-off-by: Wenbo Cao <caowenbo@mucse.com>"

	git format-patch -1
	git reset --hard  HEAD^

}
check_build_toolchain() {
	##############mips64el little-end 64bit#################
	##############    mips big-end 32bit   #################
	############## mipsel little-end 32bit #################

	if [ $DESTARCH = mipsel64 ] && [ $hostarch = x86_64 ]; then
		if [ ! $CROSS -z ]; then
			fbprint_w "Cross Compile Tool Has Been set CROSS=$CROSS"
		fi
		if ! which mips64el-loongson-linux-gcc 1> /dev/null; then
			DEFAULT_CROSS_TOOL=/opt/cross-gcc-4.9.3-n64-loongson-rc6.1/setenv.sh
			if [ -f $DEFAULT_CROSS_TOOL ]; then
				source $DEFAULT_CROSS_TOOL
				export CROSS=/opt/cross-gcc-4.9.3-n64-loongson-rc6.1/usr/bin/mips64el-loongson-linux-
			else
				wget $LONGSON_FTP_URL/$LONGSON_MIPSEL64_TOOL --directory-prefix /opt/
				cd /opt/
				tar -xf $LONGSON_MIPSEL64_TOOL
				source ./cross-gcc-4.9.3-n64-loongson-rc6.1/setenv.sh
				export CROSS=/opt/cross-gcc-4.9.3-n64-loongson-rc6.1/usr/bin/mips64el-loongson-linux-
				rm $LONGSON_MIPSEL64_TOOL
				cd $FBDIR
			fi
		else
			cross_gcc_path=`which mips64el-loongson-linux-gcc|awk -F "mips64el-loongson-linux-gcc" '{print $1}'`
			export CROSS=$cross_gcc_path/mips64el-loongson-linux-
			fbprint_d "CROSS $CROSS"
		fi

		fbprint_d "Mipsel64 CrossCompile tool Install"
	fi
	if [ $DESTARCH = mips ] && [ $hostarch = x86_64 ]; then
		if [ ! $CROSS -z ]; then
			fbprint_w "Cross Compile Tool Has Been set CROSS=$CROSS"
			return
		fi
		if ! which mips-linux-gnu-gcc 1> /dev/null; then
			wget $LONGSON_FTP_URL/$LONGSON_MIPSEL64_TOOL --directory-prefix /opt/
			cd /opt/
			tar -xf $LONGSON_FTP_URL/$LONGSON_MIPSEL64_TOOL
			export CROSS=/opt/mips-loongson-gcc4.9-linux-gnu/2019.06-29/bin/mips-linux-gnu-
			cd $FBDIR
		fi
		fbprint_d "Mips CrossCompile tool Install"
	fi
}

[ $# -eq 0 ] && usage_help && exit

[ $# -eq 0 ] && usage && exit
DESTARCH=$ARCH

[ -z "$FBDIR" ] && fbprint_e "please setup env by source setup.env" && exit
[ ! -d "$FBDIR" ] && fbprint_e "FBDIR $FBDIR isn't exist :( this isn't possible" && exit

ARGS=`getopt -a -o j:a:b:m:t:o:h:v -l job:,arch:,bit:,mode:,target:,output:,help,version: -- "$@"`
[ $? -ne 0 ] && usage
eval set -- "${ARGS}"
while true
do
        case "$1" in
        -j|--job)
                JOBS=$2 && echo JOBS: $JOBS
                shift;;
        -a|--arch)
                DESTARCH=$(echo $2 | cut -d: -f1)
                echo "DESTARCH: $DESTARCH"
                shift;;
        -b|--bit)
                BIT=$2 && echo "BIT: $BIT"
                shift;;
        -m|--mode)
		MODE=$2 && echo "MODE: $MODE"
                shift;;
	-t|--target)
		DPDK_VERSION=$2 && echo "DPDK_VERSION: $DPDK_VERSION"
		shift;;
	-o|--output)
		OUTPUT=$2 && echo "OUTPUT MODE : $OUTPUT"
		shift;;
	-h|--help)
		usage_help;;
	-v|--version)
		PATCH_VERSION=$2 && echo "PATCH_VERSION: $PATCH_VERSION"
		shift;;
        --)
                shift
                break;;
        esac
shift
done

LD_IFS="$IFS"
IFS=","
args=($MODE)
IFS="$OLD_IFS"

for arg in ${args[@]}
do
	case $arg in
	rx-off*)
	CFLAGS+=" -DRX_HW_OFFLOADING  "
	;;
	io)
	CFLAGS+=" -DIO_PRINT=1 "
	;;
	no-tx-irq)
	CFLAGS+=" -DDISABLE_TX_IRQ=1 "
	;;
	no-rx-irq)
	CFLAGS+=" -DDISABLE_RX_IRQ=1 "
	;;
	skbdump)
	CFLAGS+=" -DSKB_DUMP=1  "
	;;
	hi_dma)
	CFLAGS+=" -DENABLE_64BIT_DMA  "
	;;
	tx-off*)
	CFLAGS+=" -DTX_HW_OFFLOADING  "
	;;
	rx-off*)
	CFLAGS+=" -DRX_HW_OFFLOADING  "
	;;
	tx-debug*)
	CFLAGS+=" -DTX_DEBUG=1  "
	;;
	rx-debug*)
	CFLAGS+=" -DRX_DEBUG=1  "
	;;
	no-pf1)
	CFLAGS+=" -DDISABLE_PF1=1  "
	;;
	2pf)
	CFLAGS+=" -DHAS_2PF "
	;;
	no-pf0)
	CFLAGS+=" -DDISABLE_PF0=1 "
	;;
	v|V)
	VERBO="V=1"
	;;
	esac
done

fbprint_n "BIT VERSION $CFLAGS"

if [ -z "$BIT" ];then
    fbprint_e "We must set BIT version, please input <--bit>"
    usage_help
    exit -1
fi

if [ -z "$DPDK_VERSION" ];then
    fbprint_e "We must set DPDK version, please input <--target>"
    usage_help
    exit -1
fi

case $BIT in
	uv3p)
	NIC_OFF=0x0      && QUEUES_PEER_FUN=4 && FPGA=1 CFLAGS+=" -DNIC_BAR4 -DTSRN10_UV3P"
	;;
	asic)
	NIC_OFF=0x0      && QUEUES_PEER_FUN=1 && FPGA=0 && CFLAGS+=" -DDISABLE_PF1=1 "
	;;
	*uv440)
	NIC_OFF=0x0	 && QUEUES_PEER_FUN=4 && FPGA=1 && CFLAGS+=" -DTSRN10_UV440 -DNIC_BAR4 -DHAS_2PF"
	;;
esac
###################check if dpdk-version we support###################################################
infos=`ls $FBDIR/patchs -lh`
OLD_IFS="$IFS"
IFS="\t"
array=($infos)
IFS="$OLD_IFS"
for info in ${array[@]}
do
	version=`echo $info |awk -F " " '{print $5}'`
	if [ ! $version == " " ];then
		if [ "${version}" == $DPDK_VERSION ];then
			DPDK_DRV_SUPPORT=true
			break
		fi
	fi

	version=`echo $info |awk -F " " '{print $9}'`
	if [ ! $version == " " ];then
		if [ "${version}" == $DPDK_VERSION ];then
			DPDK_DRV_SUPPORT=true
			break
		fi
	fi
done

DPDK_DRV_SUPPORT=true
[ $DPDK_DRV_SUPPORT != true ] && fbprint_e "we don't support the DPDK $DPDK_VERSION for now" && exit

fbprint_n  "nic_off $NIC_OFF queu_peer_func $QUEUES_PEER_FUN fpga $FPGA"
######if RTE_SDK no't set and /usr/local/share/dpdk/ is not exist##########################
#######download dpdk source-code to compile it############################################
#1. if /usr/local/share/dpdk/ is exist we don't need to compile dpdk-core source code
#Just add EXTRA_CFLAGS EXTRA_LDFLAGS to compile the drv l2fwd,l3fwd and so on
#2. if RTE_SDK exist we priority to compile dr and dpdk-core don't considet the /usr/local/share/dpdk/
#3. if only exist /usr/local/share/dpdk/ try to compile drv code ,if we can't compile success
if [ -z "$RTE_SDK" ]; then
	fbprint_e "RTE_SDK isn't set we must use it for find dpdk-core\n you can cd to the dpdk-path export RTE_SDK=\`pwd\`"
	exit
fi

#1.Cross Compile Tool
[ "$DESTARCH" != $hostarch ] && check_build_toolchain

if [ "$DESTARCH" == "x86_64" ]; then
	DPDK_TARGET="x86_64-native-linuxapp-gcc"
elif [ "$DESTARCH" == "mipsel64" ]; then
	DPDK_TARGET="loongson-3A2K-linuxapp-gcc"
elif [ "$DESTARCH" == "aarch64" ] ; then
	DPDK_TARGET="arm64-armv8a-linux-gcc"
else
	fbprint_e "DESTARCH $DESTARCH is not support"
	exit
fi

DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=DESTDIR=$DESTDIR
DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_TSRN10_PMD=y
if  [  -z ${RTE_KERNELDIR}  ]; then
	KERNEL_PATH=`realpath /lib/modules/$(uname -r)/build`
	echo path $KERNEL_PATH
	if [ -d $KERNEL_PATH ] && [ $(uname -m) = "$DESTARCH" ]; then
		BUILD_KERNEL_MODULE=true
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_EAL_IGB_UIO=y
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_KNI=y
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_PMD_KNI=y
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_KNI_KMOD=y

	else
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_EAL_IGB_UIO=n
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_KNI=n
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_PMD_KNI=n
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_KNI_KMOD=n
	fi
else
	if [ -d ${RTE_KERNELDIR}  ]; then
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_EAL_IGB_UIO=y
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_PMD_KNI=y
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_KNI=y
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_KNI_KMOD=y
	else
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_EAL_IGB_UIO=n
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_PMD_KNI=n
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_LIBRTE_KNI=n
		DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=CONFIG_RTE_KNI_KMOD=n
	fi
fi

#####################DPDK_DIVER COMPILE###############################

if [ -f $RTE_SDK/lib/librte_eal/rte_eal_version.map  ]; then
	dpdk_core_status=`cat $RTE_SDK/lib/librte_eal/rte_eal_version.map | grep $DPDK_VERSION`
else
	if [ ! -f $RTE_SDK/lib/librte_eal/linuxapp/eal/rte_eal_version.map ];then
		dpdk_core_status=`cat $RTE_SDK/lib/librte_eal/linuxapp/eal/rte_eal_version.map | grep $DPDK_VERSION`
	fi
fi
#dpdk_core_version=`get_dpdk_release_version`

#fbprint_d "Check DPDK-CORE Version and Compile Target Version"
#[ `calc_dpdk_version_num $DPDK_VERSION` != `calc_dpdk_version_num $dpdk_core_version` ] && fbprint_e "the dpdk-core isn't $DPDK_VERSION is $dpdk_core_version" && exit
#fbprint_d "Version Match DPDK-core $dpdk_core_version DPDK-BUILD-TARGET $DPDK_VERSION"

[ -L $RTE_SDK/drivers/net/mce ] && rm -rf $RTE_SDK/drivers/net/mce
mkdir -p $RTE_SDK/drivers/net/mce
cp  $FBDIR/drivers/net/mce/* $RTE_SDK/drivers/net/mce -rf
cur_version=`calc_dpdk_version_num $DPDK_VERSION`
match_version=`calc_dpdk_version_num 20.11`
modify_makefile_ver=`calc_dpdk_version_num 19.11`
if [ $cur_version -gt $match_version ];then
	rm $RTE_SDK/drivers/net/mce/Makefile -rf
else
	if [ $cur_version -lt $modify_makefile_ver ];then
		PLAFORM_DEPDIRS_TO_LDLIBS=`calc_dpdk_version_num 17.11`
		if [ $cur_version -lt $PLAFORM_DEPDIRS_TO_LDLIBS ];then
			sed -i 17a\ "LIBABIVER := 1\n" $RTE_SDK/drivers/net/mce/Makefile
		else
			sed -i 17a\ "LIBABIVER := 2\n" $RTE_SDK/drivers/net/mce/Makefile
		fi
	fi
fi

match_version=`calc_dpdk_version_num 18.05`
if [ $cur_version -lt $match_version ];then
       rm $RTE_SDK/drivers/net/mce/meson.build -rf
fi

match_version=`calc_dpdk_version_num 20.08`
highst_version=`calc_dpdk_version_num 23.11`
if [ $cur_version -gt $match_version ] && [ $cur_version -lt $highst_version ];then
	echo "DPDK_21 {
        local: *;
};" > $RTE_SDK/drivers/net/mce/version.map
fi

echo $cur_version $match_version

git_repo=`git rev-parse --is-inside-work-tree`
if [ "$git_repo" == "true" ];then
	git_method="apply"
	echo $git_repo
else
	echo $git_repo
	git_method="apply"
fi
if [ $DPDK_TARGET == x86_64-native-linuxapp-gcc ]; then
	cd $RTE_SDK
	path_stat=`cat "$RTE_SDK"/drivers/net/Makefile|grep "CONFIG_RTE_LIBRTE_TSRN10_PMD"`
	if [ -z "$path_stat" ]; then
		if [ "$git_method" == "am" ]; then
			git am --abort
		else
			#git reset --hard
			echo 11
		fi
		git $git_method $FBDIR/patchs/$DPDK_VERSION/0001-net-mce-add-PMD-skeleton.patch
	fi
	cd $FBDIR
elif [ $DPDK_TARGET == arm64-armv8a-linux-gcc ]; then
	cd $RTE_SDK

	path_stat=`cat "$RTE_SDK"/drivers/net/Makefile|grep "CONFIG_RTE_LIBRTE_TSRN10_PMD"`
	if [ -z "$path_stat" ]; then
		if [ "$git_method" == "am" ]; then
			git am --abort
		else
			git reset --hard
		fi
		git $git_method $FBDIR/patchs/$DPDK_VERSION/0001-net-mce-add-PMD-skeleton.patch
	fi
	cd $FBDIR
elif [ $DPDK_TARGET == loongson-3A2K-linuxapp-gcc ]; then
	######For longson mipsel gcc will compile this driver err#########
	cd $RTE_SDK/
	path_stat=`cat $RTE_SDK/mk/rte.app.mk|grep "CONFIG_RTE_LIBRTE_TSRN10_PMD"`
	if [ -z "$path_stat" ]; then
		if [ "$git_method" == "am" ]; then
			git am --abort
		else
			git reset --hard
		fi
		git $git_method $FBDIR/patchs/$DPDK_VERSION/0001-net-mce-add-PMD-skeleton.patch
	fi
	if [ ! -d $RTE_SDK/mk/arch/loongson ] &&
	[ ! -d $RTE_SDK/lib/librte_eal/common/include/arch/loongson ] &&
	[ ! -d lib/librte_eal/common/arch/loongson ]; then
		if [ "$git_method" == "am" ]; then
			git am --abort
		else
			git reset --hard
		fi
		git $git_method $FBDIR/patchs/$DPDK_VERSION/0002-DPDK-20.02-Add-Loongson3a-Support.patch
	fi
	cd $FBDIR
else
	fbprint_e "DPDK_TARGET $DPDK_TARGET is not support"
	exit
fi
 
################################COMPILE###############################################################
if [[ -z "$IN_QUEUES_PEER_FUN" ]];then
	IN_QUEUES_PEER_FUN=$QUEUES_PEER_FUN
fi

DRIVER_BUILD_ARGS="-DNIC_BASE_OFF=$NIC_OFF -DPORT_ASSIGN_VERSION=$PV -DQUEUES_PEER_FUN=$IN_QUEUES_PEER_FUN $CFLAGS"
if [ $FPGA -ne "0" ];then
	 DRIVER_BUILD_ARGS+=" -DCONFIG_FPGA "
fi

DPDK_BUILD_ARG[${#DPDK_BUILD_ARG[*]}]=EXTRA_CFLAGS="$DRIVER_BUILD_ARGS"

cd $RTE_SDK
fbprint_d "DPDK_BUILD_ARG ${DPDK_BUILD_ARG[@]}"

fbprint_d "Check DPDK-Version Match"

cur_version=`calc_dpdk_version_num $DPDK_VERSION`
match_version=`calc_dpdk_version_num 19.08`
#if [ $cur_version -lt $match_version ];then
#	DPDK_TARGET=${DPDK_TARGET/linux/linuxapp}
#fi
if [ $OUTPUT == "patch" ];then
	patch_for_fireware_type
	generate_dpdk_patch
else
	rm $DESTDIR/share/dpdk $DESTDIR/share/include/dpdk/ $DESTDIR/bin/dpdk-* -rfv

	make -j$JOBS -f $RTE_SDK/GNUmakefile install T=$DPDK_TARGET ${DPDK_BUILD_ARG[@]}

	####################insmod igb_uio or rte_kni update modprobe database###############
	[ $BUILD_KERNEL_MODULE == true ] && install_dpdk_kmod && depmod
	fbprint_d "DPDK Compile Finish"
###############################build test demo######################################


	export RTE_TARGET=$DPDK_TARGET
	rm examples/l2fwd/build -rfv
	make -j4  -C examples/l2fwd
	mkdir -p ../build/
	cp examples/l2fwd/build/l2fwd ../build
	compile_status=`cat examples/l2fwd/build/l2fwd.map|grep mce`
	[ -z $compile_status ] && fbprint_e "we don't add N10 pmd to dpdk-core" && exit

	cd ../build
	fbprint_d "you can find l2fwd test demo `pwd`"

	cd $FBDIR
fi
