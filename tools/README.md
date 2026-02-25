
使用 ./script/link_mce_drv_to_dpdk_core.sh <dpdk-core-src>
link drivers/net/mce to dpdk-core/drivers/net/mce
然后设置好 Makefile 和配置文件

./usertools/dpdk-hugepages.py -p 2M --setup 10G -n 0
./usertools/dpdk-devbind.py -b igb_uio 0000:21:00.0 0000:21:00.1


apt install meson ninja-build
apt install libnuma-dev
#pip3 install meson==0.63.3
apt install python3-pip
pip3 install pyelftools

#meson setup -Dexamples=l2fwd,l3fwd build

meson build
cd build
ninja -j4 -v
#ninja install

#echo "/usr/local/lib64/" >> /etc/ld.so.conf.d/dpdk.conf

igb_uio
---
git clone http://dpdk.org/git/dpdk-kmods
cd ./dpdk-kmods/linux/igb_uio 
make && make install


======= call map ==

#3  in mce_init_hw (hw=0x118039f028) at ../drivers/net/mce/base/mce_common.c:261
#4  in mce_eth_dev_init (eth_dev=0x1c8af00 <rte_eth_devices>) at ../drivers/net/mce/mce_ethdev.c:2764
#5  in rte_eth_dev_pci_generic_probe (pci_dev=, private_data_size=36968, dev_init=0xe05ddf <mce_eth_dev_init>) at ../lib/ethdev/ethdev_pci.h:150
#6  in mce_pci_probe (pci_drv=0x1807ba0 <rte_mce_pmd>, pci_dev=0x1d52200) at ../drivers/net/mce/mce_ethdev.c:2997
#7  in rte_pci_probe_one_driver (dr=0x1807ba0 <rte_mce_pmd>, dev=0x1d52200) at ../drivers/bus/pci/pci_common.c:302
#8  in pci_probe_all_drivers (dev=0x1d52200) at ../drivers/bus/pci/pci_common.c:386
#9  in pci_probe () at ../drivers/bus/pci/pci_common.c:413
#10 in rte_bus_probe () at ../lib/eal/common/eal_common_bus.c:78
#11 in rte_eal_init (argc=3, argv=0x7fffffffeae8) at ../lib/eal/linux/eal.c:1281
#12 in main (argc=3, argv=0x7fffffffeae8) at ../app/test-pmd/testpmd.c:4553


#0  mce_dev_infos_get (dev=0x1c8af00 <rte_eth_devices>, dev_info=0x1180602f00) at ../drivers/net/mce/mce_ethdev.c:225
#1  in rte_eth_dev_info_get (port_id=0, dev_info=0x1180602f00) at ../lib/ethdev/rte_ethdev.c:3821
#2  in eth_dev_info_get_print_err (port_id=0, dev_info=0x1180602f00) at ../app/test-pmd/util.c:442
#3  in init_config_port_offloads (pid=0, socket_id=0) at ../app/test-pmd/testpmd.c:1632
#4  in init_config () at ../app/test-pmd/testpmd.c:1737
#5  in main (argc=2, argv=0x7fffffffeaf0) at ../app/test-pmd/testpmd.c:4630


==== fec ===

show port <pid> fec capabilities
	cmd_show_fec_capability_parsed()
		rte_eth_fec_get_capability()
			mce_fec_get_capability()
show port <pid> fec_mode
set port <pid> fec_mode auto|off|rs|baser

=== force-speed-set ==
show port 0 module_eeprom
show port info <port_id>
--show port  cap <port_id>
port config <port_id> speed <speed> duplex <full|half|auto> 
	# force 1G
	port stop 0
	port config 0 speed 1000 duplex full
	port start 0
	# auto
	port stop 0
	port config 0 speed auto duplex full
	port start 0


=== debug ==
rte_telemetry
	./usertools/dpdk-telemetry.py
		--> /mce/nic_info_summary,args...
	./mce_telemetry.c
