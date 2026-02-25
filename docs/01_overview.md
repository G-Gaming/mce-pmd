# DPDK PMD Overview

## Introduction
Data Plane Development Kit (DPDK) is a set of libraries and drivers for fast packet processing. It is widely used to accelerate network applications, leveraging the capabilities of various network cards.

## Different Network Card Vendors and Their PMD Drivers
As DPDK continues to evolve, support for a diverse range of network card vendors has expanded. Below is an overview of some prominent vendors and their associated Poll Mode Driver (PMD) implementations:

1. **Intel**
   - **PMD Driver:** i40e, ixgbe, and others
   - **Overview:** Intel provides several PMDs for its Ethernet controllers, focusing on performance and hardware acceleration features.

2. **Mellanox Technologies (now NVIDIA)**
   - **PMD Driver:** mlx5
   - **Overview:** Mellanox's PMD supports their ConnectX series of network adapters, enabling high throughput and low-latency communications.

3. **Broadcom**
   - **PMD Driver:** bnxt
   - **Overview:** Broadcom offers PMDs for its NetXtreme and other network controller families, focusing on performance and advanced features.

4. **Cavium (now part of Marvell Technology)**
   - **PMD Driver:** octeontx
   - **Overview:** Cavium’s PMDs are designed for their Octeon processors, enabling high-performance packet processing for data center and cloud environments.

5. **NXP**
   - **PMD Driver:** dpaa2
   - **Overview:** NXP provides PMDs for its Layerscape architecture, supporting networking and security applications at high speeds.

This overview highlights the rich ecosystem of network card vendors contributing to DPDK, allowing developers to build sophisticated and high-performance network applications with ease.