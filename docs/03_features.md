# DPDK PMD Features

## RSS (Receive Side Scaling)
RSS allows the distribution of incoming packets across multiple CPU cores. This enhances performance by parallelizing packet processing and maximizing CPU utilization.

## TSO (TCP Segmentation Offload)
TSO is a feature that offloads the segmentation of large TCP packets into smaller segments, reducing CPU overhead and improving throughput for large data transfers.

## LRO (Large Receive Offload)
LRO combines multiple incoming TCP packets into a single large packet before handing it off to the TCP stack. This reduces processing overhead and boosts performance in high-bandwidth scenarios.

## Other Offloading Capabilities
Besides RSS, TSO, and LRO, DPDK PMDs usually support a range of offloading features such as:
- Checksum Offloading: Reduces CPU load by offloading checksum calculations for TCP/UDP packets.
- Garage Offloading: Manages the transfer of packets through hardware to optimize network performance.
- VLAN Filtering and Tagging: Enhances packet processing capabilities by efficiently managing VLAN tags.

In conclusion, these features significantly improve packet processing efficiency and network performance, making DPDK PMDs a powerful choice for high-performance network applications.