#include <stdio.h>

#include <rte_version.h>
#include "mce_pattern.h"
#include "mce_parse.h"
#include "mce_logs.h"

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_flow_driver.h>

/**
 * @brief Parse an Ethernet flow item into lookup metadata.
 *
 * Extracts Ethernet address and ethertype matching information from
 * `item` into `meta` and sets corresponding bits in `*inset`.
 *
 * @param item
 *   Pointer to the flow item representing an Ethernet header.
 * @param meta
 *   Output lookup metadata to populate.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   True if parsing inner headers of a tunnel.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if any option was parsed and set, 0 if nothing parsed, negative on error.
 */
int mce_parse_eth(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	const struct rte_flow_item_eth *eth_spec;
	const struct rte_flow_item_eth *eth_mask;
	uint16_t eth_type = 0;
	uint64_t options = 0;

	eth_spec = item->spec;
	eth_mask = item->mask;
	if (!eth_spec || !eth_mask)
		return 0;
	if (!rte_is_zero_ether_addr(&eth_mask->src)) {
		memcpy(&meta->mask.eth_meta.src_addr, &eth_mask->src,
		       RTE_ETHER_ADDR_LEN);
	}
	if (!rte_is_zero_ether_addr(&eth_mask->dst)) {
		memcpy(&meta->mask.eth_meta.dst_addr, &eth_mask->dst,
		       RTE_ETHER_ADDR_LEN);
	}
	if (!rte_is_zero_ether_addr(&eth_spec->src)) {
		options |= MCE_OPT_SMAC;
		memcpy(&meta->hdr.eth_meta.src_addr, &eth_spec->src,
		       RTE_ETHER_ADDR_LEN);
	}
	if (!rte_is_zero_ether_addr(&eth_spec->dst)) {
		options |= MCE_OPT_DMAC;
		memcpy(&meta->hdr.eth_meta.dst_addr, &eth_spec->dst,
		       RTE_ETHER_ADDR_LEN);
	}
	if (eth_mask->type) {
		eth_type = rte_be_to_cpu_16(eth_spec->type);
		if (eth_type == RTE_ETHER_TYPE_IPV4 ||
		    eth_type == RTE_ETHER_TYPE_IPV6 ||
		    eth_type == RTE_ETHER_TYPE_VLAN ||
		    eth_type == RTE_ETHER_TYPE_QINQ)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"IPV4/IPV6 CVLAN/SVLAN ID Isn't"
				" Support Match For Ethertype");
		options |= MCE_OPT_ETHTYPE;
		meta->hdr.eth_meta.ethtype_id = eth_type;
		meta->mask.eth_meta.ethtype_id =
			rte_be_to_cpu_16(eth_mask->type);
	}
	if (options)
		meta->type = MCE_ETH_META;
	if (*inset & options) {
		memset(meta, 0, sizeof(*meta));
		if (is_tunnel)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"don't support set both out and "
				"inner as options for tunnel packet");
		else
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"don's support set eth item twice "
				"for tunnel just support inner eth");
	}
	if (options)
		*inset |= options;
	return options ? 1 : 0;
}

/**
 * @brief Parse a VLAN flow item into lookup metadata.
 *
 * Extract VLAN ID information from `item` into `meta` and update `*inset`.
 *
 * @param item
 *   Pointer to the VLAN flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Unused for VLAN parsing.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if VLAN options were parsed, 0 if not, negative on error.
 */
int mce_parse_vlan(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel __rte_unused,
		   struct rte_flow_error *error)
{
	const struct rte_flow_item_vlan *vlan_spec;
	const struct rte_flow_item_vlan *vlan_mask;
	uint16_t vlan_tci = 0;
	uint64_t options = 0;

	vlan_spec = item->spec;
	vlan_mask = item->mask;
	/*
	 * Eth may is used to describe protocol,
	 * spec and mask should be NULL.
	 */
	if (!vlan_spec || !vlan_mask)
		return 0;
	vlan_tci = rte_be_to_cpu_16(vlan_spec->tci);
	if (vlan_tci & 0xf000) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "Priority and CFI Isn't"
					  " Support Match For Vlan");
	}
	if (vlan_mask->tci) {
		meta->hdr.vlan_meta.vlan_id = vlan_tci;
		meta->mask.vlan_meta.vlan_id = rte_be_to_cpu_16(0x0FFF);
		options |= MCE_OPT_VLAN_VID;
		meta->type = MCE_VLAN_META;
	}
	if (options)
		*inset |= options;
	return options ? 1 : 0;
}

/**
 * @brief Parse an IPv4 flow item into lookup metadata.
 *
 * Parses source/destination IPv4 addresses, L4 protocol and optional
 * fields into `meta` and updates `*inset` accordingly.
 *
 * @param item
 *   Pointer to the IPv4 flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   True when parsing inner headers of a tunnel.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if IPv4 options were parsed, 0 if not, negative on error.
 */
int mce_parse_ip4(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv4 *ipv4_spec;
	const struct rte_flow_item_ipv4 *ipv4_mask;
	uint64_t options = 0;

	ipv4_spec = item->spec;
	ipv4_mask = item->mask;

	if (ipv4_spec && ipv4_mask) {
		/* Check IPv4 mask and update input set */
		if (ipv4_mask->hdr.version_ihl || ipv4_mask->hdr.total_length ||
		    ipv4_mask->hdr.packet_id || ipv4_mask->hdr.hdr_checksum)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPv4 mask Just Support "
				"Src/Dst Ip Address For Match");
		if (ipv4_mask->hdr.src_addr) {
			options |= (is_tunnel ? MCE_OPT_OUT_IPV4_SIP :
						MCE_OPT_IPV4_SIP);
			meta->hdr.ipv4_meta.src_addr =
				rte_cpu_to_be_32(ipv4_spec->hdr.src_addr);
			meta->mask.ipv4_meta.src_addr =
				rte_cpu_to_be_32(ipv4_mask->hdr.src_addr);
		}
		if (ipv4_mask->hdr.dst_addr) {
			options |= (is_tunnel ? MCE_OPT_OUT_IPV4_DIP :
						MCE_OPT_IPV4_DIP);
			meta->hdr.ipv4_meta.dst_addr =
				rte_cpu_to_be_32(ipv4_spec->hdr.dst_addr);
			meta->mask.ipv4_meta.dst_addr =
				rte_cpu_to_be_32(ipv4_mask->hdr.dst_addr);
		}
#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
		if (ipv4_mask->hdr.type_of_service & RTE_IPV4_HDR_DSCP_MASK) {
			options |= MCE_OPT_IPV4_DSCP;
			meta->mask.ipv4_meta.dscp =
				ipv4_mask->hdr.type_of_service;
			meta->hdr.ipv4_meta.dscp =
				ipv4_spec->hdr.type_of_service;
			meta->mask.ipv4_meta.dscp &= RTE_IPV4_HDR_DSCP_MASK;
			meta->hdr.ipv4_meta.dscp &= RTE_IPV4_HDR_DSCP_MASK;
		}
		if (ipv4_spec->hdr.fragment_offset ==
			    rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG) &&
		    ipv4_mask->hdr.fragment_offset ==
			    rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG)) {
			/* all IPv4 fragment packet has the same
			 * ethertype, if the spec and mask is valid,
			 * set ethertype into input set.
			 */
			options |= MCE_OPT_IPV4_FRAG;
			meta->hdr.ipv4_meta.is_frag = 1;
		} else if (ipv4_mask->hdr.packet_id == UINT16_MAX) {
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM, item,
					   "Invalid IPv4 mask.");
			return -rte_errno;
		}
#endif
		if (ipv4_mask->hdr.next_proto_id) {
			meta->hdr.ipv4_meta.protocol =
				ipv4_spec->hdr.next_proto_id;
			meta->mask.ipv4_meta.protocol =
				ipv4_mask->hdr.next_proto_id;
			options |= MCE_OPT_L4_PROTO;
		}
		if (options)
			meta->type = MCE_IPV4_META;
	}
	if (*inset & options)
		PMD_DRV_LOG(ERR, "set twitch inner or out options");
	if (options)
		*inset |= options;
	return options ? 1 : 0;
}

/**
 * @brief Parse an IPv6 flow item into lookup metadata.
 *
 * Parses IPv6 source/destination addresses, next header and optional
 * DSCP/fragment info into `meta` and updates `*inset`.
 *
 * @param item
 *   Pointer to the IPv6 flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   True when parsing inner headers of a tunnel.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if IPv6 options were parsed, 0 if not, negative on error.
 */
int mce_parse_ip6(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	struct mce_ipv6_meta *ipv6_meta = &meta->hdr.ipv6_meta;
	const struct rte_flow_item_ipv6 *ipv6_spec;
	const struct rte_flow_item_ipv6 *ipv6_mask;
	const rte_be32_t *ip = NULL;
	const rte_be32_t *mask = NULL;
	uint64_t options = 0;
	uint32_t vtc_flow_mask;
	uint32_t dscp_msk = 0;
	uint32_t vtc_flow;
	uint32_t dscp = 0;

	ipv6_spec = item->spec;
	ipv6_mask = item->mask;

	if (ipv6_spec && ipv6_mask) {
		/* Check IPv6 mask and update input set */
		if (ipv6_mask->hdr.payload_len || ipv6_mask->hdr.hop_limits) {
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_MASK,
				item,
				"Only support src & dst ip,proto in IPV6");
		}
		/*if (!memcmp(ipv6_mask->hdr.src_addr,
			&rte_flow_item_ipv6_mask.hdr.src_addr, 16)) {*/
		mask = (const rte_be32_t *)&ipv6_mask->hdr.src_addr;
		if (mask[0] | mask[1] | mask[2] | mask[3]) {
			ip = (const rte_be32_t *)&ipv6_spec->hdr.src_addr;
			/* for (i = 0; i < 4; i++) { */
			ipv6_meta->src_addr[0] = rte_cpu_to_be_32(ip[3]);
			ipv6_meta->src_addr[1] = rte_cpu_to_be_32(ip[2]);
			ipv6_meta->src_addr[2] = rte_cpu_to_be_32(ip[1]);
			ipv6_meta->src_addr[3] = rte_cpu_to_be_32(ip[0]);
			meta->mask.ipv6_meta.src_addr[0] =
				rte_cpu_to_be_32(mask[3]);
			meta->mask.ipv6_meta.src_addr[1] =
				rte_cpu_to_be_32(mask[2]);
			meta->mask.ipv6_meta.src_addr[2] =
				rte_cpu_to_be_32(mask[1]);
			meta->mask.ipv6_meta.src_addr[3] =
				rte_cpu_to_be_32(mask[0]);
			/*}*/
			options |= (is_tunnel ? MCE_OPT_OUT_IPV6_SIP :
						MCE_OPT_IPV6_SIP);
		}
		/*if (!memcmp(ipv6_mask->hdr.dst_addr,
			&rte_flow_item_ipv6_mask.hdr.dst_addr, 16)) {*/
		mask = (const rte_be32_t *)&ipv6_mask->hdr.dst_addr;
		if (mask[0] | mask[1] | mask[2] | mask[3]) {
			ip = (const rte_be32_t *)&ipv6_spec->hdr.dst_addr;
			ipv6_meta->dst_addr[0] = rte_cpu_to_be_32(ip[3]);
			ipv6_meta->dst_addr[1] = rte_cpu_to_be_32(ip[2]);
			ipv6_meta->dst_addr[2] = rte_cpu_to_be_32(ip[1]);
			ipv6_meta->dst_addr[3] = rte_cpu_to_be_32(ip[0]);
			meta->mask.ipv6_meta.dst_addr[0] =
				rte_cpu_to_be_32(mask[3]);
			meta->mask.ipv6_meta.dst_addr[1] =
				rte_cpu_to_be_32(mask[2]);
			meta->mask.ipv6_meta.dst_addr[2] =
				rte_cpu_to_be_32(mask[1]);
			meta->mask.ipv6_meta.dst_addr[3] =
				rte_cpu_to_be_32(mask[0]);
			options |= (is_tunnel ? MCE_OPT_OUT_IPV6_DIP :
						MCE_OPT_IPV6_DIP);
		}
		if (ipv6_mask->hdr.proto) {
			ipv6_meta->protocol = ipv6_spec->hdr.proto;
			meta->mask.ipv6_meta.protocol = ipv6_mask->hdr.proto;
			options |= MCE_OPT_L4_PROTO;
		}
#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
		if ((ipv6_mask->hdr.vtc_flow &
		     rte_cpu_to_be_32(RTE_IPV6_HDR_DSCP_MASK)) ==
		    rte_cpu_to_be_32(RTE_IPV6_HDR_DSCP_MASK)) {
			vtc_flow_mask =
				rte_cpu_to_be_32(ipv6_mask->hdr.vtc_flow);
			vtc_flow = rte_cpu_to_be_32(ipv6_spec->hdr.vtc_flow);
			if (!(vtc_flow & RTE_IPV6_HDR_TC_MASK)) {
				printf("tc value is zero\n");
				return -EINVAL;
			}
			dscp_msk = vtc_flow_mask & RTE_IPV6_HDR_DSCP_MASK;
			dscp = vtc_flow & RTE_IPV6_HDR_DSCP_MASK;
			dscp_msk = dscp_msk >> RTE_IPV6_HDR_TC_SHIFT;
			dscp = dscp >> RTE_IPV6_HDR_TC_SHIFT;
			meta->mask.ipv6_meta.dscp = dscp_msk;
			meta->hdr.ipv6_meta.dscp = dscp;

			options |= MCE_OPT_IPV6_DSCP;
		}
#else
		RTE_SET_USED(dscp);
		RTE_SET_USED(vtc_flow);
		RTE_SET_USED(dscp_msk);
		RTE_SET_USED(vtc_flow_mask);
#endif
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		if (ipv6_mask->has_frag_ext && ipv6_spec->has_frag_ext) {
			options |= MCE_OPT_IPV6_FRAG;
			meta->hdr.ipv6_meta.is_frag = 1;
		}
#endif
		if (options)
			meta->type = MCE_IPV6_META;
	}
	if (options)
		*inset |= options;
	return options ? 1 : 0;
}

/**
 * @brief Parse IPv6 fragment flow item.
 *
 * Detects IPv6 fragment flows and sets metadata accordingly.
 *
 * @param item
 *   Pointer to the IPv6 fragment flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Unused for IPv6 fragment parsing.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if fragment option parsed, 0 if not, negative on error.
 */
int mce_parse_ip6_frag(const struct rte_flow_item *item,
			   struct mce_lkup_meta *meta, uint64_t *inset,
			   bool is_tunnel __rte_unused,
			   struct rte_flow_error *error)
{
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
	struct mce_ip_frag_meta *frag_meta = &meta->hdr.frag_meta;
	const struct rte_flow_item_ipv6_frag_ext *ipv6_frag_spec;
	const struct rte_flow_item_ipv6_frag_ext *ipv6_frag_mask;
	uint64_t options = 0;

	ipv6_frag_spec = item->spec;
	ipv6_frag_mask = item->mask;
	if (!(ipv6_frag_spec && ipv6_frag_mask))
		return 0;

	/* fragment Ipv6:
	 * spec is 0x1, mask is 0x1
	 */
	if (ipv6_frag_spec->hdr.frag_data == rte_cpu_to_be_16(1)) {
		/* all IPv6 fragment packet has the same
		 * ethertype, if the spec and mask is valid,
		 * set ethertype into input set.
		 */
		options |= MCE_OPT_IPV6_FRAG;
		meta->type = MCE_IP_FRAG;
		frag_meta->is_frag = 1;
	} else if (ipv6_frag_mask->hdr.id == UINT32_MAX) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
				   item, "Invalid IPv6 mask.");
		return -rte_errno;
	}
	if (options)
		*inset |= options;

	return options ? 1 : 0;
#else
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(error);

	return 0;
#endif
}

/**
 * @brief Parse a UDP flow item into lookup metadata.
 *
 * Extracts UDP source/destination ports into `meta` and updates `*inset`.
 *
 * @param item
 *   Pointer to the UDP flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   True when parsing inner headers of a tunnel.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if UDP options were parsed, 0 if not, negative on error.
 */
int mce_parse_udp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	const struct rte_flow_item_udp *udp_spec = item->spec;
	const struct rte_flow_item_udp *udp_mask = item->mask;
	uint64_t options = 0;

	if (!(udp_mask && udp_spec))
		return 0;
	/* Only dest/src port is used */
	if (udp_mask->hdr.dgram_len || udp_mask->hdr.dgram_cksum)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
					  "UDP only support Dest/Src port");
	if (udp_mask->hdr.dst_port) {
		meta->hdr.udp_meta.dst_port =
			rte_cpu_to_be_16(udp_spec->hdr.dst_port);
		meta->mask.udp_meta.dst_port =
			rte_cpu_to_be_16(udp_mask->hdr.dst_port);
		options |=
			(is_tunnel ? MCE_OPT_OUT_L4_DPORT : MCE_OPT_UDP_DPORT);
	}
	if (udp_mask->hdr.src_port) {
		meta->hdr.udp_meta.src_port =
			rte_cpu_to_be_16(udp_spec->hdr.src_port);
		meta->mask.udp_meta.src_port =
			rte_cpu_to_be_16(udp_mask->hdr.src_port);
		options |=
			(is_tunnel ? MCE_OPT_OUT_L4_SPORT : MCE_OPT_UDP_SPORT);
	}
	if (options)
		meta->type = MCE_UDP_META;
	if (*inset & options)
		PMD_DRV_LOG(ERR, "set twitch inner or out options");
	if (options)
		*inset |= options;

	return options ? 1 : 0;
}

/* Parse pattern type of TCP */
/**
 * @brief Parse a TCP flow item into lookup metadata.
 *
 * Extracts TCP ports and SYN flag into `meta` and updates `*inset`.
 *
 * @param item
 *   Pointer to the TCP flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   True when parsing inner headers of a tunnel.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if TCP options were parsed, 0 if not, negative on error.
 */
int mce_parse_tcp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	const struct rte_flow_item_tcp *tcp_spec = item->spec;
	const struct rte_flow_item_tcp *tcp_mask = item->mask;
	const struct rte_flow_item_tcp *tcp_last = item->last;
	uint64_t options = 0;

	if (!(tcp_mask && tcp_spec))
		return 0;

	if (tcp_last) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"TCP Not support range");
	}
	if (tcp_mask->hdr.sent_seq || tcp_mask->hdr.recv_ack ||
	    tcp_mask->hdr.data_off || tcp_mask->hdr.rx_win ||
	    tcp_mask->hdr.cksum || tcp_mask->hdr.tcp_urp ||
	    (tcp_mask->hdr.tcp_flags &&
	     tcp_spec->hdr.tcp_flags != RTE_TCP_SYN_FLAG))
		return rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
			"TCP only dst/src port FLAG-SYNC Support");
	/* if (tcp_mask->hdr.src_port == UINT16_MAX) { */
	if (tcp_mask->hdr.src_port) {
		meta->hdr.tcp_meta.src_port =
			rte_cpu_to_be_16(tcp_spec->hdr.src_port);
		meta->mask.tcp_meta.src_port =
			rte_cpu_to_be_16(tcp_mask->hdr.src_port);
		options |=
			(is_tunnel ? MCE_OPT_OUT_L4_SPORT : MCE_OPT_TCP_SPORT);
	}
	if (tcp_mask->hdr.tcp_flags == UINT8_MAX) {
		options |= MCE_OPT_TCP_SYNC;
	}
	if (tcp_mask->hdr.dst_port) {
		meta->hdr.tcp_meta.dst_port =
			rte_cpu_to_be_16(tcp_spec->hdr.dst_port);
		meta->mask.tcp_meta.dst_port =
			rte_cpu_to_be_16(tcp_mask->hdr.dst_port);
		options |=
			(is_tunnel ? MCE_OPT_OUT_L4_DPORT : MCE_OPT_TCP_DPORT);
	}
	if (options)
		meta->type = MCE_TCP_META;
	if (*inset & options)
		PMD_DRV_LOG(ERR, "set twitch inner or out options");
	if (options)
		*inset |= options;
	return options ? 1 : 0;
}

/**
 * @brief Parse an SCTP flow item into lookup metadata.
 *
 * Extracts SCTP ports into `meta` and updates `*inset`.
 *
 * @param item
 *   Pointer to the SCTP flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   True when parsing inner headers of a tunnel.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if SCTP options were parsed, 0 if not, negative on error.
 */
int mce_parse_sctp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error)
{
	const struct rte_flow_item_sctp *sctp_spec = item->spec;
	const struct rte_flow_item_sctp *sctp_mask = item->mask;
	uint64_t options = 0;

	if (!(sctp_mask && sctp_spec))
		return 0;
	/* Only dest/src port is used */
	if (sctp_mask->hdr.tag || sctp_mask->hdr.cksum)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
					  "UDP only support Dest/Src port");
	if (sctp_mask->hdr.dst_port) {
		meta->hdr.sctp_meta.dst_port =
			rte_cpu_to_be_16(sctp_spec->hdr.dst_port);
		meta->mask.sctp_meta.dst_port =
			rte_cpu_to_be_16(sctp_mask->hdr.dst_port);
		options |=
			(is_tunnel ? MCE_OPT_OUT_L4_DPORT : MCE_OPT_SCTP_DPORT);
	}
	if (sctp_mask->hdr.src_port) {
		meta->hdr.sctp_meta.src_port =
			rte_cpu_to_be_16(sctp_spec->hdr.src_port);
		meta->mask.sctp_meta.src_port =
			rte_cpu_to_be_16(sctp_mask->hdr.src_port);
		options |=
			(is_tunnel ? MCE_OPT_OUT_L4_SPORT : MCE_OPT_SCTP_SPORT);
	}
	if (sctp_mask->hdr.tag) {
		meta->hdr.sctp_meta.vtag = sctp_spec->hdr.tag;
		meta->mask.sctp_meta.vtag = sctp_mask->hdr.tag;
		options |=
			(is_tunnel ? MCE_OPT_OUT_SCTP_VTAG : MCE_OPT_SCTP_VTAG);
	}
	if (options)
		meta->type = MCE_SCTP_META;
	if (*inset & options)
		PMD_DRV_LOG(ERR, "set twitch inner or out options");
	if (options)
		*inset |= options;

	return options ? 1 : 0;
}

/**
 * @brief Parse VXLAN flow item and extract VNI.
 *
 * When present, extracts the VXLAN VNI into `meta` and updates `*inset`.
 *
 * @param item
 *   Pointer to the VXLAN flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Tunnel indicator (not used here).
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if VXLAN VNI parsed, 0 if not, negative on error.
 */
int mce_parse_vxlan(const struct rte_flow_item *item,
			struct mce_lkup_meta *meta, uint64_t *inset, bool is_tunnel,
			struct rte_flow_error *error)
{
	const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
	const struct rte_flow_item_vxlan *vxlan_mask = item->mask;
	bool is_vni_masked = 0;
	uint8_t vni_mask[] = { 0xFF, 0xFF, 0xFF };
	uint32_t tenant_id_be = 0;
	uint64_t options = 0;

	(void)is_tunnel;
	/* Check if VXLAN item is used to describe protocol.
	 * If yes, both spec and mask should be NULL.
	 * If no, both spec and mask shouldn't be NULL.
	 */
	if (!(vxlan_spec && vxlan_mask))
		return 0;
	if (vxlan_mask->flags)
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
				   item, "not support VXLAN item flags");
	/* Check if VNI is masked. */
	if (vxlan_mask->vni[0] || vxlan_mask->vni[1] || vxlan_mask->vni[2]) {
		is_vni_masked =
			!!memcmp(vxlan_mask->vni, vni_mask, RTE_DIM(vni_mask));
		if (is_vni_masked) {
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM, item,
					   "Invalid VNI mask");
			return -rte_errno;
		}

		memcpy(((uint8_t *)&tenant_id_be + 1), vxlan_spec->vni, 3);
		meta->hdr.vxlan_meta.vni = rte_be_to_cpu_32(tenant_id_be);
		memcpy(((uint8_t *)&tenant_id_be + 1), vxlan_mask->vni, 3);
		meta->mask.vxlan_meta.vni = rte_be_to_cpu_32(tenant_id_be);
		options |= MCE_OPT_VXLAN_VNI;
	}

	if (options) {
		meta->type = MCE_VXLAN_META;
		*inset |= options;
	}

	return options ? 1 : 0;
}

/**
 * @brief Parse NVGRE flow item and extract TNI.
 *
 * Extracts NVGRE TNI fields into `meta` when present and updates `*inset`.
 *
 * @param item
 *   Pointer to the NVGRE flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Unused for NVGRE parsing.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if NVGRE TNI parsed, 0 if not, negative on error.
 */
int mce_parse_nvgre(const struct rte_flow_item *item,
			struct mce_lkup_meta *meta, uint64_t *inset,
			bool is_tunnel __rte_unused, struct rte_flow_error *error)
{
	const struct rte_flow_item_nvgre *nvgre_spec;
	const struct rte_flow_item_nvgre *nvgre_mask;
	uint64_t options = 0;

	nvgre_spec = item->spec;
	nvgre_mask = item->mask;
	/*
	 * NVGRE may is used to describe protocol,
	 * spec and mask should be NULL.
	 */
	if (item->spec == NULL && item->mask == NULL)
		return 0;
	if (nvgre_mask->protocol || nvgre_mask->c_k_s_rsvd0_ver ||
	    nvgre_mask->flow_id)
		return rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
			"Ver/protocol/flow_id is not supported in NVGRE");
	if (nvgre_mask->tni[0] || nvgre_mask->tni[1] || nvgre_mask->tni[2]) {
		memcpy(&meta->hdr.nvgre_meta.key, &nvgre_spec->tni,
		       sizeof(nvgre_spec->tni));
		memcpy(&meta->mask.nvgre_meta.key, &nvgre_mask->tni,
		       sizeof(nvgre_mask->tni));
		meta->type = MCE_NVGRE_META;
		options |= MCE_OPT_NVGRE_TNI;
	}
	if (options)
		*inset |= options;

	return options ? 1 : 0;
}

#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
/**
 * @brief Parse ESP flow item (SPI support).
 *
 * Extracts ESP SPI into `meta` when specified and updates `*inset`.
 *
 * @param item
 *   Pointer to the ESP flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Unused for ESP parsing.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if ESP SPI parsed, 0 if not, negative on error.
 */
int mce_parse_esp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	const struct rte_flow_item_esp *esp_spec = item->spec;
	const struct rte_flow_item_esp *esp_mask = item->mask;
	uint64_t options = 0;

	(void)is_tunnel;
	if (!esp_spec && !esp_mask) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "Invalid ESP item");
	}
	if (esp_mask->hdr.seq)
		return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"esp seq is not support");
	if (esp_mask->hdr.spi) {
		meta->hdr.esp_meta.spi = rte_be_to_cpu_32(esp_spec->hdr.spi);
		meta->mask.esp_meta.spi = rte_be_to_cpu_32(esp_mask->hdr.spi);
		options |= MCE_OPT_ESP_SPI;
	}
	if (options)
		meta->type = MCE_ESP_META;
	if (*inset & options)
		PMD_DRV_LOG(ERR, "set twitch inner or out options");
	if (options)
		*inset |= options;

	return options ? 1 : 0;
}
#endif

#if RTE_VERSION_NUM(18, 2, 0, 0) <= RTE_VERSION
/**
 * @brief Parse GENEVE flow item and extract VNI.
 *
 * Extracts GENEVE VNI into `meta` and updates `*inset` when present.
 *
 * @param item
 *   Pointer to the GENEVE flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Tunnel indicator (not used here).
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if GENEVE VNI parsed, 0 if not, negative on error.
 */
int mce_parse_geneve(const struct rte_flow_item *item,
			 struct mce_lkup_meta *meta, uint64_t *inset,
			 bool is_tunnel, struct rte_flow_error *error)
{
	const struct rte_flow_item_geneve *geneve_spec = item->spec;
	const struct rte_flow_item_geneve *geneve_mask = item->mask;
	bool is_vni_masked = 0;
	uint8_t vni_mask[] = { 0xFF, 0xFF, 0xFF };
	uint32_t tenant_id_be = 0;
	uint64_t options = 0;
	(void)is_tunnel;

	/* Check if GENEVE item is used to describe protocol.
	 * If yes, both spec and mask should be NULL.
	 * If no, both spec and mask shouldn't be NULL.
	 */
	if ((!geneve_spec && geneve_mask) || (geneve_spec && !geneve_mask)) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
				   item, "Invalid GENEVE item");
		return -rte_errno;
	}
	/* Check if VNI is masked. */
	if (geneve_mask->vni[0] || geneve_mask->vni[1] || geneve_mask->vni[2]) {
		is_vni_masked =
			!!memcmp(geneve_mask->vni, vni_mask, RTE_DIM(vni_mask));
		if (is_vni_masked) {
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM, item,
					   "Invalid VNI mask");
			return -rte_errno;
		}

		memcpy(((uint8_t *)&tenant_id_be + 1), geneve_spec->vni, 3);
		meta->hdr.geneve_meta.vni = rte_be_to_cpu_32(tenant_id_be);
		memcpy(((uint8_t *)&tenant_id_be + 1), geneve_mask->vni, 3);
		meta->mask.geneve_meta.vni = rte_be_to_cpu_32(tenant_id_be);
		options |= MCE_OPT_GENEVE_VNI;
	}

	if (options)
		meta->type = MCE_GENEVE_META;
	if (options)
		*inset |= options;

	return options ? 1 : 0;
}
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) < RTE_VERSION
/**
 * @brief Parse GTP-U flow item and extract TEID.
 *
 * Extracts the GTP-U TEID into `meta` and updates `*inset` when present.
 *
 * @param item
 *   Pointer to the GTP-U flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Tunnel indicator (not used here).
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if GTP-U TEID parsed, 0 if not, negative on error.
 */
int mce_parse_gtpu(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error)
{
	const struct rte_flow_item_gtp *gtp_spec;
	const struct rte_flow_item_gtp *gtp_mask;
	uint64_t options = 0;

	(void)is_tunnel;
	gtp_spec = item->spec;
	gtp_mask = item->mask;
	/*
	 * GTP may is used to describe protocol,
	 * spec and mask should be NULL.
	 */
	if (!gtp_spec || !gtp_mask)
		return 0;

	if (gtp_mask->v_pt_rsv_flags || gtp_mask->msg_type ||
	    gtp_mask->msg_len || gtp_mask->teid != UINT32_MAX) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
				   item, "Invalid GTP-U mask");
		return -rte_errno;
	}
	if (*inset & MCE_OPT_GTP_U_TEID) {
		PMD_DRV_LOG(ERR, "set twitch inner or out options");
		return -EINVAL;
	}
	if (gtp_mask->teid) {
		meta->hdr.gtp_meta.teid = rte_be_to_cpu_32(gtp_spec->teid);
		meta->mask.gtp_meta.teid = rte_be_to_cpu_32(gtp_mask->teid);
		options |= MCE_OPT_GTP_U_TEID;
		meta->type = MCE_GTPU_META;
		*inset |= options;
	}

	return options ? 1 : 0;
}

/**
 * @brief Parse GTP-C (control) flow item.
 *
 * Extracts GTP-C TEID when present and updates `*inset`.
 *
 * @param item
 *   Pointer to the GTP-C flow item.
 * @param meta
 *   Output lookup metadata.
 * @param inset
 *   Pointer to the input-set bitmask updated by this parser.
 * @param is_tunnel
 *   Unused for GTP-C parsing.
 * @param error
 *   Out parameter for flow parsing errors.
 * @return
 *   1 if GTP-C TEID parsed, 0 if not, negative on error.
 */
int mce_parse_gtpc(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel __rte_unused,
		   struct rte_flow_error *error)
{
	const struct rte_flow_item_gtp *gtp_spec;
	const struct rte_flow_item_gtp *gtp_mask;
	uint64_t options = 0;

	gtp_spec = item->spec;
	gtp_mask = item->mask;
	if (!gtp_spec || !gtp_mask)
		return 0;
	if (gtp_mask->v_pt_rsv_flags || gtp_mask->msg_type ||
	    gtp_mask->msg_len || gtp_mask->teid != UINT32_MAX) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM, item,
					  "Invalid GTP mask");
	}

	if (gtp_spec->v_pt_rsv_flags & RTE_BIT32(4)) {
		meta->hdr.gtp_meta.teid = rte_be_to_cpu_32(gtp_spec->teid);
		meta->mask.gtp_meta.teid = rte_be_to_cpu_32(gtp_mask->teid);
		options |= MCE_OPT_GTP_C_TEID;
		meta->type = MCE_GTPC_META;
		*inset |= options;
	}

	return options ? 1 : 0;
}
#endif
#else
int mce_parse_eth(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_vlan(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_ip4(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_ip6(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_ip6_frag(const struct rte_flow_item *item,
		       struct mce_lkup_meta *meta, uint64_t *inset,
		       bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_tcp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_udp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_sctp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_vxlan(const struct rte_flow_item *item,
		    struct mce_lkup_meta *meta, uint64_t *inset, bool is_tunnel,
		    struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_geneve(const struct rte_flow_item *item,
		     struct mce_lkup_meta *meta, uint64_t *inset,
		     bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_nvgre(const struct rte_flow_item *item,
		    struct mce_lkup_meta *meta, uint64_t *inset, bool is_tunnel,
		    struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_esp(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		  uint64_t *inset, bool is_tunnel, struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_gtpc(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
int mce_parse_gtpu(const struct rte_flow_item *item, struct mce_lkup_meta *meta,
		   uint64_t *inset, bool is_tunnel,
		   struct rte_flow_error *error)
{
	RTE_SET_USED(item);
	RTE_SET_USED(meta);
	RTE_SET_USED(inset);
	RTE_SET_USED(is_tunnel);
	RTE_SET_USED(error);
	return 0;
}
#endif /* RTE_VERSION >= 17.02 */
