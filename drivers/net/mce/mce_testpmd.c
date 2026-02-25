#include <ethdev_driver.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "base/mce_eth_regs.h"

#include "mce.h"
#include "mce_rxtx.h"
#include "rte_pmd_mce.h"

#include "testpmd.h"

/* Common result structure for vf split drop enable */
struct cmd_tx_3_vlan_insert_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vlan3;
	cmdline_fixed_string_t insert;
	portid_t port_id;
	uint16_t vlan_id;
	cmdline_fixed_string_t on_off;
};
static cmdline_parse_token_string_t cmd_tx_3_vlan_insert_set =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_3_vlan_insert_result, set,
				 "set");
static cmdline_parse_token_string_t cmd_tx_3_vlan_insert_vlan3 =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_3_vlan_insert_result, vlan3,
				 "vlan3");
static cmdline_parse_token_string_t cmd_tx_3_vlan_insert_insert =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_3_vlan_insert_result, insert,
				 "insert");
static cmdline_parse_token_num_t cmd_tx_3_vlan_insert_port =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_3_vlan_insert_result, port_id,
			      RTE_UINT16);
static cmdline_parse_token_num_t cmd_tx_3_vlan_insert_vlan_id =
	TOKEN_NUM_INITIALIZER(struct cmd_tx_3_vlan_insert_result, vlan_id,
			      RTE_UINT16);
static cmdline_parse_token_string_t cmd_tx_3_vlan_insert_on_off =
	TOKEN_STRING_INITIALIZER(struct cmd_tx_3_vlan_insert_result, on_off,
				 "on#off");

static void cmd_cmd_tx_3_vlan_insert_parse(void *parsed_result,
					   __rte_unused struct cmdline *cl,
					   __rte_unused void *data)
{
	struct cmd_tx_3_vlan_insert_result *res = parsed_result;
	struct rte_eth_dev *dev;
	struct mce_tx_queue *txq;
	int i = 0;
	int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	if (is_on) {
		for (i = 0; i < dev->data->nb_tx_queues; i++) {
			txq = (struct mce_tx_queue *)dev->data->tx_queues[i];
			txq->vlan3_insert_en = 1;
			txq->vlan_id = res->vlan_id;
		}
	} else {
		for (i = 0; i < dev->data->nb_tx_queues; i++) {
			txq = (struct mce_tx_queue *)dev->data->tx_queues[i];
			txq->vlan3_insert_en = 0;
			txq->vlan_id = 0;
		}
	}
}

static cmdline_parse_inst_t cmd_tx_3_vlan_insert = {
	.f = cmd_cmd_tx_3_vlan_insert_parse,
	.data = NULL,
	.help_str = "set vlan3 insert <port_id> <vlan_id> on|off",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_tx_3_vlan_insert_set,
			(void *)&cmd_tx_3_vlan_insert_vlan3,
			(void *)&cmd_tx_3_vlan_insert_insert,
			(void *)&cmd_tx_3_vlan_insert_port,
			(void *)&cmd_tx_3_vlan_insert_vlan_id,
			(void *)&cmd_tx_3_vlan_insert_on_off,
			NULL,
		},
	/* clang-format on */
};

/* Common result structure for rx_etype_white_filter */
struct cmd_rx_etype_white_filter_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t etype;
	cmdline_fixed_string_t whitelist;
	portid_t port_id;
	uint16_t loc;
	uint16_t etype_id;
	cmdline_fixed_string_t on_off;
};

/* Common result structure for rx_etype_white_filter */
struct cmd_dcbsetget_conf {
	cmdline_fixed_string_t dcbgetset;
	portid_t port_id;
	cmdline_fixed_string_t ver_name;
	cmdline_fixed_string_t up2tc_list_name;
	cmdline_fixed_string_t up2tc_list_of_items;
	cmdline_fixed_string_t tcbw_list_name;
	cmdline_fixed_string_t tcbw_list_of_items;
	cmdline_fixed_string_t tsa_list_name;
	cmdline_fixed_string_t tsa_list_of_items;
	cmdline_fixed_string_t pfc_list_name;
	cmdline_fixed_string_t pfc_list_of_items;
};

static cmdline_parse_token_string_t cmd_config_dcbgetset =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, dcbgetset,
				 "dcbgetset");
static cmdline_parse_token_num_t cmd_dcbsetget_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_dcbsetget_conf, port_id, RTE_UINT16);
static cmdline_parse_token_string_t cmd_dcbgetset_conf_ver =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, ver_name, "ieee");
static cmdline_parse_token_string_t cmd_dcbgetset_up2tc =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, up2tc_list_name,
				 "up2tc");
static cmdline_parse_token_string_t cmd_dcbgetset_up2tc_list_of_items =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, up2tc_list_of_items,
				 NULL);
static cmdline_parse_token_string_t cmd_dcbgetset_tcbw =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, tcbw_list_name,
				 "tcbw");
static cmdline_parse_token_string_t cmd_dcbgetset_tcbw_list_of_items =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, tcbw_list_of_items,
				 NULL);
static cmdline_parse_token_string_t cmd_dcbgetset_tsa =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, tsa_list_name,
				 "tsa");
static cmdline_parse_token_string_t cmd_dcbgetset_tsa_list_of_item =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, tsa_list_of_items,
				 NULL);
static cmdline_parse_token_string_t cmd_dcbgetset_pfc =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, pfc_list_name,
				 "pfc");
static cmdline_parse_token_string_t cmd_dcbgetset_pfc_list_of_items =
	TOKEN_STRING_INITIALIZER(struct cmd_dcbsetget_conf, pfc_list_of_items,
				 NULL);

static int mce_dcb_conf_split(char *str, const char *split_key, uint8_t *data,
			      uint8_t array_num)
{
	char *token;
	int i = 0;

	if (str == NULL)
		return -EINVAL;
	token = strtok(str, split_key);
	while (token != NULL) {
		/* 打印子字符串 */
		printf("%s\n", token);
		data[i] = atoi(token);
		/* 获取下一个子字符串 */
		token = strtok(NULL, split_key);
		i++;
		if (i >= array_num)
			break;
	}

	return 0;
}

struct mce_dcb_info {
	uint8_t bw_limit[MCE_MAX_TC_NUM];
	uint8_t prio_tc[MCE_MAX_USER_PRIO];
	uint8_t tsa[MCE_MAX_TC_NUM];
	uint8_t pfc_en[MCE_MAX_TC_NUM];
};

static void mce_dump_dcb_info(struct mce_dcb_info *dcb)
{
	int i = 0;

	for (i = 0; i < 8; i++)
		printf("tc_bw[%d] %d\n", i, dcb->bw_limit[i]);

	for (i = 0; i < 8; i++)
		printf("priority %d => tc_num %d\n", i, dcb->prio_tc[i]);

	for (i = 0; i < 8; i++)
		printf("tc_tsa[%d => mode %d\n", i, dcb->tsa[i]);

	for (i = 0; i < 8; i++)
		printf("tc[%d] pfc_en %d\n", i, dcb->pfc_en[i]);
}

#define IEEE_8021QAZ_TSA_STRICT	   0
#define IEEE_8021QAZ_TSA_CB_SHAPER 1
#define IEEE_8021QAZ_TSA_ETS	   2

static int cmd_dcb_set_conf(struct rte_eth_dev *dev, struct mce_dcb_info *dcb)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t bw_limit = 0;
	uint8_t num_tc = 0;
	uint8_t tc_bit = 0;
	uint32_t ctrl = 0;
	int i = 0;

	for (i = 0; i < 8; i++)
		tc_bit |= RTE_BIT32(dcb->prio_tc[i]);
	num_tc = __builtin_popcount(tc_bit);
	for (i = 0; i < num_tc; i++)
		bw_limit += dcb->bw_limit[i];
	if (tc_bit > 8 || bw_limit != 100)
		return -EINVAL;
	hw->num_tc = num_tc;
	memcpy(hw->tc_prior_map, &dcb->prio_tc, sizeof(dcb->prio_tc));
	for (i = 0; i < hw->num_tc; i++) {
		switch (dcb->tsa[i]) {
		case IEEE_8021QAZ_TSA_STRICT:
			hw->tc_sched_mode[i] = MCE_DCB_TC_SCHD_SP;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			hw->tc_sched_mode[i] = MCE_DCB_TC_SCHD_ETS;
			break;
		}
		MCE_E_REG_WRITE(hw, MCE_TC_BW_PCT(i), dcb->bw_limit[i]);
	}
	ctrl = MCE_E_REG_READ(hw, MCE_TC_TM_CTRL);
	ctrl &= ~MCE_TC_SCHED_MODE;
	for (i = 0; i < hw->num_tc; i++) {
		ctrl |= RTE_BIT32(i) << MCE_TC_VALID_SHIFT;
		if (hw->tc_sched_mode[i] == MCE_DCB_TC_SCHD_ETS)
			ctrl |= MCE_TC_SCHED_ETS << i;
		else
			ctrl |= MCE_TC_SCHED_SP << i;
	}
	MCE_E_REG_WRITE(hw, MCE_TC_TM_CTRL, ctrl);

	return 0;
}

static void cmd_dcbgetset_conf_parse(void *parsed_result,
				     __rte_unused struct cmdline *cl,
				     __rte_unused void *data)
{
	struct cmd_dcbsetget_conf *res = parsed_result;
	struct mce_dcb_info dcb_conf;
	struct rte_eth_dev *dev;
	int ret = 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	memset(&dcb_conf, 0, sizeof(dcb_conf));
	mce_dcb_conf_split(res->up2tc_list_of_items, ",", &dcb_conf.prio_tc[0],
			   8);
	mce_dcb_conf_split(res->tcbw_list_of_items, ",", &dcb_conf.bw_limit[0],
			   8);
	mce_dcb_conf_split(res->tsa_list_of_items, ",", &dcb_conf.tsa[0], 8);
	mce_dcb_conf_split(res->pfc_list_of_items, ",", &dcb_conf.pfc_en[0], 8);

	mce_dump_dcb_info(&dcb_conf);
	ret = cmd_dcb_set_conf(dev, &dcb_conf);
	if (ret < 0)
		printf("dcbsetget config failed\n");
}

static cmdline_parse_inst_t cmd_dcbsetget_configure = {
	.f = cmd_dcbgetset_conf_parse,
	.data = NULL,
	.help_str =
		"dcbgetset <port_id> ieee up2tc 0,0,0,0,0,0,0,0 tcbw "
		"10,30,60,0,0,0,0,0,0 tsa 0,0,0,0,0,0,0,0 pfc 0,0,0,0,0,0,0,0",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_config_dcbgetset,
			(void *)&cmd_dcbsetget_port_id,
			(void *)&cmd_dcbgetset_conf_ver,
			(void *)&cmd_dcbgetset_up2tc,
			(void *)&cmd_dcbgetset_up2tc_list_of_items,
			(void *)&cmd_dcbgetset_tcbw,
			(void *)&cmd_dcbgetset_tcbw_list_of_items,
			(void *)&cmd_dcbgetset_tsa,
			(void *)&cmd_dcbgetset_tsa_list_of_item,
			(void *)&cmd_dcbgetset_pfc,
			(void *)&cmd_dcbgetset_pfc_list_of_items,
			NULL,
		},
	/* clang-format on */
};

/* *** READ A RING DESCRIPTOR OF A PORT RX/TX QUEUE *** */
struct cmd_read_rxd_txd_result {
	cmdline_fixed_string_t read;
	cmdline_fixed_string_t rxd_txd;
	portid_t port_id;
	uint16_t queue_id;
	uint16_t desc_id;
};

static const struct rte_memzone *
ring_dma_zone_lookup(const char *ring_name, portid_t port_id, uint16_t q_id)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;

	snprintf(mz_name, sizeof(mz_name), "eth_p%d_q%d_%s", port_id, q_id,
		 ring_name);
	mz = rte_memzone_lookup(mz_name);
	if (mz == NULL)
		fprintf(stderr,
			"%s ring memory zoneof (port %d, queue %d) not found  "
			"(zone name = %s\n",
			ring_name, port_id, q_id, mz_name);
	return mz;
}

static void ring_rx_descriptor_display(portid_t port_id,
				       const struct rte_memzone *ring_mz,
				       queueid_t rxq_id, uint16_t desc_id)
{
	struct mce_rx_queue *rxq;
	union mce_rx_desc *ring;
	union mce_rx_desc rxd;
	struct rte_eth_dev *dev;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[port_id];

	if (dev == NULL)
		return;
	rxq = dev->data->rx_queues[rxq_id];
	if (rxq == NULL) {
		printf("rxq is NULL invalid rxq_id\n");
		return;
	}
	ring = (union mce_rx_desc *)((char *)ring_mz->addr);
	rxq = dev->data->rx_queues[rxq_id];
	printf("rxq[%d] tail %d rxrearm_start %d\n", rxq->attr.index,
	       rxq->rx_tail, rxq->rxrearm_start);
	rxd.d.pkt_addr = rte_le_to_cpu_64(ring[desc_id].d.pkt_addr);
	rxd.d.rsvd1 = rte_le_to_cpu_64(ring[desc_id].d.rsvd1);
	rxd.d.rsvd2 = rte_le_to_cpu_64(ring[desc_id].d.rsvd2);
	rxd.d.rsvd3 = rte_le_to_cpu_64(ring[desc_id].d.rsvd3);
	printf("    0x%08lX - 0x%08lX 0x%08lX - 0x%08lX\n",
	       (uint64_t)rxd.d.pkt_addr, (uint64_t)rxd.d.rsvd1,
	       (uint64_t)rxd.d.rsvd2, (uint64_t)rxd.d.rsvd3);
}

static void mce_rx_ring_desc_display(portid_t port_id, queueid_t rxq_id,
				     uint16_t rxd_id)
{
	const struct rte_memzone *rx_mz;
	rx_mz = ring_dma_zone_lookup("rx_ring", port_id, rxq_id);
	if (rx_mz == NULL)
		return;
	ring_rx_descriptor_display(port_id, rx_mz, rxq_id, rxd_id);
}

static void ring_tx_descriptor_display(const struct rte_memzone *ring_mz,
				       uint16_t desc_id)
{
	union mce_tx_desc *ring;
	union mce_tx_desc txd;

	ring = (union mce_tx_desc *)ring_mz->addr;
	txd.wb.rsvd1 = rte_le_to_cpu_64(ring[desc_id].wb.rsvd1);
	txd.wb.rsvd2 = rte_le_to_cpu_64(ring[desc_id].wb.rsvd2);
	txd.wb.rsvd3 = rte_le_to_cpu_64(ring[desc_id].wb.rsvd3);
	txd.wb.rsvd4 = rte_le_to_cpu_32(ring[desc_id].wb.rsvd4);
	txd.wb.cmd = rte_le_to_cpu_32(ring[desc_id].wb.cmd);
	printf("    0x%08lX - 0x%08lX 0x%08lX - 0x%08lX - 0x%08lX\n",
	       (uint64_t)txd.wb.rsvd1, (uint64_t)txd.wb.rsvd2,
	       (uint64_t)txd.wb.rsvd3, (uint64_t)txd.wb.rsvd4,
	       (uint64_t)txd.wb.cmd);
}

static void mce_tx_ring_desc_display(portid_t port_id, queueid_t txq_id,
				     uint16_t txd_id)
{
	const struct rte_memzone *tx_mz;

	tx_mz = ring_dma_zone_lookup("tx_ring", port_id, txq_id);
	if (tx_mz == NULL)
		return;
	ring_tx_descriptor_display(tx_mz, txd_id);
}

static void cmd_read_rxd_txd_parsed(void *parsed_result,
				    __rte_unused struct cmdline *cl,
				    __rte_unused void *data)
{
	struct cmd_read_rxd_txd_result *res = parsed_result;
	struct rte_eth_dev *dev;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev) && !is_mcevf_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	if (!strcmp(res->rxd_txd, "rxd"))
		mce_rx_ring_desc_display(res->port_id, res->queue_id,
					 res->desc_id);
	else if (!strcmp(res->rxd_txd, "txd"))
		mce_tx_ring_desc_display(res->port_id, res->queue_id,
					 res->desc_id);
}

static cmdline_parse_token_string_t cmd_read_rxd_txd_read =
	TOKEN_STRING_INITIALIZER(struct cmd_read_rxd_txd_result, read,
				 "mce_read");
static cmdline_parse_token_string_t cmd_read_rxd_txd_rxd_txd =
	TOKEN_STRING_INITIALIZER(struct cmd_read_rxd_txd_result, rxd_txd,
				 "rxd#txd");
static cmdline_parse_token_num_t cmd_read_rxd_txd_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_rxd_txd_result, port_id,
			      RTE_UINT16);
static cmdline_parse_token_num_t cmd_read_rxd_txd_queue_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_rxd_txd_result, queue_id,
			      RTE_UINT16);
static cmdline_parse_token_num_t cmd_read_rxd_txd_desc_id =
	TOKEN_NUM_INITIALIZER(struct cmd_read_rxd_txd_result, desc_id,
			      RTE_UINT16);

static cmdline_parse_inst_t cmd_read_rxd_txd = {
	.f = cmd_read_rxd_txd_parsed,
	.data = NULL,
	.help_str = "mce_read rxd|txd <port_id> <queue_id> <desc_id>",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_read_rxd_txd_read,
			(void *)&cmd_read_rxd_txd_rxd_txd,
			(void *)&cmd_read_rxd_txd_port_id,
			(void *)&cmd_read_rxd_txd_queue_id,
			(void *)&cmd_read_rxd_txd_desc_id,
			NULL,
		},
	/* clang-format on */
};

/* *** configure mce fd flow mode *** */
struct cmd_fd_flow_mode_result {
	cmdline_fixed_string_t mce;
	cmdline_fixed_string_t fd_flow_mode;
	cmdline_fixed_string_t set;
	portid_t port_id;
	cmdline_fixed_string_t mode_type;
	cmdline_fixed_string_t enable_disable;
};

static void cmd_flow_mode_udp_esp_enable(struct mce_hw *hw, bool enable)
{
	uint32_t val;

	val = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
	if (enable)
		val |= MCE_FDIR_UDP_ESP_SPI_EN;
	else
		val &= ~MCE_FDIR_UDP_ESP_SPI_EN;
	MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, val);
}

static void cmd_flow_mode_tcp_sync_enable(struct mce_hw *hw, bool enable)
{
	uint32_t val;

	val = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
	if (enable)
		val |= MCE_FDIR_TCP_MODE_SYNC;
	else
		val &= ~MCE_FDIR_TCP_MODE_SYNC;
	MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, val);
}

static void cmd_flow_mode_set_parsed(void *parsed_result,
				     __rte_unused struct cmdline *cl,
				     __rte_unused void *data)
{
	struct cmd_fd_flow_mode_result *res = parsed_result;
	struct rte_eth_dev *dev;
	struct mce_hw *hw = NULL;
	bool enable = false;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	hw = MCE_DEV_TO_HW(dev);
	printf("%s:%d,mode type:%s,enable:%s\n", __func__, __LINE__,
	       res->mode_type, res->enable_disable);
	if (!strcmp(res->enable_disable, "enable")) {
		/* MCE_E_REG_WRITE(hw, MCE_FDIR_MASK_SIPV4,
		 * res->mask_value); */
		enable = true;
	}

	if (!strcmp(res->mode_type, "udp_esp")) {
		/*  MCE_E_REG_WRITE(hw, MCE_FDIR_MASK_SIPV4,
		 * res->mask_value); */
		cmd_flow_mode_udp_esp_enable(hw, enable);
	} else if (!strcmp(res->mode_type, "tcp_sync")) {
		cmd_flow_mode_tcp_sync_enable(hw, enable);
	}
	/*else if (!strcmp(res->mode_type, "tunnel_inner")) {
	    MCE_E_REG_WRITE(hw, MCE_FDIR_MASK_SIPV6_0, res->mask_value);
	}
		else if (!strcmp(res->rxd_txd, "rxbuf"))
		mce_rx_ring_buf_display(res->port_id, res->queue_id,
	res->desc_id);
	*/
}

static cmdline_parse_token_string_t cmd_fd_flow_mode_mce =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_mode_result, mce, "mce");
static cmdline_parse_token_string_t cmd_fd_flow_mode_flow_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_mode_result, fd_flow_mode,
				 "fd_flow_mode");
static cmdline_parse_token_string_t cmd_fd_flow_mode_set =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_mode_result, set, "set");
static cmdline_parse_token_num_t cmd_fd_flow_mode_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_fd_flow_mode_result, port_id,
			      RTE_UINT16);
static cmdline_parse_token_string_t cmd_fd_flow_mode_type =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_mode_result, mode_type,
				 "udp_esp#tcp_sync");
static cmdline_parse_token_string_t cmd_fd_flow_mode_enable_disable =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_mode_result, enable_disable,
				 "enable#disable");

static cmdline_parse_inst_t cmd_fd_flow_mode_set_result = {
	.f = cmd_flow_mode_set_parsed,
	.data = NULL,
	.help_str = "mce fd_flow_mode set <port_id> udp_esp|tcp_sync "
		    "enable|disable",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_fd_flow_mode_mce,
			(void *)&cmd_fd_flow_mode_flow_mode,
			(void *)&cmd_fd_flow_mode_set,
			(void *)&cmd_fd_flow_mode_port_id,
			(void *)&cmd_fd_flow_mode_type,
			(void *)&cmd_fd_flow_mode_enable_disable,
			NULL,
		},
	/* clang-format on */
};

/* *** configure mce fd flow eth_mode *** */
struct cmd_fd_flow_eth_mode_result {
	cmdline_fixed_string_t mce;
	cmdline_fixed_string_t fd_flow_mode;
	cmdline_fixed_string_t set;
	portid_t port_id;
	cmdline_fixed_string_t eth_mode;
	cmdline_fixed_string_t mac_vlan;
};

static void cmd_flow_eth_mode_set_parsed(void *parsed_result,
					 __rte_unused struct cmdline *cl,
					 __rte_unused void *data)
{
	struct cmd_fd_flow_eth_mode_result *res = parsed_result;
	struct rte_eth_dev *dev;
	struct mce_hw *hw = NULL;
	uint8_t eth_mode = MCE_FDIR_L2_M_NONE;
	uint32_t eth_mask = 0;
	uint32_t val;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	hw = MCE_DEV_TO_HW(dev);
	if (!strcmp(res->mac_vlan, "mac")) {
		eth_mode = MCE_FDIR_L2_M_MAC;
		eth_mask = MCE_FDIR_MASK_ETH_DMAC | MCE_FDIR_MASK_ETH_SMAC;
	} else if (!strcmp(res->mac_vlan, "vlan")) {
		eth_mode = MCE_FDIR_L2_M_VLAN;
		eth_mask = MCE_FDIR_MASK_ETH_VLAN;
	} else if (!strcmp(res->mac_vlan, "none")) {
		eth_mode = MCE_FDIR_L2_M_NONE;
		eth_mask = 0;
	}

	/* set eth_mode */
	val = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
	val &= ~MCE_FDIR_MATCH_L2_EN;
	val |= eth_mode << MCE_FDIR_L2_M_S;
	MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, val);

	/* set mask */
	if (eth_mask) {
		val = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
		val |= MCE_FDIR_GL_MASK_EN;
		MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, val);

		val = MCE_E_REG_READ(hw, MCE_FDIR_MASK_ETH_KEY);
		val &= ~MCE_FDIR_MASK_ETH_KEY_MASK;
		val |= eth_mask;
		MCE_E_REG_WRITE(hw, MCE_FDIR_MASK_ETH_KEY, val);
	} else {
		val = MCE_E_REG_READ(hw, MCE_FDIR_CTRL);
		val &= ~MCE_FDIR_GL_MASK_EN;
		MCE_E_REG_WRITE(hw, MCE_FDIR_CTRL, val);
	}
	return;
}

static cmdline_parse_token_string_t cmd_fd_flow_eth_mode_mce =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_eth_mode_result, mce,
				 "mce");
static cmdline_parse_token_string_t cmd_fd_flow_eth_mode_flow_mode =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_eth_mode_result,
				 fd_flow_mode, "fd_flow_mode");
static cmdline_parse_token_string_t cmd_fd_flow_eth_mode_set =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_eth_mode_result, set,
				 "set");
static cmdline_parse_token_num_t cmd_fd_flow_eth_mode_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_fd_flow_eth_mode_result, port_id,
			      RTE_UINT16);
static cmdline_parse_token_string_t cmd_fd_flow_eth_mode_type =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_eth_mode_result, eth_mode,
				 "eth_mode");
static cmdline_parse_token_string_t cmd_fd_flow_eth_mode_mac_vlan =
	TOKEN_STRING_INITIALIZER(struct cmd_fd_flow_eth_mode_result, mac_vlan,
				 "mac#vlan#none");

static cmdline_parse_inst_t cmd_fd_flow_eth_mode_set_result = {
	.f = cmd_flow_eth_mode_set_parsed,
	.data = NULL,
	.help_str = "mce fd_flow_mode set <port_id> eth_mode mac|vlan|none",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_fd_flow_eth_mode_mce,
			(void *)&cmd_fd_flow_eth_mode_flow_mode,
			(void *)&cmd_fd_flow_eth_mode_set,
			(void *)&cmd_fd_flow_eth_mode_port_id,
			(void *)&cmd_fd_flow_eth_mode_type,
			(void *)&cmd_fd_flow_eth_mode_mac_vlan,
			NULL,
		},
	/* clang-format on */
};

/* *** configure mce fd flow eth_mode *** */
struct cmd_ip_link_result {
	cmdline_fixed_string_t ip;
	cmdline_fixed_string_t link;
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t port;
	portid_t port_id;
	cmdline_fixed_string_t vf;
	uint16_t vf_num;
	cmdline_fixed_string_t rate;
	uint32_t tx_rate;
	cmdline_fixed_string_t spoofchk;
	cmdline_fixed_string_t trust;
	cmdline_fixed_string_t on_off;
};

static cmdline_parse_token_string_t cmd_ip_link_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, ip, "ip");
static cmdline_parse_token_string_t cmd_ip_link_link =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, link, "link");
static cmdline_parse_token_string_t cmd_ip_link_set =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, set, "set");
static cmdline_parse_token_string_t cmd_ip_link_port =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, port, "port");
static cmdline_parse_token_num_t cmd_ip_link_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_ip_link_result, port_id, RTE_UINT16);
static cmdline_parse_token_string_t cmd_ip_link_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, vf, "vf");
static cmdline_parse_token_num_t cmd_ip_link_vf_num =
	TOKEN_NUM_INITIALIZER(struct cmd_ip_link_result, vf_num, RTE_UINT16);
static cmdline_parse_token_string_t cmd_ip_link_rate =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, rate, "rate");
static cmdline_parse_token_num_t cmd_ip_link_tx_rate =
	TOKEN_NUM_INITIALIZER(struct cmd_ip_link_result, tx_rate, RTE_UINT32);
static cmdline_parse_token_string_t cmd_ip_link_spoofchk =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, spoofchk,
				 "spoofchk");
static cmdline_parse_token_string_t cmd_ip_link_trust =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, trust,
				 "trust");
static cmdline_parse_token_string_t cmd_ip_link_spoof_on_off =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, on_off, "on#off");
static cmdline_parse_token_string_t cmd_ip_link_trust_on_off =
	TOKEN_STRING_INITIALIZER(struct cmd_ip_link_result, on_off, "on#off");
static void cmd_vf_rate_limit_parse(void *parsed_result,
				    __rte_unused struct cmdline *cl,
				    __rte_unused void *data)
{
	struct cmd_ip_link_result *res = parsed_result;
	struct rte_eth_dev *dev;
	uint32_t tx_rate;
	uint16_t vf_num;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	tx_rate = res->tx_rate;
	vf_num = res->vf_num;
	rte_pmd_mce_set_vf_rate_limit(res->port_id, vf_num, tx_rate,
				      UINT64_MAX);

	return;
}

static void cmd_vf_anti_spoof_parse(void *parsed_result,
				    __rte_unused struct cmdline *cl,
				    __rte_unused void *data)
{
	struct cmd_ip_link_result *res = parsed_result;
	struct rte_eth_dev *dev;
	uint16_t vf_num;
	bool on = false;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	on = (!strcmp(res->on_off, "on")) ? 1 : 0;
	vf_num = res->vf_num;
	rte_pmd_mce_set_vf_mac_anti_spoof(res->port_id, vf_num, on);

	return;
}

static void cmd_vf_trust_parse(void *parsed_result,
				    __rte_unused struct cmdline *cl,
				    __rte_unused void *data)
{
	struct cmd_ip_link_result *res = parsed_result;
	struct rte_eth_dev *dev;
	uint16_t vf_num;
	bool on = false;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;
	dev = &rte_eth_devices[res->port_id];
	if (!is_mce_supported(dev)) {
		printf("port is not come from mce\n");
		return;
	}
	on = (!strcmp(res->on_off, "on")) ? 1 : 0;
	vf_num = res->vf_num;
	rte_pmd_mce_set_vf_trust(res->port_id, vf_num, on);

	return;
}

static cmdline_parse_inst_t cmd_vf_rate_limit_impl = {
	.f = cmd_vf_rate_limit_parse,
	.data = NULL,
	.help_str = "ip link set port <port_id> vf <num> rate <speed>",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_ip_link_ip,
			(void *)&cmd_ip_link_link,
			(void *)&cmd_ip_link_set,
			(void *)&cmd_ip_link_port,
			(void *)&cmd_ip_link_port_id,
			(void *)&cmd_ip_link_vf,
			(void *)&cmd_ip_link_vf_num,
			(void *)&cmd_ip_link_rate,
			(void *)&cmd_ip_link_tx_rate,
			NULL,
		},
	/* clang-format on */
};

static cmdline_parse_inst_t cmd_vf_anti_spoof_impl = {
	.f = cmd_vf_anti_spoof_parse,
	.data = NULL,
	.help_str = "ip link set port <port_id> vf <num> spoofchk on/off",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_ip_link_ip,
			(void *)&cmd_ip_link_link,
			(void *)&cmd_ip_link_set,
			(void *)&cmd_ip_link_port,
			(void *)&cmd_ip_link_port_id,
			(void *)&cmd_ip_link_vf,
			(void *)&cmd_ip_link_vf_num,
			(void *)&cmd_ip_link_spoofchk,
			(void *)&cmd_ip_link_spoof_on_off,
			NULL,
		},
	/* clang-format on */
};

static cmdline_parse_inst_t cmd_vf_trust_impl = {
	.f = cmd_vf_trust_parse,
	.data = NULL,
	.help_str = "ip link set port <port_id> vf <num> trust on/off",
	/* clang-format off */
	.tokens = {
			(void *)&cmd_ip_link_ip,
			(void *)&cmd_ip_link_link,
			(void *)&cmd_ip_link_set,
			(void *)&cmd_ip_link_port,
			(void *)&cmd_ip_link_port_id,
			(void *)&cmd_ip_link_vf,
			(void *)&cmd_ip_link_vf_num,
			(void *)&cmd_ip_link_trust,
			(void *)&cmd_ip_link_trust_on_off,
			NULL,
		},
	/* clang-format on */
};

static struct testpmd_driver_commands
	mce_cmds = { .commands = {
			     {
				     &cmd_tx_3_vlan_insert,
				     "set vlan3 insert <port_id> <vlan_id> on|off\n"
				     "    Set the thired vlan-id to insert\n",
			     },
			     {
				     &cmd_dcbsetget_configure,
				     "dcbgetset <port_id> ieee up2tc (0,..,0) tcbw (0,..,0) "
				     "tsa "
				     "(0,..,0) pfc (0,..,0)",
			     },
			     {
				     &cmd_read_rxd_txd,
				     "mce_read rxd <port_id>\n",
			     },
#if 0
	{
			&cmd_fd_flow_mask_set_result,
			"mce flow_mask set <port_id> sipv4|dipv4|sipv6_0|sipv6_1|sipv6_2|sipv6_3|dipv6_0|dipv6_1|dipv6_2|dipv6_3 <mask_value>\n",
	},
#endif
			     {
				     &cmd_fd_flow_mode_set_result,
				     "mce fd_flow_mode set <port_id> udp_esp|tcp_sync "
				     "enable|disable\n",
			     },
			     {
				     &cmd_fd_flow_eth_mode_set_result,
				     "mce fd_flow_mode set <port_id> eth_mode "
				     "mac|vlan|none\n",
			     },
			     {
				     &cmd_vf_rate_limit_impl,
				     "ip link set port <port_id> vf x rate xxxx\n",
			     },
			     {
				     &cmd_vf_anti_spoof_impl,
				     "ip link set port <port_id> vf x spoofchk on#off\n",
			     },
			     {
			             &cmd_vf_trust_impl,
				     "ip link set port <port_id> vf x trust on#off\n",
			     },
			     { NULL, NULL },
		     }
	};
TESTPMD_ADD_DRIVER_COMMANDS(mce_cmds)
