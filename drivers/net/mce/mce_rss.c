/* SPDX-License-Identifier: BSD-3-Clause
 */

#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_common.h>
#include <rte_version.h>

#include "mce.h"
#include "mce_rss.h"
#include "mce_flow.h"
#include "mce_logs.h"
#include "mce_rxtx.h"

#include "base/mce_pfvf.h"

struct mce_rss_cfg_match_pattern {
	uint64_t rss_cfg;
	uint64_t match_pattern;
};
uint8_t mce_rss_default_key[52] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25,
	0x3d, 0x43, 0xa3, 0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b,
	0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c, 0x6a,
	0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
static const struct mce_rss_cfg_match_pattern rss_match_pattern[] = {
	{ RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_OTHER |
		  RTE_ETH_RSS_FRAG_IPV4,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV4) },
	{ RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_NONFRAG_IPV6_OTHER |
		  RTE_ETH_RSS_FRAG_IPV6,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV6) },
	{ RTE_ETH_RSS_NONFRAG_IPV4_TCP,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV4) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_TCP) },
	{ RTE_ETH_RSS_NONFRAG_IPV4_UDP,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV4) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_UDP) },
	{ RTE_ETH_RSS_NONFRAG_IPV4_SCTP,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV4) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_SCTP) },
	{ RTE_ETH_RSS_NONFRAG_IPV6_TCP,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV6) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_TCP) },
	{ RTE_ETH_RSS_NONFRAG_IPV6_UDP,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV6) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_UDP) },
	{ RTE_ETH_RSS_NONFRAG_IPV6_SCTP,
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV6) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_SCTP) },
	{ RTE_ETH_RSS_GTPU,
	  /* ipv4 gtp ipv4 tcp */
	  RTE_BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_IPV4) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_UDP) |
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_GTPU) |
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_GTP_PSC) |
#endif
		  RTE_BIT64(RTE_FLOW_ITEM_TYPE_TCP) },
};

static int mce_check_rss_pattern(const struct rte_flow_action_rss *rss,
				 uint64_t compose, uint16_t *inset,
				 struct rte_flow_error *error __rte_unused)
{
	uint16_t i = 0;
	bool match = false;

	for (i = 0; i < RTE_DIM(rss_match_pattern); i++) {
		if (rss->types & rss_match_pattern[i].rss_cfg &&
		    ((rss_match_pattern[i].match_pattern & compose) ==
		     compose)) {
			match = true;
			break;
		}
	}
	if (rss->types && match)
		*inset |= MCE_RSS_INSET_TYPE;

	return 0;
}

static int mce_parse_rss_action(struct mce_vport *vport, uint16_t *inset,
				uint64_t compose,
				struct mce_flow_action *action_conf,
				struct rte_flow_error *error)
{
	struct rte_flow_action_rss *rss = &action_conf->rss;
	uint16_t idx;

	if (action_conf->rss_cfg == 0)
		return 0;

	if (rss->func)
		*inset |= MCE_RSS_INSET_FUNC;
#if RTE_VERSION_NUM(20, 8, 0, 0) >= RTE_VERSION
	/* Workaround Testpmd BUG */
	const char *testpmd_key = "testpmd's default RSS hash key, "
				  "override it for better balancing";
	if (rss->key_len == MCE_MAX_HASH_KEY_SIZE * 4 &&
	    !memcmp(rss->key, testpmd_key, MCE_MAX_HASH_KEY_SIZE * 4))
		rss->key_len = 0;
#endif
	if (rss->key_len && rss->key_len != MCE_MAX_HASH_KEY_SIZE)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, rss,
			"RSS hash key must be exactly 52 bytes");
	if (rss->queue_num && rss->queue_num > vport->dev->data->nb_rx_queues)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, rss,
			"Redirect Queues Is Out Of Max Queue Num");
	if (rss->queue_num) {
		for (idx = 0; idx < rss->queue_num; idx++) {
			if (rss->queue[idx] &&
			    rss->queue[idx] > vport->dev->data->nb_rx_queues) {
				return rte_flow_error_set(
					error, ENOTSUP,
					RTE_FLOW_ERROR_TYPE_ACTION, rss,
					"Queue Index Is Out Of Range "
					"Of Set Max Queues Num");
			}
		}
		*inset |= MCE_RSS_INSET_QUEUE;
	}
	if (rss->types && (!(rss->types & MCE_SUPPORT_RSS_OFFLOAD_ALL)))
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss,
					  "RSS type Is Not Support");
	if (rss->key && rss->key_len)
		*inset |= MCE_RSS_INSET_KEY;
	if (rss->types)
		return mce_check_rss_pattern(rss, compose, inset, error);

	return 0;
}
#endif

/**
 * @brief Configure RSS hash key and hash function for a vport.
 *
 * Program the device RSS key, hash function and RSS offload mode according
 * to the provided `rss_conf` for the Ethernet device `dev`.
 *
 * @param dev
 *   Pointer to the Ethernet device.
 * @param rss_conf
 *   RSS configuration containing key, hash flags and algorithm.
 * @return
 *   0 on success, negative errno on failure.
 */
int mce_rss_hash_set(struct rte_eth_dev *dev, struct rte_eth_rss_conf *rss_conf)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint32_t attr_base = hw->vp_reg_base[MCE_VP_ATTR];
	uint32_t rss_base = hw->vp_reg_base[MCE_VP_RSS];
	uint32_t mrqc_reg = 0;
	uint32_t vp_attr = 0;
	__maybe_unused uint16_t vport_id = 0;
	uint8_t *hash_key;
	uint32_t rss_key;
	uint64_t rss_hf;
	uint8_t i;

	vport_id = vport->attr.vport_id;
	hash_key = rss_conf->rss_key;
	rss_hf = rss_conf->rss_hf;
	if (hash_key != NULL) {
		for (i = 0; i < MCE_MAX_HASH_KEY_SIZE; i++) {
			rss_key = hash_key[(i * 4)];
			rss_key |= hash_key[(i * 4) + 1] << 8;
			rss_key |= hash_key[(i * 4) + 2] << 16;
			rss_key |= hash_key[(i * 4) + 3] << 24;
			rss_key = rte_cpu_to_be_32(rss_key);

			MCE_E_REG_WRITE(hw, MCE_RSS_KEY_ENTRY(rss_base, i), rss_key);
		}
	}
	mrqc_reg = MCE_E_REG_READ(hw, MCE_RSS_FUNC_SET(rss_base));
	mrqc_reg &= ~MCE_RSS_INPUT_MASK;
	mrqc_reg &= ~MCE_RSS_FUNC_MASK;
	for (i = 0; i < RTE_DIM(mce_rss_cfg); i++)
		if (mce_rss_cfg[i].rss_flag & rss_hf)
			mrqc_reg |= mce_rss_cfg[i].reg_val;
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
	switch (rss_conf->algorithm) {
	case RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ_SORT:
		mrqc_reg |= MCE_RSS_HASH_FUNC_ORDER_EN;
		mrqc_reg |= MCE_RSS_HASH_FUNC_XOR_EN;
		break;
	case RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ:
		mrqc_reg |= MCE_RSS_HASH_FUNC_XOR_EN;
		break;
	default:
		break;
	}
#endif
	if (mrqc_reg)
		mrqc_reg |= MCE_RSS_HASH_FUNC_EN;
	else
		mrqc_reg &= ~MCE_RSS_HASH_FUNC_EN;
	MCE_E_REG_WRITE(hw, MCE_RSS_FUNC_SET(rss_base), mrqc_reg);
	if (rss_hf & RTE_ETH_RSS_LEVEL_MASK) {
		vp_attr = MCE_E_REG_READ(hw, attr_base);
		vp_attr &= ~MCE_FWD_TUNNEL_CTRL_MASK;
		vp_attr |= MCE_FWD_TUNNEL_CTRL_EN;
		switch (rss_hf & RTE_ETH_RSS_LEVEL_MASK) {
		case RTE_ETH_RSS_LEVEL_INNERMOST:
			vp_attr |= MCE_FWD_SECLECT_INNER;
			vport->attr.inner_rss_en = 1;
			break;
		case RTE_ETH_RSS_LEVEL_OUTERMOST:
		case RTE_ETH_RSS_LEVEL_PMD_DEFAULT:
			vport->attr.inner_rss_en = 0;
		}
		MCE_E_REG_WRITE(hw, MCE_VF_FWD_ATTR, attr_base);
	} else {
		vport->attr.inner_rss_en = 0;
	}
	vport->rss_en = ENABLE;
	vport->rss_hf = rss_hf;

	return 0;
}

/**
 * @brief Update the RSS redirection table (RETA).
 *
 * Populate the device RETA according to `reta_conf` and program the
 * internal lookup table for `dev`.
 *
 * @param dev
 *   Pointer to the Ethernet device.
 * @param reta_conf
 *   RETA configuration entries.
 * @param reta_size
 *   Size (in groups) of the provided RETA configuration.
 * @return
 *   0 on success, negative errno on failure.
 */
int mce_rss_reta_update(struct rte_eth_dev *dev,
			struct rte_eth_rss_reta_entry64 *reta_conf,
			uint16_t reta_size)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	uint32_t *lut = vport->lut;
	uint16_t *reta = NULL;
	uint16_t idx, shift;
	uint16_t lut_size;
	int i = 0;

	if (!lut) {
		PMD_DRV_LOG(ERR, "No memory can be allocated");
		return -ENOMEM;
	}
	lut_size = vport->attr.max_reta_num * 2;
	memset(lut, 0, lut_size);
	reta = rte_zmalloc(NULL, reta_size, 0);
	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_ETH_RETA_GROUP_SIZE;
		shift = i % RTE_ETH_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			reta[i] = reta_conf[idx].reta[shift];
	}
	memcpy((uint16_t *)lut, (uint16_t *)reta, lut_size);
	mce_setup_rss_reta(vport, lut);
	rte_free(reta);

	return 0;
}

/**
 * @brief Query the device RETA into the provided buffer.
 *
 * Reads the current RSS redirection table for `dev` and fills `reta_conf`.
 *
 * @param dev
 *   Pointer to the Ethernet device.
 * @param reta_conf
 *   Output buffer for RETA entries.
 * @param reta_size
 *   Size (in groups) of the provided RETA buffer.
 * @return
 *   0 on success, negative errno on failure.
 */
int mce_rss_reta_query(struct rte_eth_dev *dev,
			   struct rte_eth_rss_reta_entry64 *reta_conf,
			   uint16_t reta_size)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	uint16_t i, idx, shift;
	uint16_t *reta;

	if (reta_size > MCE_MAX_RETA_LOC_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid reta size, reta_size:%d", reta_size);
		return -EINVAL;
	}
	reta = (uint16_t *)vport->lut;
	mce_get_rss_reta(vport, vport->lut);
	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_ETH_RETA_GROUP_SIZE;
		shift = i % RTE_ETH_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			reta_conf[idx].reta[shift] = reta[i];
	}

	return 0;
}

/**
 * @brief Retrieve current RSS hash configuration.
 *
 * Populates `rss_conf` with the RSS key, hash flags and algorithm
 * currently active on the device `dev`.
 *
 * @param dev
 *   Pointer to the Ethernet device.
 * @param rss_conf
 *   Output structure to receive RSS configuration.
 * @return
 *   0 on success, negative errno on failure.
 */
int mce_rss_hash_conf_get(struct rte_eth_dev *dev,
			  struct rte_eth_rss_conf *rss_conf)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t vport_id __maybe_unused = vport->attr.vport_id;
	uint32_t rss_base = hw->vp_reg_base[MCE_VP_RSS];
	uint32_t rss_key = 0;
	uint32_t rss_mode;
	uint8_t *hash_key;
	uint64_t rss_hf = 0;
	uint32_t i = 0;

	hash_key = rss_conf->rss_key;
	if (hash_key) {
		for (i = 0; i < MCE_MAX_HASH_KEY_SIZE; i++) {
			rss_key = MCE_E_REG_READ(hw, MCE_RSS_KEY_ENTRY(rss_base, i));
			rss_key = rte_be_to_cpu_32(rss_key);
			hash_key[(i * 4)] = rss_key & 0x000000FF;
			hash_key[(i * 4) + 1] = (rss_key >> 8) & 0x000000FF;
			hash_key[(i * 4) + 2] = (rss_key >> 16) & 0x000000FF;
			hash_key[(i * 4) + 3] = (rss_key >> 24) & 0x000000FF;
		}
	}
	rss_mode = MCE_E_REG_READ(hw, MCE_RSS_FUNC_SET(rss_base));
	if (rss_mode == 0) {
		rss_conf->rss_hf = 0;
		return 0;
	}
	for (i = 0; i < RTE_DIM(mce_rss_cfg); i++)
		if (mce_rss_cfg[i].reg_val & rss_mode)
			rss_hf |= mce_rss_cfg[i].rss_flag;
	if (vport->attr.inner_rss_en)
		rss_hf |= RTE_ETH_RSS_LEVEL_INNERMOST;
	rss_conf->rss_hf = rss_hf;
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
	switch ((rss_mode & MCE_RSS_FUNC_MASK) >> 29) {
	case 4:
		rss_conf->algorithm = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
		break;
	case 7:
		rss_conf->algorithm = RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ_SORT;
		break;
	case 6:
		rss_conf->algorithm = RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
	}
#endif

	return 0;
}

static int mce_disable_rss(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	uint16_t vport_id __maybe_unused = vport->attr.vport_id;
	uint32_t rss_base = hw->vp_reg_base[MCE_VP_RSS];

	MCE_E_REG_WRITE(hw, MCE_RSS_FUNC_SET(rss_base), RTE_BIT32(31));
	vport->rss_en = DISABLE;

	return 0;
}

#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
static int mce_rss_flow_parse(struct mce_vport *vport, void **o_parm,
			      const struct rte_flow_attr *attr __rte_unused,
			      const struct rte_flow_item pattern[],
			      const struct rte_flow_action actions[],
			      struct rte_flow_error *error)
{
	struct mce_rss_rule **rule = (struct mce_rss_rule **)o_parm;
	const struct rte_flow_action *act = actions;
	const struct rte_flow_item *item = pattern;
	struct mce_rss_rule *tmp = NULL;
	struct mce_flow_action action_conf;
	uint64_t item_compose = 0;
	uint16_t inset = 0;
	uint8_t act_mark_cnt = 0;
	uint8_t act_rss_cnt = 0;
	uint8_t act_pop_cnt = 0;
	int ret = -EINVAL;

	/* 1.define filter enging can support pattern compose */
	/* 2.check the pattern input options flow engine can deal */
	if (pattern == NULL)
		return -EINVAL;
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->spec != NULL)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION, act,
				"RSS flow not support pattern spec match");

		item_compose |= RTE_BIT64(item->type);
	}
	/* check use set item for mark flow type for rss */
	memset(&action_conf, 0, sizeof(action_conf));
	item = pattern;
	for (; act->type != RTE_FLOW_ACTION_TYPE_END; act++) {
		switch (act->type) {
		case RTE_FLOW_ACTION_TYPE_RSS:
			memcpy(&action_conf.rss, act->conf,
			       sizeof(struct rte_flow_action_rss));
			action_conf.rss_cfg = 1;
			act_rss_cnt++;
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			memcpy(&action_conf.mark, act->conf,
			       sizeof(struct rte_flow_action_mark));
			action_conf.mark_en = 1;
			act_mark_cnt++;
			break;
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		case RTE_FLOW_ACTION_TYPE_OF_POP_VLAN:
			action_conf.pop_vlan = 1;
			act_pop_cnt++;
			break;
#endif
		default:
			return rte_flow_error_set(
				error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
				"Rss Flow Act type not supported");
		}
	}
	if (act_mark_cnt >= 2)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
			"Flow Act type Mark 1 Rule Just Support One");
	if (act_rss_cnt >= 2)
		return rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, act,
			"Flow Act type RSS 1 Rule Just Support One");
	ret = mce_parse_rss_action(vport, &inset, item_compose, &action_conf,
				   error);
	if (ret < 0)
		return ret;
	if (rule == NULL || inset == 0)
		goto finish;
	tmp = rte_zmalloc(NULL, sizeof(struct mce_rss_rule), 0);
	if (tmp == NULL)
		return -ENOMEM;
	tmp->rule_engine = MCE_RSS_FD;
	tmp->action = action_conf;
	tmp->inset = inset;
	*rule = tmp;
finish:
	return 0;
}

static void mce_rss_redirect_update(struct mce_vport *vport,
				    struct mce_rss_handle *handle,
				    struct mce_rss_rule *rule)
{
	struct mce_rx_queue *rxq = NULL;
	struct mce_hw *hw = vport->hw;
	uint32_t *lut = vport->lut;
	uint16_t max_reta_num = 0;
	uint16_t reta_size = 0;
	uint32_t act_attr = 0;
	uint16_t *ptr = NULL;
	uint16_t qid = 0;
	uint16_t i = 0;
	uint32_t attr;
	uint16_t index;

	act_attr = hw->vp_reg_base[MCE_VP_RSS_ACT];
	max_reta_num = vport->attr.max_reta_num;
	reta_size = max_reta_num / 2;
	if (rule->action.rss.queue_num) {
		memset(lut, 0, reta_size * sizeof(*lut));
		ptr = (uint16_t *)lut;
		for (i = 0; i < max_reta_num; i++) {
			index = i % rule->action.rss.queue_num;
			qid = (uint16_t)rule->action.rss.queue[index];
			qid %= vport->data->nb_rx_queues;
			rxq = vport->data->rx_queues[qid];
			if (!rxq) {
				PMD_DRV_LOG(WARNING,
						"RSS RETA cfg: RX queue %d is NULL",
						qid);
				qid = 0;
			}
			ptr[i] = qid;
		}
		mce_setup_rss_reta(vport, lut);
		for (i = 0; i < rule->action.rss.queue_num; i++) {
			qid = (uint16_t)rule->action.rss.queue[i];
			attr = MCE_E_REG_READ(hw, MCE_RSS_ACT_ATTR(act_attr, qid));
			if (!rxq) {
				PMD_DRV_LOG(WARNING,
						"RSS RETA cfg: RX queue %d is null",
						qid);
				continue;
			}
			if (rule->action.mark_en) {
				attr |= MCE_Q_ATTR_RSS_MARK_EN;
				attr &= ~MCE_Q_ATTR_RSS_MARK_MASK;
				attr |= (rule->action.mark.id &
						(UINT16_MAX - 1));
			} else {
				attr &= ~MCE_Q_ATTR_RSS_MARK_EN;
				attr &= ~MCE_Q_ATTR_RSS_MARK_MASK;
			}
			if (rule->action.pop_vlan)
				attr |= MCE_Q_ATTR_RSS_POP_VLAN_EN;
			else
				attr &= ~MCE_Q_ATTR_RSS_POP_VLAN_EN;
			MCE_E_REG_WRITE(hw, MCE_RSS_ACT_ATTR(act_attr, qid), attr);
		}
		memcpy((void *)((uintptr_t)handle->rss_cfg.queue),
		       rule->action.rss.queue,
		       sizeof(uint16_t) * rule->action.rss.queue_num);
		handle->rss_cfg.queue_num = rule->action.rss.queue_num;
	}
}

static void mce_rss_func_update(struct mce_vport *vport,
				struct mce_rss_handle *handle,
				struct mce_rss_rule *rule)
{
	struct mce_hw *hw __maybe_unused = MCE_DEV_TO_HW(vport->dev);
	struct rte_eth_rss_conf rss_conf;
	enum rte_eth_hash_function func;
	uint32_t mrqc_reg __maybe_unused = 0;
	uint32_t vp_attr __maybe_unused = 0;
	uint16_t vport_id __maybe_unused = 0;
	const uint8_t *hash_key __maybe_unused;
	uint32_t level = 0;
	uint64_t rss_hf;

	vport_id = vport->attr.vport_id;
	memset(&rss_conf, 0, sizeof(rss_conf));
	if (rule->inset & MCE_RSS_INSET_KEY) {
		hash_key = rule->action.rss.key;
		memcpy((void *)((uintptr_t)rule->action.rss.key), hash_key,
		       sizeof(uint8_t) * rule->action.rss.key_len);
	}
	if (rule->inset & MCE_RSS_INSET_TYPE) {
		rss_hf = rule->action.rss.types;
		rss_conf.rss_hf = rss_hf;
		handle->rss_cfg.types = rss_hf;
	} else {
		if (handle->rss_cfg.types)
			rss_conf.rss_hf = handle->rss_cfg.types;
		else if (vport->rss_hf)
			rss_conf.rss_hf = vport->rss_hf;
		else
			rss_conf.rss_hf = 0;
		handle->rss_cfg.types = rss_conf.rss_hf;
	}
	if (rule->inset & MCE_RSS_INSET_LEVEL) {
		level = rule->action.rss.level;
		handle->rss_cfg.level = level;
		rss_conf.rss_hf |= level;
	}
	if (rule->inset & MCE_RSS_INSET_FUNC) {
		func = rule->action.rss.func;
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
		rss_conf.algorithm = func;
#endif
		handle->rss_cfg.func = func;
	}
	mce_rss_hash_set(vport->dev, &rss_conf);
}

static int mce_rss_flow_create(struct mce_vport *vport, struct rte_flow *flow,
			       struct rte_flow_error *error)
{
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_rss_rule *rule = flow->rule;
	struct mce_rss_handle *handle = NULL;
	/* according the flow to setup the rule engine sub rule */
	if (rule == NULL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, flow,
					  "parse rule is null");
	handle = (struct mce_rss_handle *)flow_engine->handle;
	if (rule->inset & MCE_RSS_INSET_QUEUE)
		mce_rss_redirect_update(vport, handle, rule);
	mce_rss_func_update(vport, handle, rule);

	return 0;
}

static void mce_rss_reset_reta(struct mce_vport *vport,
			       struct mce_rss_handle *handle)
{
	struct mce_rx_queue *rxq = NULL;
	uint32_t *lut = vport->lut;
	uint16_t max_reta_num = 0;
	uint16_t *ptr = NULL;
	uint16_t qid;
	int i = 0;

	max_reta_num = vport->attr.max_reta_num;
	if (vport->rss_en) {
		ptr = (uint16_t *)lut;
		memset(lut, 0, (max_reta_num / 2)* sizeof(*lut));
		for (i = 0; i < max_reta_num; i++) {
			qid = i % vport->dev->data->nb_rx_queues;
			rxq = vport->data->rx_queues[qid];
			if (!rxq) {
				PMD_DRV_LOG(WARNING,
						"RSS RETA cfg: RX queue %d is NULL",
						qid);
				qid = 0;
			}
			ptr[i] = qid;
		}
		memset((void *)((uintptr_t)handle->rss_cfg.queue), 0,
		       sizeof(uint16_t) * max_reta_num);
		handle->rss_cfg.queue_num = vport->data->nb_rx_queues;
	} else {
		memset(vport->lut, 0, vport->attr.max_reta_num * 4);
		memset((void *)((uintptr_t)handle->rss_cfg.queue), 0,
		       sizeof(uint16_t) * vport->attr.max_reta_num);
		handle->rss_cfg.queue_num = 0;
	}
	mce_setup_rss_reta(vport, vport->lut);
}

static void mce_rss_reset_hash(struct mce_vport *vport,
			       struct mce_rss_handle *handle,
			       struct mce_rss_rule *rule)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(vport->dev);
	enum rte_eth_hash_function func;
	uint8_t *hash_key = NULL;
	uint32_t mrqc_reg = 0;
	uint16_t vport_id __maybe_unused = 0;
	uint32_t vp_attr = 0;
	uint64_t level = 0;
	uint32_t rss_key = 0;
	uint64_t rss_hf = 0;
	uint8_t i;

	vport_id = vport->attr.vport_id;
	if (vport->rss_en) {
		if (rule->inset & MCE_RSS_INSET_KEY)
			hash_key = mce_rss_default_key;
		if (rule->inset & MCE_RSS_INSET_TYPE)
			rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6;
		if (rule->inset & MCE_RSS_INSET_LEVEL)
			level = RTE_ETH_RSS_LEVEL_OUTERMOST;
		if (rule->inset & MCE_RSS_INSET_FUNC)
			func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
	} else {
		hash_key = NULL;
		rss_hf = 0;
		level = 0;
		handle->rss_cfg.types = 0;
	}
	if (hash_key != NULL)
		for (i = 0; i < MCE_MAX_HASH_KEY_SIZE; i++) {
			rss_key = hash_key[(i * 4)];
			rss_key |= hash_key[(i * 4) + 1] << 8;
			rss_key |= hash_key[(i * 4) + 2] << 16;
			rss_key |= hash_key[(i * 4) + 3] << 24;
			rss_key = rte_cpu_to_be_32(rss_key);
			MCE_E_REG_WRITE(hw, MCE_ETH_RSS_KEY_ENTRY(vport_id, i),
					rss_key);
		}

	for (i = 0; i < RTE_DIM(mce_rss_cfg); i++)
		if (mce_rss_cfg[i].rss_flag & rss_hf)
			mrqc_reg |= mce_rss_cfg[i].reg_val;
	switch (func) {
	case RTE_ETH_HASH_FUNCTION_TOEPLITZ:
		mrqc_reg |= MCE_RSS_HASH_FUNC_EN;
		break;
#if RTE_VERSION_NUM(23, 11, 0, 0) <= RTE_VERSION
	case RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ_SORT:
		mrqc_reg |= MCE_RSS_HASH_FUNC_ORDER_EN;
		mrqc_reg |= MCE_RSS_HASH_FUNC_XOR_EN;
		break;
#endif
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
	case RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ:
		mrqc_reg |= MCE_RSS_HASH_FUNC_XOR_EN;
		break;
#endif
	default:
		mrqc_reg |= MCE_RSS_HASH_FUNC_EN;
		break;
	}
	mrqc_reg |= MCE_RSS_HASH_FUNC_EN;
	MCE_E_REG_WRITE(hw, MCE_ETH_RSS_FUNC_SET(vport_id), mrqc_reg);
	/* update rss tunnel select */
	vp_attr = MCE_E_REG_READ(hw, MCE_ETH_FWD_ATTR(vport_id));
	vp_attr |= MCE_FWD_TUNNEL_CTRL_EN;
	switch (level) {
	case RTE_ETH_RSS_LEVEL_INNERMOST:
		vp_attr |= MCE_FWD_SECLECT_INNER;
		break;
	default:
		vp_attr &= ~MCE_FWD_TUNNEL_CTRL_EN;
	}
	MCE_E_REG_WRITE(hw, MCE_ETH_FWD_ATTR(vport_id), vp_attr);
}

static int mce_rss_flow_delate(struct mce_vport *vport, struct rte_flow *flow,
			       struct rte_flow_error *error)
{
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_rss_rule *rule = flow->rule;
	struct mce_rss_handle *handle = NULL;

	if (rule == NULL)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ITEM, flow,
					  "delete rss rule is null");
	handle = (struct mce_rss_handle *)flow_engine->handle;
	if (rule->inset & MCE_RSS_INSET_QUEUE)
		mce_rss_reset_reta(vport, handle);
	mce_rss_reset_hash(vport, handle, rule);

	return 0;
}

static int mce_rss_flow_engine_init(struct mce_vport *vport __rte_unused,
				    void **handle)
{
	struct mce_rss_handle *tmp;

	tmp = rte_zmalloc(NULL, sizeof(struct mce_rss_handle), 0);
	if (tmp == NULL)
		return -ENOMEM;
	tmp->rss_cfg.key =
		rte_zmalloc(NULL, sizeof(uint8_t) * MCE_MAX_HASH_KEY_SIZE, 0);
	tmp->rss_cfg.queue =
		rte_zmalloc(NULL, sizeof(uint16_t) * MCE_MAX_RETA_LOC_SIZE, 0);
	if (tmp->rss_cfg.key == NULL || tmp->rss_cfg.queue == NULL)
		return -ENOMEM;
	memcpy((void *)((uintptr_t)tmp->rss_cfg.key), mce_rss_default_key,
	       sizeof(mce_rss_default_key));
	*handle = tmp;

	return 0;
}

static int mce_rss_flow_engine_uinit(struct mce_vport *vport __rte_unused,
				     void *handle)
{
	if (handle)
		rte_free(handle);

	return 0;
}
#endif /* RTE_VERSION >= 18.11 */
/**
 * @brief Configure RSS for a device based on ethdev settings.
 *
 * Reads the RSS configuration from `dev->data->dev_conf` and programs
 * device RSS key, RETA and mode accordingly. If RSS is disabled in the
 * configuration, the device RSS is disabled.
 *
 * @param dev
 *   Pointer to the Ethernet device.
 * @return
 *   0 on success, negative errno on failure.
 */
int mce_dev_rss_configure(struct rte_eth_dev *dev)
{
	enum rte_eth_rx_mq_mode mq_mode = dev->data->dev_conf.rxmode.mq_mode;
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct rte_eth_rss_conf rss_conf;
	struct mce_rx_queue *rxq;
	uint32_t *lut = vport->lut;
	uint16_t max_reta_num = 0;
	uint16_t qid = 0;
	uint16_t *ptr;
	int i;

	rss_conf = dev->data->dev_conf.rx_adv_conf.rss_conf;
	if (!(rss_conf.rss_hf & MCE_SUPPORT_RSS_OFFLOAD_ALL) ||
	    !(mq_mode & RTE_ETH_MQ_RX_RSS_FLAG)) {
		mce_disable_rss(dev);

		return 0;
	}
	if (rss_conf.rss_key == NULL)
		rss_conf.rss_key = mce_rss_default_key;
	max_reta_num = vport->attr.max_reta_num;
	if (dev->data->nb_rx_queues > 1) {
		mce_rss_hash_set(dev, &rss_conf);
		memset(lut, 0, (max_reta_num / 2) * sizeof(*lut));
		ptr = (uint16_t *)lut;
		for (i = 0; i < max_reta_num; i++) {
			qid = i % dev->data->nb_rx_queues;
			rxq = vport->data->rx_queues[qid];
			if (!rxq) {
				PMD_DRV_LOG(WARNING,
						"RSS RETA cfg: RX queue %d is NULL",
						qid);
				qid = 0;
			}
			ptr[i] = qid;
		}
		mce_setup_rss_reta(vport, vport->lut);
	}

	return 0;
}

#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
/**
 * @brief Query RSS flow engine state for a given `flow`.
 *
 * Copies the RSS action configuration associated with `flow` into
 * the output `out` pointer which must point to a
 * `struct rte_flow_action_rss`.
 *
 * @param vport
 *   VPort owning the flow (unused in this implementation).
 * @param flow
 *   Flow to query.
 * @param out
 *   Output buffer (expected: struct rte_flow_action_rss *).
 * @param error
 *   Error reporting structure.
 * @return
 *   0 on success, negative errno on failure.
 */
static int mce_rss_flow_query(struct mce_vport *vport __maybe_unused,
				  struct rte_flow *flow, void *out,
				  struct rte_flow_error *error)

{
	struct mce_flow_engine_module *flow_engine = flow->flow_engine;
	struct mce_rss_rule *rule = (struct mce_rss_rule *)flow->rule;
	struct rte_flow_action_rss *rss_conf = out;
	struct mce_rss_handle *handle = NULL;

	handle = (struct mce_rss_handle *)flow_engine->handle;
	if (!rule) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "Invalid rule");
		return -rte_errno;
	}
	rte_memcpy(rss_conf, &handle->rss_cfg,
		   sizeof(struct rte_flow_action_rss));

	return 0;
}
struct mce_flow_engine_module mce_rss_engine = {
	.parse = mce_rss_flow_parse,
	.create = mce_rss_flow_create,
	.destroy = mce_rss_flow_delate,
	.query = mce_rss_flow_query,
	.init = mce_rss_flow_engine_init,
	.uinit = mce_rss_flow_engine_uinit,
	.name = "rss_flow",
	.type = MCE_FLOW_RSS,
};

#endif
