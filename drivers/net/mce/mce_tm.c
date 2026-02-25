#include <rte_malloc.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
#include <rte_tm.h>
#include <rte_tm_driver.h>
#endif
#include <rte_tailq.h>

#include "mce_logs.h"
#include "mce_tm.h"
#include "mce.h"
#include "base/mce_sched.h"

#if RTE_VERSION_NUM(17, 8, 0, 0) <= RTE_VERSION
static inline uint32_t mce_tm_max_tx_queues_get(struct rte_eth_dev *dev)
{
	struct rte_eth_dev_info dev_info;

	memset(&dev_info, 0, sizeof(dev_info));
	if (dev->dev_ops->dev_infos_get)
		dev->dev_ops->dev_infos_get(dev, &dev_info);
	return RTE_MIN(dev_info.max_tx_queues, RTE_MAX_QUEUES_PER_PORT);
}

void mce_tm_conf_init(struct rte_eth_dev *dev)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_tm_shaper_conf *tm_conf = &vport->tm_conf;

	tm_conf->profile_max = 4;
	hw->max_tm_rate = 100000000000;
	hw->num_tc = 1;
	TAILQ_INIT(&tm_conf->shaper_profile_list);
	TAILQ_INIT(&tm_conf->qgroup_list);
	TAILQ_INIT(&tm_conf->queue_list);
}

static int mce_tm_capabilities_get(struct rte_eth_dev *dev,
				   struct rte_tm_capabilities *cap,
				   struct rte_tm_error *error)
{
	uint32_t max_tx_queues = mce_tm_max_tx_queues_get(dev);

	if (cap == NULL || error == NULL)
		return -EINVAL;

	error->type = RTE_TM_ERROR_TYPE_NONE;

	memset(cap, 0, sizeof(struct rte_tm_capabilities));

	cap->n_nodes_max = 1 + MCE_MAX_TC_NUM + max_tx_queues;
	cap->n_levels_max = MCE_TM_NODE_TYPE_MAX;
	cap->non_leaf_nodes_identical = 1;
	cap->leaf_nodes_identical = 1;
	cap->shaper_n_max = 1 + MCE_MAX_TC_NUM;
	cap->shaper_private_n_max = 1 + MCE_MAX_TC_NUM;

	cap->sched_n_children_max = max_tx_queues;
	cap->sched_sp_n_priorities_max = 1;
	cap->sched_wfq_weight_max = 1;

	cap->shaper_pkt_length_adjust_min = RTE_TM_ETH_FRAMING_OVERHEAD;
	cap->shaper_pkt_length_adjust_max = RTE_TM_ETH_FRAMING_OVERHEAD_FCS;

	return 0;
}

static struct mce_tm_shaper_profile *
mce_tm_shaper_profile_search(struct rte_eth_dev *dev,
			     uint32_t shaper_profile_id)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_shaper_profile_list *shaper_profile_list =
		&vport->tm_conf.shaper_profile_list;
	struct mce_tm_shaper_profile *shaper_profile;

	TAILQ_FOREACH(shaper_profile, shaper_profile_list, node) {
		if (shaper_profile_id == shaper_profile->shaper_profile_id)
			return shaper_profile;
	}

	return NULL;
}

static int
mce_tm_shaper_profile_param_check(struct rte_eth_dev *dev,
#if RTE_VERSION_NUM(24, 11, 0, 0) <= RTE_VERSION
				  const struct rte_tm_shaper_params *profile,
#else
				  struct rte_tm_shaper_params *profile,
#endif
				  struct rte_tm_error *error)
{
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);

	if (profile->committed.size) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_COMMITTED_RATE;
		error->message = "committed size not supvported";
		return -EINVAL;
	}

	if (profile->peak.rate > hw->max_tm_rate) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_RATE;
		error->message = "peak rate too large";
		return -EINVAL;
	}

	if (profile->peak.rate < 1) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_RATE;
		error->message = "peak rate must be at least 1Mbps";
		return -EINVAL;
	}

	if (profile->peak.size) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_PEAK_SIZE;
		error->message = "peak bucket size not supvported";
		return -EINVAL;
	}

	return 0;
}

static int mce_tm_shaper_profile_add(struct rte_eth_dev *dev,
				     uint32_t shaper_profile_id,
#if RTE_VERSION_NUM(24, 11, 0, 0) <= RTE_VERSION
				     const struct rte_tm_shaper_params *profile,
#else
				     struct rte_tm_shaper_params *profile,
#endif
				     struct rte_tm_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_tm_shaper_conf *tm_conf = &vport->tm_conf;
	struct mce_tm_shaper_profile *shaper_profile;
	int ret = -EINVAL;

	if (tm_conf->profile_user_set >= tm_conf->profile_max) {
		error->type = RTE_TM_ERROR_TYPE_UNSPECIFIED;
		error->message = "too much profiles";
		return -EINVAL;
	}
	ret = mce_tm_shaper_profile_param_check(dev, profile, error);
	if (ret)
		return ret;
	shaper_profile = mce_tm_shaper_profile_search(dev, shaper_profile_id);
	if (shaper_profile) {
		error->type = RTE_TM_ERROR_TYPE_SHAPER_PROFILE_ID;
		error->message = "profile ID exist";
		return -EINVAL;
	}
	shaper_profile = rte_zmalloc("mce_tm_shaper_profile",
				     sizeof(struct mce_tm_shaper_profile) * 2,
				     0);
	if (shaper_profile == NULL)
		return -ENOMEM;
	shaper_profile->shaper_profile_id = shaper_profile_id;
	*shaper_profile->profile = *profile;
	TAILQ_INSERT_TAIL(&tm_conf->shaper_profile_list, shaper_profile, node);
	tm_conf->profile_user_set++;

	return 0;
}

static int mce_tm_shaper_profile_del(struct rte_eth_dev *dev,
				     uint32_t shaper_profile_id,
				     struct rte_tm_error *error)
{
	RTE_SET_USED(shaper_profile_id);
	RTE_SET_USED(error);
	RTE_SET_USED(dev);

	return 0;
}

static int mce_node_param_check(struct mce_vport *vport, uint32_t node_id,
				uint32_t priority, uint32_t weight,
#if RTE_VERSION_NUM(24, 11, 0, 0) <= RTE_VERSION
				const struct rte_tm_node_params *params,
#else
				struct rte_tm_node_params *params,
#endif
				struct rte_tm_error *error)
{
	/* checked all the unsupvported parameter */
	if (node_id == RTE_TM_NODE_ID_NULL) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "invalid node id";
		return -EINVAL;
	}

	if (priority >= 8) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PRIORITY;
		error->message = "priority should be less than 8";
		return -EINVAL;
	}

	if (weight > 255 || weight < 1) {
		error->type = RTE_TM_ERROR_TYPE_NODE_WEIGHT;
		error->message = "weight must be between 1 and 200";
		return -EINVAL;
	}

	/* not supvport shared shaper */
	if (params->shared_shaper_id) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_SHAPER_ID;
		error->message = "shared shaper not supvported";
		return -EINVAL;
	}
	if (params->n_shared_shapers) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_SHAPERS;
		error->message = "shared shaper not supvported";
		return -EINVAL;
	}
	/* for non-leaf node */
	if (node_id >= vport->data->nb_tx_queues) {
#if 0
		if (params->nonleaf.wfq_weight_mode) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_WFQ_WEIGHT_MODE;
			error->message = "WFQ not supvported";
			return -EINVAL;
		}
#endif
		if (params->nonleaf.n_sp_priorities != 1) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SP_PRIORITIES;
			error->message = "SP priority not supvported";
			return -EINVAL;
		}
#if 0
		else if (params->nonleaf.wfq_weight_mode &&
				!(*params->nonleaf.wfq_weight_mode)) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_WFQ_WEIGHT_MODE;
			error->message = "WFP should be byte mode";
			return -EINVAL;
		}
#endif
	} else {
		/* for leaf node */
		if (params->leaf.cman) {
			error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS_CMAN;
			error->message = "Congestion management not supvported";
			return -EINVAL;
		}
		if (params->leaf.wred.wred_profile_id !=
		    RTE_TM_WRED_PROFILE_ID_NONE) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_WRED_PROFILE_ID;
			error->message = "WRED not supvported";
			return -EINVAL;
		}
		if (params->leaf.wred.shared_wred_context_id) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_SHARED_WRED_CONTEXT_ID;
			error->message = "WRED not supvported";
			return -EINVAL;
		}
		if (params->leaf.wred.n_shared_wred_contexts) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_N_SHARED_WRED_CONTEXTS;
			error->message = "WRED not supvported";
			return -EINVAL;
		}
	}

	return 0;
}

static int mce_tm_root_child_add(struct mce_tm_shaper_conf *tm_conf,
				 struct mce_tm_node *tm_node,
				 struct mce_tm_node *parent_node)
{
	TAILQ_INIT(&tm_node->child);
	TAILQ_INSERT_TAIL(&parent_node->child, tm_node, node);
	tm_node->level = MCE_TM_NODE_TYPE_QG;
	tm_conf->nb_qgroup_node++;
	parent_node->has_child = 1;
	parent_node->reference_count++;

	return 0;
}

static int mce_tm_qg_child_add(struct mce_tm_shaper_conf *tm_conf,
			       struct mce_tm_node *tm_node,
			       struct mce_tm_node *parent_node)
{
	if (tm_node->priority != 0 &&
	    tm_node->level != MCE_TM_NODE_TYPE_QUEUE &&
	    tm_node->level != MCE_TM_NODE_TYPE_QG)
		PMD_DRV_LOG(WARNING, "priority != 0 not supvported in level %d",
			    tm_node->level);

	if (tm_node->weight != 1 && tm_node->level != MCE_TM_NODE_TYPE_QUEUE &&
	    tm_node->level != MCE_TM_NODE_TYPE_QG)
		PMD_DRV_LOG(WARNING, "weight != 1 not supvported in level %d",
			    tm_node->level);
	TAILQ_INSERT_TAIL(&parent_node->child, tm_node, node);
	tm_node->level = MCE_TM_NODE_TYPE_QUEUE;
	tm_conf->nb_queue_node++;
	parent_node->has_child = 1;
	parent_node->reference_count++;

	return 0;
}

static inline struct mce_tm_node *mce_tm_node_search(struct rte_eth_dev *dev,
						     uint32_t node_id)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_tm_shaper_conf *tm_conf = &vport->tm_conf;
	struct mce_tm_node *tm_node;

	if (tm_conf->root && tm_conf->root->id == node_id)
		return vport->tm_conf.root;

	if (tm_conf->root == NULL)
		return NULL;
	printf("find_parent_id %d\n", node_id);
	TAILQ_FOREACH(tm_node, &tm_conf->root->child, node) {
		printf("tm_node->id %d\n", tm_node->id);
		if (tm_node->id == node_id)
			return tm_node;
	}
	printf("find node NULL\n");
	return NULL;
}

static int mce_tm_node_add(struct rte_eth_dev *dev, uint32_t node_id,
			   uint32_t parent_node_id, uint32_t priority,
			   uint32_t weight, uint32_t level_id,
#if RTE_VERSION_NUM(24, 11, 0, 0) <= RTE_VERSION
			   const struct rte_tm_node_params *params,
#else
			   struct rte_tm_node_params *params,
#endif
			   struct rte_tm_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_tm_shaper_profile *shaper_profile = NULL;
	struct mce_tm_shaper_conf *tm_conf = &vport->tm_conf;
	struct mce_hw *hw = MCE_DEV_TO_HW(dev);
	struct mce_tm_node *tm_node;
	struct mce_tm_node *parent_node;
	int ret;

	if (!params || !error)
		return -EINVAL;

	ret = mce_node_param_check(vport, node_id, priority, weight, params,
				   error);
	if (ret)
		return ret;
	/* check node already add*/
	tm_node = mce_tm_node_search(dev, node_id);
	if (tm_node) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "node id already used";
		return -EINVAL;
	}
	/* check the shaper profile id */
	if (params->shaper_profile_id != RTE_TM_SHAPER_PROFILE_ID_NONE) {
		shaper_profile = mce_tm_shaper_profile_search(
			dev, params->shaper_profile_id);
		if (!shaper_profile) {
			error->type =
				RTE_TM_ERROR_TYPE_NODE_PARAMS_SHAPER_PROFILE_ID;
			error->message = "shaper profile not exist";
			return -EINVAL;
		}
	}
	/* root node if not have a parent */
	if (parent_node_id == RTE_TM_NODE_ID_NULL) {
		/* check level */
		/* for root node level must be vport */
		if (level_id != MCE_TM_NODE_TYPE_PORT) {
			error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS;
			error->message = "Wrong level";
			return -EINVAL;
		}

		/* obviously no more than one root */
		if (vport->tm_conf.root) {
			error->type = RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID;
			error->message = "already have a root";
			return -EINVAL;
		}
		/* add the root node */
		tm_node = rte_zmalloc(NULL, sizeof(struct mce_tm_node), 0);
		if (!tm_node)
			return -ENOMEM;
		tm_node->id = node_id;
		tm_node->level = MCE_TM_NODE_TYPE_PORT;
		tm_node->parent = NULL;
		tm_node->reference_count = 0;
		tm_node->shaper_profile = shaper_profile;
		memcpy(&tm_node->params, params,
		       sizeof(struct rte_tm_node_params));
		vport->tm_conf.root = tm_node;
		TAILQ_INIT(&vport->tm_conf.root->child);

		return 0;
		;
	}
	/* check the parent node */
	parent_node = mce_tm_node_search(dev, parent_node_id);
	if (!parent_node) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID;
		error->message = "parent not exist";
		return -EINVAL;
	}
	if (parent_node->level != MCE_TM_NODE_TYPE_PORT &&
	    parent_node->level != MCE_TM_NODE_TYPE_QG) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARENT_NODE_ID;
		error->message = "parent is not valid";
		return -EINVAL;
	}
	/* check level */
	if (level_id != RTE_TM_NODE_LEVEL_ID_ANY &&
	    level_id != parent_node->level + 1) {
		error->type = RTE_TM_ERROR_TYPE_NODE_PARAMS;
		error->message = "Wrong level";
		return -EINVAL;
	}
	switch (parent_node->level) {
	case MCE_TM_NODE_TYPE_PORT:
		if (parent_node->reference_count >= hw->num_tc) {
			error->type = RTE_TM_ERROR_TYPE_NODE_ID;
			error->message = "too many queue groups";
			return -EINVAL;
		}
		break;
	case MCE_TM_NODE_TYPE_QG:
		/* check the queue number */
		if (parent_node->reference_count >= 4) {
			error->type = RTE_TM_ERROR_TYPE_NODE_ID;
			error->message = "too many queues";
			return -EINVAL;
		}
		if (node_id >= vport->data->nb_tx_queues) {
			error->type = RTE_TM_ERROR_TYPE_NODE_ID;
			error->message = "too large queue id";
			return -EINVAL;
		}
		break;
	}

	tm_node = rte_zmalloc(NULL, sizeof(struct mce_tm_node), 0);

	if (!tm_node)
		return -ENOMEM;
	tm_node->id = node_id;
	tm_node->priority = priority;
	tm_node->weight = weight;
	tm_node->reference_count = 0;
	tm_node->parent = parent_node;
	tm_node->shaper_profile = shaper_profile;
	memcpy(&tm_node->params, params, sizeof(struct rte_tm_node_params));
	if (parent_node->level == MCE_TM_NODE_TYPE_PORT)
		mce_tm_root_child_add(tm_conf, tm_node, parent_node);
	if (parent_node->level == MCE_TM_NODE_TYPE_QG)
		mce_tm_qg_child_add(tm_conf, tm_node, parent_node);

	return 0;
}

static int mce_tm_node_delete(struct rte_eth_dev *dev, uint32_t node_id,
			      struct rte_tm_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_tm_node *tm_node;
	struct mce_tm_node *it;
	bool find = false;

	if (node_id == RTE_TM_NODE_ID_NULL) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "invalid node id";
		return -EINVAL;
	}

	/* check if the node id exists */
	tm_node = mce_tm_node_search(dev, node_id);
	if (!tm_node) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "no such node";
		return -EINVAL;
	}

	/* the node should have no child */
	if (tm_node->reference_count) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "cannot delete a node which has children";
		return -EINVAL;
	}
	/* root node */
	if (tm_node->level == MCE_TM_NODE_TYPE_PORT) {
		rte_free(tm_node);
		vport->tm_conf.root = NULL;
		return 0;
	}
	TAILQ_FOREACH(it, &tm_node->parent->child, node) {
		if (it->id == node_id && tm_node == it) {
			find = true;
			break;
		}
	}
	if (!find) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "cannot find node parent";
		return -EINVAL;
	}

	TAILQ_REMOVE(&tm_node->parent->child, tm_node, node);
	tm_node->parent->reference_count--;
	rte_free(tm_node);

	return 0;
}

static int mce_tm_hierarchy_do_commit(struct mce_vport *vport,
				      int clear_on_fail,
				      struct rte_tm_error *error __rte_unused)
{
	return mce_sched_commit(vport, clear_on_fail);
}

static int mce_tm_hierarchy_commit(struct rte_eth_dev *dev, int clear_on_fail,
				   struct rte_tm_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	int ret = 0;

	ret = mce_tm_hierarchy_do_commit(vport, clear_on_fail, error);

	if (ret < 0) {
		error->type = RTE_TM_ERROR_TYPE_NODE_ID;
		error->message = "fff";
	}

	return 0;
}

static const struct rte_tm_ops mce_tm_ops = {
	.capabilities_get = mce_tm_capabilities_get,
	.shaper_profile_add = mce_tm_shaper_profile_add,
	.shaper_profile_delete = mce_tm_shaper_profile_del,
	.node_add = mce_tm_node_add,
	.node_delete = mce_tm_node_delete,
	.hierarchy_commit = mce_tm_hierarchy_commit,
};

int mce_tm_ops_get(struct rte_eth_dev *dev __rte_unused, void *arg)
{
	*(const void **)arg = &mce_tm_ops;

	return 0;
}
#endif /* HAVE_TM_MODULE */
