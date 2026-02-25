#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_version.h>
#include <rte_ether.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_dev.h>

#include "mce_flow.h"

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_flow_driver.h>
#include <rte_tailq.h>

#include "mce_logs.h"
#include "mce.h"

/**
 * @brief Return the engine-specific handle for a given flow module on a vport.
 *
 * @param vport Pointer to the vport containing registered flow engines.
 * @param type Flow module type to query.
 * @return Engine handle pointer if found, NULL otherwise.
 */
void *mce_get_engine_handle(struct mce_vport *vport, enum mce_flow_module type)
{
	struct mce_flow_engine_module *engine;

	TAILQ_FOREACH(engine, &vport->flow_engine_list, node) {
		if (engine->type == type)
			return engine->handle;
	}
	return NULL;
}
static int mce_flow_valid_rule(struct mce_vport *port, void **rule,
			       struct mce_flow_engine_module **engine,
			       const struct rte_flow_attr *attr,
			       const struct rte_flow_item pattern[],
			       const struct rte_flow_action actions[],
			       struct rte_flow_error *error)
{
	/* find a flow engine can support the input argument */
	/* use all flow engine to try parse input is support or not */
	struct mce_flow_engine_module *it, *support = NULL;
	uint8_t type = 0;
	void *temp = NULL;
	int ret = -EINVAL;

	if (attr->group) {
		switch (attr->group) {
		case 1:
			type = MCE_FLOW_FDIR;
			break;
		case 2:
			type = MCE_FLOW_GENERIC;
			break;
		case 3:
			type = MCE_FLOW_SWITCH;
			break;
		}
		RTE_TAILQ_FOREACH_SAFE(it, &port->flow_engine_list, node,
				       temp) {
			if (it->type == type)
				break;
		}
		if (it == NULL)
			goto out;
		ret = it->parse(port, rule, attr, pattern, actions, error);
		if (ret)
			goto out;
		support = it;
	} else {
		RTE_TAILQ_FOREACH_SAFE(it, &port->flow_engine_list, node,
				       temp) {
			ret = it->parse(port, rule, attr, pattern, actions,
					error);
			if (!ret) {
				support = it;
				break;
			}
		}
	}
	if (support != NULL) {
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
		if (support->type != MCE_FLOW_SWITCH && attr->transfer)
			return rte_flow_error_set(
				error, EINVAL, RTE_FLOW_ERROR_TYPE_ATTR, NULL,
				"only switch engine support transfer");
#endif
	}
	if (!ret)
		*engine = support;
out:
	if (*engine == NULL && error->message == NULL)
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_NUM,
				   NULL, "hw rule engine not support");
	return ret;
}

static int mce_flow_valid_input(const struct rte_flow_attr *attr,
				const struct rte_flow_item pattern[],
				const struct rte_flow_action actions[],
				struct rte_flow_error *error)
{
	if (!pattern) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_NUM,
				   NULL, "NULL pattern.");
		return -rte_errno;
	}

	if (!actions || actions->type == RTE_FLOW_ACTION_TYPE_END) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ACTION_NUM, NULL,
				   "NULL action.");
		return -rte_errno;
	}

	if (!attr) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ATTR,
				   NULL, "NULL attribute.");
		return -rte_errno;
	}
#if 0
	/* Must be input direction */
	if (!attr->ingress) {
		rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ATTR_INGRESS,
				attr, "Only support ingress.");
		return -rte_errno;
	}
#endif
	/* Not supported */
	if (attr->egress) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, attr,
				   "Not support egress.");
		return -rte_errno;
	}
	if (attr->priority > 1) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY, attr,
				   "Only support priority 0 and 1.");
		return -rte_errno;
	}

	return 0;
}

static int mce_flow_valid_parse_engine(struct rte_eth_dev *dev, void **rule,
				       const struct rte_flow_attr *attr,
				       const struct rte_flow_item pattern[],
				       const struct rte_flow_action actions[],
				       struct mce_flow_engine_module **engine,
				       struct rte_flow_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	int ret = 0;

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	if (dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR) {
		struct mce_vf_representor *vfr = dev->data->dev_private;

		vport = vfr->adapter->pf.pf_vport;
	}
#endif

	ret = mce_flow_valid_input(attr, pattern, actions, error);
	if (ret)
		return ret;
	return mce_flow_valid_rule(vport, rule, engine, attr, pattern, actions,
				   error);
}

/**
 * @brief Validate a flow pattern and actions against hardware capabilities.
 *
 * This function uses the registered flow engine modules to determine if the
 * requested pattern and actions can be supported on the given device.
 *
 * @param dev Ethernet device pointer.
 * @param attr Flow attributes.
 * @param pattern Flow pattern items.
 * @param actions Flow actions.
 * @param error Error structure to populate on failure.
 * @return 0 if valid, negative on error.
 */
static int mce_flow_validate(struct rte_eth_dev *dev,
				 const struct rte_flow_attr *attr,
				 const struct rte_flow_item pattern[],
				 const struct rte_flow_action actions[],
				 struct rte_flow_error *error)
{
	struct mce_flow_engine_module *engine;

	if (mce_eth_dev_is_repr(dev)) {
		struct mce_vf_representor *vfr = dev->data->dev_private;
		struct mce_pf *pf = NULL;

		pf = &vfr->adapter->pf;
		return mce_flow_valid_parse_engine(pf->dev, NULL, attr, pattern,
						   actions, &engine, error);
	}
	return mce_flow_valid_parse_engine(dev, NULL, attr, pattern, actions,
					   &engine, error);
}

/**
 * @brief Create a hardware flow based on the supplied pattern and actions.
 *
 * Allocates a `rte_flow` handle, selects an appropriate engine and invokes
 * the engine's create callback to program the rule into hardware.
 *
 * @param dev Ethernet device pointer.
 * @param attr Flow attributes.
 * @param pattern Flow pattern items.
 * @param actions Flow actions.
 * @param error Error structure to populate on failure.
 * @return Pointer to `rte_flow` on success, NULL on failure.
 */
static struct rte_flow *mce_flow_create(struct rte_eth_dev *dev,
					const struct rte_flow_attr *attr,
					const struct rte_flow_item pattern[],
					const struct rte_flow_action actions[],
					struct rte_flow_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_flow_engine_module *engine = NULL;
	struct rte_flow *flow = NULL;
	void *rule = NULL;
	int ret = 0;

	if (mce_eth_dev_is_repr(dev)) {
		struct mce_vf_representor *vfr = dev->data->dev_private;
		struct mce_pf *pf = NULL;

		pf = &vfr->adapter->pf;
		vport = MCE_DEV_TO_VPORT(pf->dev);
	}
	flow = rte_zmalloc("mce_flow", sizeof(struct rte_flow), 0);
	if (!flow) {
		rte_flow_error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "Failed to allocate memory");
		return flow;
	}

	ret = mce_flow_valid_parse_engine(dev, &rule, attr, pattern, actions,
					  &engine, error);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to parse input argument");
		rte_free(flow);
		flow = NULL;
		goto finish;
	}
	flow->flow_engine = engine;
	flow->rule = rule;
	ret = engine->create(vport, flow, error);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to create flow");
		if (flow->rule != NULL)
			rte_free(flow->rule);
		rte_free(flow);
		flow = NULL;
		goto finish;
	}
	TAILQ_INSERT_TAIL(&vport->flow_list, flow, node);
finish:
	return flow;
}

/**
 * @brief Destroy a previously created hardware flow.
 *
 * Invokes the engine-specific destroy callback and frees the `rte_flow`
 * structure if successful.
 *
 * @param dev Ethernet device pointer.
 * @param flow Pointer to the flow to be destroyed.
 * @param error Error structure to populate on failure.
 * @return 0 on success, negative errno on failure.
 */
static int mce_flow_destroy(struct rte_eth_dev *dev, struct rte_flow *flow,
				struct rte_flow_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	int ret = 0;

	if (!flow || !flow->flow_engine || !flow->flow_engine->destroy) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "Invalid flow");
		return -rte_errno;
	}
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	if (dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR) {
		struct mce_vf_representor *vfr = dev->data->dev_private;

		vport = vfr->adapter->pf.pf_vport;
	}
#endif
	ret = flow->flow_engine->destroy(vport, flow, error);
	if (!ret) {
		TAILQ_REMOVE(&vport->flow_list, flow, node);
		rte_free(flow);
	} else {
		rte_flow_error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "Failed to destroy flow");
	}

	return 0;
}

/**
 * @brief Flush all hardware flows programmed on the device.
 *
 * Iterates the vport's flow list and destroys each flow.
 *
 * @param dev Ethernet device pointer.
 * @param error Error structure to populate on failure.
 * @return 0 on success, negative errno on failure.
 */
static int mce_flow_flush(struct rte_eth_dev *dev, struct rte_flow_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct rte_flow *p_flow;
	void *temp;
	int ret = 0;

#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	if (dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR) {
		struct mce_vf_representor *vfr = dev->data->dev_private;

		vport = vfr->adapter->pf.pf_vport;
	}
#endif
	RTE_TAILQ_FOREACH_SAFE(p_flow, &vport->flow_list, node, temp) {
		ret = mce_flow_destroy(dev, p_flow, error);
		if (ret) {
			PMD_DRV_LOG(ERR, "Failed to flush flows");
			if (ret != -EAGAIN)
				ret = -EINVAL;
			return ret;
		}
	}

	return ret;
}


#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
/**
 * @brief Query flow counters or statistics for a programmed flow.
 *
 * Supports actions such as `COUNT` or `RSS` to retrieve information from the
 * engine-specific query implementation.
 *
 * @param dev Ethernet device pointer.
 * @param flow Flow handle to query.
 * @param actions Action array specifying the query type.
 * @param data Output buffer for query results.
 * @param error Error structure to populate on failure.
 * @return 0 on success, negative errno on failure.
 */
static int mce_flow_query(struct rte_eth_dev *dev, struct rte_flow *flow,
			  const struct rte_flow_action *actions, void *data,
			  struct rte_flow_error *error)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct rte_flow_query_count *count = data;
	int ret = 0;

	if (!flow || !flow->flow_engine || !flow->flow_engine->query) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE,
				   NULL, "flow query not support ");
		return -rte_errno;
	}
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	if (dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR) {
		struct mce_vf_representor *vfr = dev->data->dev_private;

		vport = vfr->adapter->pf.pf_vport;
	}
#endif
	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
		case RTE_FLOW_ACTION_TYPE_RSS:
			ret = flow->flow_engine->query(vport, flow, count,
						       error);
			break;

		default:
			ret = rte_flow_error_set(error, ENOTSUP,
						 RTE_FLOW_ERROR_TYPE_ACTION,
						 actions,
						 "action not supported");
		}
	}
	if (ret) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				   actions, "flow query failed");
		return -rte_errno;
	}

	return 0;
}
#endif

struct rte_flow_ops mce_flow_ops = {
	.validate = mce_flow_validate,
	.create = mce_flow_create,
	.destroy = mce_flow_destroy,
	.flush = mce_flow_flush,
#if RTE_VERSION_NUM(18, 5, 0, 0) <= RTE_VERSION
	.query = mce_flow_query,
#endif
};
#else
void *mce_get_engine_handle(struct mce_vport *vport, enum mce_flow_module type)
{
	RTE_SET_USED(vport);
	RTE_SET_USED(type);
	return NULL;
}
#endif
