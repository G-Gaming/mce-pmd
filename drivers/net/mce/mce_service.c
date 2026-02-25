#include <stdio.h>
#include <error.h>
#include <unistd.h>

#include <rte_version.h>
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#include <rte_pci.h>
#else
#if RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
#include <rte_ethdev_pci.h>
#else
#include <ethdev_pci.h>
#endif
#endif
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION

#include "mce_service.h"
#include "mce_logs.h"
#include "mce_compat.h"

int mce_register_services(const char *service_name, rte_service_func func,
			  void *arg)
{
	struct rte_service_spec spec_service = {
		.callback = func,
		.callback_userdata = (void *)arg,
	};
	uint32_t service_id;
	int ret;

	strlcpy(spec_service.name, service_name, sizeof(spec_service.name));
	/* Register the flower services */
	ret = rte_service_component_register(&spec_service, &service_id);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Could not register %s", spec_service.name);
		return -EINVAL;
	}

	PMD_INIT_LOG(INFO, "%s registered", spec_service.name);
	return service_id;
}

/**
 * @brief Register a service callback with the rte_service component.
 *
 * Registers `func` as a service component using `service_name` and
 * user data `arg`. Returns the service id on success or a negative
 * error code on failure.
 *
 * @param service_name
 *   Human readable name for the service component.
 * @param func
 *   Callback function invoked by the service framework.
 * @param arg
 *   User-provided pointer passed to the callback.
 * @return
 *   Non-negative service id on success, negative errno on failure.
 */


int mce_service_map_ctrl(uint32_t service_id)
{
	uint32_t slcore = 0;
	int32_t slcore_count;
	uint8_t service_count;
	const char *service_name;
	uint32_t slcore_array[RTE_MAX_LCORE];
	uint8_t min_service_count = UINT8_MAX;
	int32_t ret;

	slcore_count = rte_service_lcore_list(slcore_array, RTE_MAX_LCORE);
	if (slcore_count <= 0) {
		PMD_INIT_LOG(DEBUG, "No service cores found");
		return -ENOENT;
	}
	/*
	 * Find a service core with the least number of services already
	 * registered to it.
	 */
	while (slcore_count--) {
		service_count = rte_service_lcore_count_services(slcore_array[slcore_count]);
		if (service_count < min_service_count) {
			slcore = slcore_array[slcore_count];
			min_service_count = service_count;
		}
	}

	service_name = rte_service_get_name(service_id);
	PMD_INIT_LOG(INFO, "Mapping service %s to core %u", service_name,
		     slcore);

	ret = rte_service_map_lcore_set(service_id, slcore, 1);
	if (ret != 0) {
		PMD_INIT_LOG(DEBUG, "Could not map flower service");
		return -ENOENT;
	}
	ret = rte_service_runstate_set(service_id, 1);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to set service runstate: %d", ret);
		return ret;
	}
	ret =rte_service_component_runstate_set(service_id, 1);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to set component runstate: %d", ret);
		return ret;
	}
	ret = rte_service_lcore_start(slcore);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to start service lcore: %d", ret);
		return ret;
	}
#if RTE_VERSION_NUM(18, 8, 0, 0) < RTE_VERSION
	if (rte_service_may_be_active(slcore) != 0)
		PMD_INIT_LOG(INFO, "The service %s is running", service_name);
	else
		PMD_INIT_LOG(ERR, "The service %s is not running", service_name);
#endif

	return 0;
}

/**
 * @brief Map a registered service to an appropriate lcore and start it.
 *
 * Chooses a service lcore with the least number of services and maps
 * the provided `service_id` to that lcore, then starts the service.
 *
 * @param service_id
 *   Identifier of a previously registered service component.
 * @return
 *   0 on success, negative errno on failure.
 */
#endif /* HAVE_SERVICE_MASTER_CORE */
