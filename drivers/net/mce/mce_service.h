#ifndef _MCE_SERVICE_H_
#define _MCE_SERVICE_H_

#include <stdio.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
#include <rte_service_component.h>
int mce_register_services(const char *service_name, rte_service_func func,
			  void *arg);
int mce_service_map_ctrl(uint32_t service_id);
#endif /* RTE_VERSION >= 17.11 */
#endif /* _MCE_SERVICE_H_ */
