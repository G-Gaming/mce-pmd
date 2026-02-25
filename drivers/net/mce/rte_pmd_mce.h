#ifndef _RTE_PMD_MCE_H_
#define _RTE_PMD_MCE_H_

#include <rte_compat.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

/**
 * @brief Set the transmit rate limit for a VF on a given port.
 *
 * @param port The port identifier.
 * @param vf The virtual function index.
 * @param tx_rate Transmit rate limit in kbps.
 * @param q_msk Queue mask indicating which queues to apply the limit to.
 *
 * @return 0 on success, negative errno on failure.
 */
int rte_pmd_mce_set_vf_rate_limit(uint16_t port, uint16_t vf, uint32_t tx_rate,
				  uint64_t q_msk);

/**
 * @brief Enable or disable MAC anti-spoofing for a VF.
 *
 * @param port The port identifier.
 * @param vf The virtual function index.
 * @param on Non-zero to enable anti-spoofing, zero to disable.
 *
 * @return 0 on success, negative errno on failure.
 */
int rte_pmd_mce_set_vf_mac_anti_spoof(uint16_t port, uint16_t vf, uint8_t on);
int rte_pmd_mce_set_vf_trust(uint16_t port, uint16_t vf, uint8_t on);
#endif /* _MCE_PMD_MCE_H_ */
