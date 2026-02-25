#include "mce.h"
#include "mce_pf.h"
#include "rte_pmd_mce.h"
#include "base/mce_sched.h"
#include "base/mce_l2_filter.h"

/**
 * @brief Internal helper to set VF transmit rate limit.
 *
 * Converts rate units and programs the hardware VF rate limiter.
 *
 * @param dev Pointer to the Ethernet device.
 * @param vf VF index to configure.
 * @param tx_rate Transmit rate in Mbps.
 * @return 0 on success, negative errno on failure.
 */
static int mce_set_vf_rate_limit(struct rte_eth_dev *dev, uint16_t vf,
				 uint64_t tx_rate)
{
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = vport->hw;
	uint64_t hw_rate = 0;

	if (vport->attr.is_vf)
		return -EINVAL;
	if (tx_rate >= vport->attr.speed)
		return -EINVAL;
	hw_rate = tx_rate * 1000 * 1000;
	printf("hw_rate %ld\n", hw_rate);
	printf("target 10g %ld\n", 10000000000);
	if (hw->max_vfs)
		vf += 1;
	return mce_set_vf_rate(hw, vf, hw_rate);
}

/**
 * @brief PMD API wrapper to set a VF transmit rate limit by port id.
 *
 * This is the public function callable by userspace via the PMD API.
 *
 * @param port Port identifier.
 * @param vf VF index.
 * @param tx_rate Transmit rate in Mbps.
 * @param q_msk Queue mask (unused currently).
 * @return 0 on success, negative errno on failure.
 */
int rte_pmd_mce_set_vf_rate_limit(uint16_t port, uint16_t vf, uint32_t tx_rate,
				  uint64_t q_msk)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);
	RTE_SET_USED(q_msk);
	dev = &rte_eth_devices[port];

	if (!is_mce_supported(dev))
		return -ENOTSUP;
	return mce_set_vf_rate_limit(dev, vf, tx_rate);
}

/**
 * @brief Internal helper to enable/disable MAC anti-spoof for a VF.
 *
 * @param dev Pointer to the Ethernet device (PF context expected).
 * @param vf VF index to configure.
 * @param on Non-zero to enable, zero to disable.
 * @return 0 on success.
 */
static int mce_set_vf_mac_anti_spoof(struct rte_eth_dev *dev, uint16_t vf,
					 uint8_t on)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(dev);
	struct mce_vf_info *vf_info = &pf->vfinfos[vf + 1];
	struct mce_hw *hw = pf->pf_vport->hw;

	vf_info->spoofchk = on;
	mce_vf_mac_spoof_ctrl(hw, vf + 1, on);

	return 0;
}

/**
 * @brief PMD API wrapper to set VF MAC anti-spoofing by port id.
 *
 * @param port Port identifier.
 * @param vf VF index.
 * @param on Non-zero to enable anti-spoofing, zero to disable.
 * @return 0 on success, negative errno on failure.
 */
int rte_pmd_mce_set_vf_mac_anti_spoof(uint16_t port, uint16_t vf, uint8_t on)
{
	struct mce_vport *vport = NULL;
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);
	dev = &rte_eth_devices[port];

	if (!is_mce_supported(dev))
		return -ENOTSUP;
	vport = MCE_DEV_TO_VPORT(dev);
	if (vport->is_vf)
		return -EINVAL;
	if (vf > vport->hw->max_vfs) {
		PMD_DRV_LOG(ERR, "Invalid vport.");
		return -EINVAL;
	}

	return mce_set_vf_mac_anti_spoof(dev, vf, on);
}

/**
 * @brief PMD API wrapper to set VF Trust by port id.
 *
 * @param port Port identifier.
 * @param vf VF index.
 * @param on Non-zero to enable trust, zero to disable.
 * @return 0 on success, negative errno on failure.
 */
int rte_pmd_mce_set_vf_trust(uint16_t port, uint16_t vf, uint8_t on)
{
	struct mce_vport *vport = NULL;
	struct mce_pf *pf = NULL;
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);
	dev = &rte_eth_devices[port];

	if (!is_mce_supported(dev))
		return -ENOTSUP;
	vport = MCE_DEV_TO_VPORT(dev);
	if (vport->is_vf)
		return -EINVAL;
	if (vf > vport->hw->max_vfs) {
		PMD_DRV_LOG(ERR, "Invalid vport.");
		return -EINVAL;
	}
	pf = MCE_DEV_TO_PF(dev);
	return mce_set_vf_trust(pf, vf, on);
}
