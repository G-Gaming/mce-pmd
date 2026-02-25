#include <string.h>

#include "mce.h"
#include "base/mce_irq.h"
#include "mce_rxtx.h"
#include "mce_intr.h"

enum mce_ring_type { MCE_RING_TYPE_TX, MCE_RING_TYPE_RX };

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
static int mce_intr_bind(struct mce_hw *hw, enum mce_ring_type type,
			 uint16_t vec_id, uint16_t q_id)
{
	uint32_t reg = 0;

	reg = MCE_E_REG_READ(hw, MCE_RING_VEC_C(q_id));
	if (hw->is_vf) {
		reg &= ~MCE_RING_VEC_VFID_MASK;
		reg |= hw->vfnum << MCE_RING_VEC_VFID_S;
	}
	if (type == MCE_RING_TYPE_RX) {
		reg &= ~MCE_RING_VEC_RXID_MASK;
		reg |= vec_id;
	}
	if (type == MCE_RING_TYPE_TX) {
		reg &= ~MCE_RING_VEC_TXID_MASK;
		reg |= vec_id << MCE_RING_VEC_TXID_S;
	}
	MCE_E_REG_WRITE(hw, MCE_RING_VEC_C(q_id), reg);

	return 0;
}
#endif /* RTE_VERSION >= 17.02 */

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <unistd.h>
/* Macros to check for valid interrupt handle */
#define CHECK_VALID_INTR_HANDLE(intr_handle)                         \
	do {                                                         \
		if (intr_handle == NULL) {                           \
			RTE_LOG(DEBUG, EAL,                          \
				"Interrupt instance unallocated\n"); \
			rte_errno = EINVAL;                          \
			goto fail;                                   \
		}                                                    \
	} while (0)
static int rte_intr_vec_list_index_set(struct rte_intr_handle *intr_handle,
				       int index, int vec)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	if (index >= 128) {
		RTE_LOG(DEBUG, EAL, "Index %d greater than vec list size %d\n",
			index, 128);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->intr_vec[index] = vec;

	return 0;
fail:
	return -rte_errno;
}

static int rte_intr_vec_list_alloc(struct rte_intr_handle *intr_handle,
				   const char *name, int size)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	/* Vector list already allocated */
	if (intr_handle->intr_vec != NULL)
		return 0;

	if (size > RTE_MAX_RXTX_INTR_VEC_ID) {
		RTE_LOG(DEBUG, EAL, "Invalid size %d, max limit %d\n", size,
			RTE_MAX_RXTX_INTR_VEC_ID);
		rte_errno = ERANGE;
		goto fail;
	}

	intr_handle->intr_vec = rte_zmalloc(name, size * sizeof(int), 0);
	if (intr_handle->intr_vec == NULL) {
		RTE_LOG(ERR, EAL, "Failed to allocate %d intr_vec\n", size);
		rte_errno = ENOMEM;
		goto fail;
	}

	return 0;
fail:
	return -rte_errno;
}

static int rte_intr_nb_efd_get(const struct rte_intr_handle *intr_handle)
{
	CHECK_VALID_INTR_HANDLE(intr_handle);

	return intr_handle->nb_efd;
fail:
	return -rte_errno;
}
#endif /* 17.02 < RTE_VERION < 21.11 */

/**
 * @brief Enable RX queue interrupts for the device if supported.
 *
 * Configures per-RX-queue eventfds / vectors and binds DMA rings to
 * interrupt vectors where the underlying environment supports multiple
 * interrupt vectors.
 *
 * @param eth_dev Pointer to the Ethernet device.
 * @return 0 on success, negative errno on failure or -ENOTSUP if not supported.
 */
int mce_rxq_intr_enable(struct rte_eth_dev *eth_dev)
{
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
	struct rte_intr_handle *intr_handle = pci_dev->intr_handle;
#else
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
#endif
	struct mce_vport *vport = MCE_DEV_TO_VPORT(eth_dev);
	struct mce_hw *hw = vport->hw;
	struct mce_rx_queue *rxq = NULL;
	uint16_t intr_vector = 0;
	uint16_t nb_rxq = 0;
	uint16_t en_efd = 0;
	uint16_t q_id;

	if (!rte_intr_cap_multiple(intr_handle) ||
	    eth_dev->data->dev_conf.intr_conf.rxq == 0) {
		return 0;
	}

	intr_vector = eth_dev->data->nb_rx_queues;
	rte_intr_disable(intr_handle);
	if (rte_intr_efd_enable(intr_handle, intr_vector)) {
		PMD_INIT_LOG(ERR, "rte_intr_efd_enable failed");
		return -1;
	}
	if (rte_intr_dp_is_en(intr_handle))
		if (rte_intr_vec_list_alloc(intr_handle, "intr_vec",
					    eth_dev->data->nb_rx_queues)) {
			PMD_INIT_LOG(ERR,
				     "Failed to allocate %d rx_queues intr_vec",
				     eth_dev->data->nb_rx_queues);
			return -ENOMEM;
		}

	if (!rte_intr_dp_is_en(intr_handle))
		return 0;

	nb_rxq = eth_dev->data->nb_rx_queues;
	en_efd = rte_intr_nb_efd_get(intr_handle);
	if (en_efd == 0) {
		PMD_DRV_LOG(ERR, "No msix resource\n");
		return -EINVAL;
	}
	uint16_t vec = 0;
	uint16_t base = 0;
	uint16_t index = 0;
	if (rte_intr_allow_others(intr_handle)) {
		vec = RTE_INTR_VEC_RXTX_OFFSET;
		base = RTE_INTR_VEC_RXTX_OFFSET;
	}
	for (q_id = 0; q_id < nb_rxq; q_id++) {
		rxq = eth_dev->data->rx_queues[q_id];
		index = rxq->attr.index;
		mce_intr_bind(hw, MCE_RING_TYPE_RX, vec, index);
		if (rte_intr_vec_list_index_set(intr_handle, q_id, vec))
			return -EINVAL;

		/*
		 * If there are not enough efds (e.g. not enough interrupt),
		 * remaining queues will be bond to the last interrupt.
		 */
		if (vec < base + rte_intr_nb_efd_get(intr_handle) - 1)
			vec++;
	}
	rte_intr_enable(intr_handle);
#if RTE_VERSION_NUM(19, 8, 0, 0) <= RTE_VERSION
	rte_intr_ack(intr_handle);
#endif

	return 0;
#else
	RTE_SET_USED(eth_dev);
	return -ENOTSUP;
#endif
}

/**
 * @brief Enable interrupt for a specific RX queue.
 *
 * @param dev Pointer to the Ethernet device.
 * @param qidx Queue index to enable interrupt for.
 * @return 0 on success, -EINVAL for invalid queue index, or -ENOTSUP.
 */
int mce_dev_rx_queue_intr_enable(struct rte_eth_dev *dev, uint16_t qidx)
{
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = vport->hw;
	struct mce_rx_queue *rxq = NULL;
	uint16_t index = 0;
	uint32_t ctrl = 0;

	if (qidx < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[qidx];
		index = rxq->attr.index;
		ctrl = MCE_E_REG_READ(hw, MCE_DMA_INT_MASK(index));
		ctrl &= ~MCE_RX_INT_MASK;
		ctrl |= RTE_BIT32(16);
		MCE_E_REG_WRITE(hw, MCE_DMA_INT_MASK(index), ctrl);
	} else
		return -EINVAL;

	return 0;
#else
	RTE_SET_USED(dev);
	RTE_SET_USED(qidx);
	return -ENOTSUP;
#endif
}

/**
 * @brief Disable interrupt for a specific RX queue.
 *
 * @param dev Pointer to the Ethernet device.
 * @param qidx Queue index to disable interrupt for.
 * @return 0 on success, -EINVAL for invalid queue index, or -ENOTSUP.
 */
int mce_dev_rx_queue_intr_disable(struct rte_eth_dev *dev, uint16_t qidx)
{
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
	struct mce_vport *vport = MCE_DEV_TO_VPORT(dev);
	struct mce_hw *hw = vport->hw;
	struct mce_rx_queue *rxq = NULL;
	uint16_t index = 0;
	uint32_t ctrl = 0;

	if (qidx < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[qidx];
		index = rxq->attr.index;
		ctrl = MCE_E_REG_READ(hw, MCE_DMA_INT_MASK(index));
		ctrl |= MCE_RX_INT_MASK;
		ctrl |= RTE_BIT32(17);
		MCE_E_REG_WRITE(hw, MCE_DMA_INT_MASK(index), ctrl);
	} else {
		return -EINVAL;
	}

	return 0;
#else
	RTE_SET_USED(dev);
	RTE_SET_USED(qidx);
	return -ENOTSUP;
#endif
}
