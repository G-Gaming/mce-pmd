/**
 * @file mce_fdir.c
 * @brief Flow Director (FDIR) packet classification implementation
 *
 * Implements hardware-based Flow Director packet classification and
 * distribution. FDIR enables intelligent packet steering based on
 * deep packet inspection (DPI):
 * - 5-tuple classification (Protocol, SIP, DIP, Sport, Dport)
 * - Tunnel-aware classification (outer and inner headers)
 * - Dynamic rule insertion and removal
 * - Hash-based rule table management
 * - Per-rule queue or drop actions
 *
 * Features:
 * - CRC32 hash computation for rule matching
 * - Rule conflict detection and management
 * - Per-VF FDIR policies
 * - Support for multiple classification levels
 * - Integration with rte_flow for rule programming
 *
 * @see mce_fdir.h for public API
 * @see mce_pattern.h for packet pattern definitions
 */

#include <stdio.h>
#include <assert.h>

#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_tailq.h>

#include "mce_osdep.h"
#include "mce_fdir.h"
#include "mce_eth_regs.h"
#include "../mce_logs.h"
#include "../mce_pattern.h"
#include "../mce.h"

static void mce_fdir_exact_encap_node(struct mce_fdir_filter *filter,
				      struct mce_fdir_node *node,
				      bool new_node);
static struct mce_fdir_node *
mce_fdir_find_insert_node(struct mce_fdir_hash_entry *hash_entry,
			  uint8_t max_entry);
/**
 * @brief Shift an array of 16-bit values right by given bit positions.
 *
 * Utility used by hash and key encoding routines to rotate/align
 * bitstreams when computing FDIR hash vectors.
 *
 * @param array Pointer to 16-bit array to modify
 * @param len Number of 16-bit elements in the array
 * @param shift Number of bits to shift right
 */
static void shift_bits_right(uint16_t *array, int len, int shift)
{
	uint16_t array_out[128];
	int i;

	shift = shift % 16;

	memset(array_out, 0, len);

	for (i = 0; i < len; i++) {
		array_out[i] = array[i] >> shift;
		if (array[i + 1] & 0x001)
			array_out[i] |= RTE_BIT32(15);
	}
	memcpy(array, array_out, len * 2);
}

/**
 * @brief Encode hardware inset keys into hash input words.
 *
 * Transforms the hw inset key fields into the packed word stream
 * used when computing the FDIR hash.
 *
 * @param hw_inset Pointer to hardware inset keys
 * @param hash_data Output hash data buffer to populate
 */
static void mce_hash_data_encode(struct mce_hw_rule_inset *hw_inset,
				 union mce_hash_data *hash_data)
{
	uint32_t *ext_key = (uint32_t *)&hw_inset->keys.inset_ex;
	uint32_t *key = (uint32_t *)&hw_inset->keys.inset;

	hash_data->hash_inset[0] = key[0];
	hash_data->hash_inset[1] = ext_key[0];
	hash_data->hash_inset[2] = ext_key[1];
	hash_data->hash_inset[3] = ext_key[2];

	hash_data->hash_inset[4] = key[1];
	hash_data->hash_inset[5] = ext_key[3];
	hash_data->hash_inset[6] = ext_key[4];
	hash_data->hash_inset[7] = ext_key[5];

	hash_data->hash_inset[8] = key[2];
	hash_data->hash_inset[9] = key[3];
}

/**
 * @brief Compute hardware FDIR hash for an inset and key.
 *
 * Converts the provided hw inset and key into the hardware-specific
 * hash value used for FDIR lookup. The returned value maps to a
 * hash-entry bucket in the software handle.
 *
 * @param handle FDIR handle used to determine hashing mode
 * @param hw_inset Hardware inset containing key/profile data
 * @param profile_id Profile identifier
 * @param vport_id VPort identifier
 * @param key Seed key used for hashing
 * @return 32-bit hash value
 */
uint32_t mce_inset_compute_hash(struct mce_fdir_handle *handle,
				struct mce_hw_rule_inset *hw_inset,
				uint16_t profile_id, uint16_t vport_id,
				uint32_t key)
{
	union mce_hash_data hash_data;
	struct mce_hash_key fdir_key;
	struct mce_hash_key key_tmp;
	union mce_ext_seg ext_seg;
	uint32_t hash_result = 0;
	uint16_t first_seg = 0;
	uint16_t end_seg = 0;
	uint16_t *ext = NULL;
	uint16_t i = 0, j = 0;
	uint16_t loc;

	memset(&fdir_key, 0, sizeof(fdir_key));
	memset(&ext_seg, 0, sizeof(ext_seg));
	memset(&hash_data, 0, sizeof(hash_data));
	for (i = 0; i < 11; i++)
		key_tmp.key[i] = key;
	shift_bits_right((uint16_t *)&key_tmp, sizeof(key_tmp) / 2, 1);
	fdir_key = key_tmp;
	mce_hash_data_encode(hw_inset, &hash_data);
	if (handle->hash_mode == MCE_MODE_HASH_EX_PORT) {
		hash_data.word_stream[20] = vport_id << 6 | profile_id;
		hash_data.word_stream[20] |= hw_inset->keys.tun_type << 13;
	}
#ifdef MCE_FD_DEBUG
	for (i = 0; i < 10; i++)
		printf("hash_data 0x%.2x\n", hash_data.hash_inset[i]);
	printf("hash_data_rev 0x%.2x\n", hash_data.rev);
#endif
	first_seg = (hash_data.word_stream[20]) & GENMASK_U32(15, 1);
	end_seg = (hash_data.word_stream[0] & GENMASK_U32(14, 0));
	for (i = 0; i < 21; i++)
		ext_seg.word_stream[1 + i] = hash_data.word_stream[i];
	ext_seg.word_stream[0] = first_seg;
	ext_seg.word_stream[22] = end_seg;
	shift_bits_right((uint16_t *)&ext_seg, sizeof(ext_seg) / 2, 1);
	for (i = 0; i <= 350; i++) {
		ext = (uint16_t *)&ext_seg;
		loc = i / 32;
		j = i % 32;
		if (fdir_key.key[loc] & RTE_BIT32(j))
			hash_result ^= ext[0];
		shift_bits_right((uint16_t *)&ext_seg, sizeof(ext_seg) / 2, 1);
#ifdef MCE_FD_DEBUG
		printf("0x%.4x", ext[22]);
		printf(" %.4x", ext[21]);
		printf(" %.4x", ext[20]);
		printf(" %.4x", ext[19]);
		printf(" %.4x", ext[18]);
		printf(" %.4x", ext[17]);
		printf(" %.4x", ext[16]);
		printf(" %.4x", ext[15]);
		printf(" %.4x", ext[14]);
		printf(" %.4x", ext[13]);
		printf(" %.4x", ext[12]);
		printf(" %.4x", ext[11]);
		printf(" %.4x", ext[10]);
		printf(" %.4x", ext[9]);
		printf(" %.4x", ext[8]);
		printf(" %.4x", ext[7]);
		printf(" %.4x", ext[6]);
		printf(" %.4x", ext[5]);
		printf(" %.4x", ext[4]);
		printf(" %.4x", ext[3]);
		printf(" %.4x", ext[2]);
		printf(" %.4x", ext[1]);
		printf(" %.4x", ext[0]);
		printf("\n");
		printf("hash_result 0x%.2x\n", hash_result);
#endif
	}
	printf("hash_result 0x%.2x\n", hash_result);

	return hash_result;
}

/**
 * @brief Find a hash entry by hash value.
 *
 * Searches the handle's appropriate hash-entry list (IPv4 or IPv6)
 * and returns the entry matching the provided hash value.
 *
 * @param handle FDIR handle containing hash lists
 * @param fdir_hash Hash value to look up
 * @param is_ipv6 True to search IPv6 hash list, false for IPv4
 * @return Pointer to matching mce_fdir_hash_entry or NULL if not found
 */
static struct mce_fdir_hash_entry *
mce_fdir_find_hash(struct mce_fdir_handle *handle, uint32_t fdir_hash,
		   bool is_ipv6)
{
	struct mce_fdir_node_list *hash_entry_list = NULL;
	struct mce_fdir_hash_entry *it;
	void *temp = NULL;

	if (is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE)
		hash_entry_list = &handle->hash_entry1_list;
	else
		hash_entry_list = &handle->hash_entry0_list;

	RTE_TAILQ_FOREACH_SAFE(it, hash_entry_list, entry, temp) {
		if (it->fdir_hash == fdir_hash)
			return it;
	}
	return NULL;
}

/**
 * @brief Insert a hash entry into the handle's list.
 *
 * Appends the given hash_entry to either the IPv4 or IPv6 tailq
 * maintained by the handle.
 *
 * @param handle FDIR handle
 * @param hash_entry Hash entry to insert
 * @param is_ipv6 True to insert into IPv6 list, false for IPv4
 */
static void mce_fdir_hash_entry_insert(struct mce_fdir_handle *handle,
					   struct mce_fdir_hash_entry *hash_entry,
					   bool is_ipv6)
{
	struct mce_fdir_node_list *hash_entry_list = NULL;

	if (is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE)
		hash_entry_list = &handle->hash_entry1_list;
	else
		hash_entry_list = &handle->hash_entry0_list;
	TAILQ_INSERT_TAIL(hash_entry_list, hash_entry, entry);
}

/**
 * @brief Remove a hash entry from the handle's list.
 *
 * Removes the provided hash_entry from the appropriate tailq and
 * leaves memory management to the caller.
 *
 * @param handle FDIR handle
 * @param hash_entry Hash entry to remove
 * @param is_ipv6 True to remove from IPv6 list, false for IPv4
 */
static void mce_fdir_hash_entry_remove(struct mce_fdir_handle *handle,
					   struct mce_fdir_hash_entry *hash_entry,
					   bool is_ipv6)
{
	struct mce_fdir_node_list *hash_entry_list = NULL;

	if (is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE)
		hash_entry_list = &handle->hash_entry1_list;
	else
		hash_entry_list = &handle->hash_entry0_list;
	TAILQ_REMOVE(hash_entry_list, hash_entry, entry);
}

/**
 * @brief Check whether adding a new hash entry would exceed limits.
 *
 * @param handle FDIR handle containing current counts and limits
 * @param filter Filter describing IPv4/IPv6 selection
 * @return 0 on success, -EBUSY if max entries reached
 */
static int mce_check_hash_entry_max(struct mce_fdir_handle *handle,
				    struct mce_fdir_filter *filter)
{
	u16 *used_hash_entry = NULL;
	u16 *max_entry_num = NULL;

	if (filter->is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE) {
		used_hash_entry = &handle->ipv6_hash_entry_num;
		max_entry_num = &handle->ipv6_max_hash_entry;
	} else {
		used_hash_entry = &handle->ipv4_hash_entry_num;
		max_entry_num = &handle->ipv4_max_hash_entry;
	}
	if (*used_hash_entry + 1 >= *max_entry_num)
		return -EBUSY;

	return 0;
}

/**
 * @brief Update IPv4/IPv6 hash entry counters for the handle.
 *
 * Increments or decrements the appropriate counter depending on
 * the value of @p add.
 *
 * @param handle FDIR handle
 * @param filter Filter used to select IPv4 vs IPv6 counter
 * @param add True to increment, false to decrement
 */
static void mce_update_hash_entry_num(struct mce_fdir_handle *handle,
				      struct mce_fdir_filter *filter, bool add)
{
	u16 *used_hash_entry = NULL;

	if (filter->is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE)
		used_hash_entry = &handle->ipv6_hash_entry_num;
	else
		used_hash_entry = &handle->ipv4_hash_entry_num;
	if (add)
		*used_hash_entry = *used_hash_entry + 1;
	else
		*used_hash_entry = *used_hash_entry - 1;
	;
}

/**
 * @brief Insert an exact-match FDIR entry into hardware and software lists.
 *
 * Handles allocation of node structures, programming hardware metadata
 * and updating the hash-entry lists for exact-match mode.
 *
 * @param handle FDIR handle
 * @param vport VPort context for hardware access
 * @param filter Filter to insert (contains precomputed hash/loc)
 * @return 0 on success, negative errno on failure
 */
static int mce_fdir_exact_insert_entry(struct mce_fdir_handle *handle,
					   struct mce_vport *vport,
					   struct mce_fdir_filter *filter)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
	struct mce_fdir_node *node = NULL, *first_node;
	struct mce_fdir_hash_entry *hash_node;
	struct mce_fdir_node *cur = NULL;
	struct mce_hw *hw = vport->hw;
	bool is_ipv6 = filter->is_ipv6;
	uint16_t first_bit = 0;
	u32 hw_state = 0;
	int i = 0;

	hash_node = mce_fdir_find_hash(handle, filter->fdirhash, is_ipv6);
	if (hash_node) {
		if (!is_ipv6)
			cur = mce_fdir_find_insert_node(
				hash_node, MCE_EXACT_NODE_MAX_ENTRY);
		if (cur == NULL) {
			if (mce_get_valid_entry_loc(handle, &filter->loc) < 0)
				return -EBUSY;
			first_node = TAILQ_LAST(&hash_node->node_entrys,
						mce_fdir_node_entry);
			first_bit = first_node->loc;
			if (is_ipv6) {
				first_node->exact_meta.v6.next_fd_ptr =
					filter->loc;
				first_node->exact_meta.v6.end = 0;
			} else {
				first_node->exact_meta.v4.next_fd_ptr =
					filter->loc;
				first_node->exact_meta.v4.end = 0;
			}
			do {
				hw_state =
					MCE_E_REG_READ(hw, MCE_FDIR_CMD_CTRL);
				if (!(hw_state & MCE_FDIR_HW_RD))
					break;
			} while (1);
			if (pf->fdir_flush_en) {
				struct mce_fdir_prog_cmd *cmd_buf =
					&pf->commit
						 .cmd_buf[pf->commit.cmd_block];

				memcpy(&cmd_buf->data,
				       &first_node->exact_meta.dword_stream,
				       BIT_TO_BYTES(384));
				cmd_buf->loc = first_bit;
				cmd_buf->cmd_type = 2;
				pf->commit.cmd_block++;
			} else {
				MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT,
						first_bit);
				for (i = 0; i < MCE_FDIR_META_LEN; i++)
					MCE_E_REG_WRITE(
						hw, MCE_FDIR_ENTRY_META_EDIT(i),
						first_node->exact_meta
							.dword_stream[i]);
				MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL,
						MCE_FDIR_WR_CMD);
			}
			node = rte_zmalloc(NULL, sizeof(*node), 0);
			filter->hash_child = 1;
			hash_node->nb_child++;
			mce_fdir_exact_encap_node(filter, node, 1);
			TAILQ_INSERT_TAIL(&hash_node->node_entrys, node, entry);
			mce_set_fdir_entry_bit(handle, filter->loc);
		} else {
			filter->loc = cur->loc;
			node = cur;
			mce_fdir_exact_encap_node(filter, node, 0);
		}
		filter->hash_child = 1;
		hash_node->nb_child++;
	} else {
		if (mce_check_hash_entry_max(handle, filter) < 0)
			return -EBUSY;
		if (mce_get_valid_entry_loc(handle, &filter->loc) < 0)
			return -EBUSY;
		hash_node = rte_zmalloc(NULL, sizeof(*hash_node), 0);
		hash_node->fdir_hash = filter->fdirhash;
		node = rte_zmalloc(NULL, sizeof(*node), 0);
		filter->hash_child = 0;
		mce_fdir_exact_encap_node(filter, node, 1);
		TAILQ_INIT(&hash_node->node_entrys);
		TAILQ_INSERT_TAIL(&hash_node->node_entrys, node, entry);
		mce_fdir_hash_entry_insert(handle, hash_node, is_ipv6);
		mce_set_fdir_entry_bit(handle, filter->loc);
		mce_update_hash_entry_num(handle, filter, 1);
	}

	return 0;
}

/**
 * @brief Search a sign-mode hash entry for a node matching the filter.
 *
 * Locates the node that contains the matching sign-hash and loc.
 *
 * @param hash_entry Hash entry bucket to search
 * @param filter Filter with search keys (signhash, loc)
 * @return Pointer to matching node or NULL if not found
 */
static struct mce_fdir_node *
mce_fdir_sign_search_node(struct mce_fdir_hash_entry *hash_entry,
			  struct mce_fdir_filter *filter)
{
	struct mce_fdir_node *it;
	void *temp = NULL;
	int i = 0;

	RTE_TAILQ_FOREACH_SAFE(it, &hash_entry->node_entrys, entry, temp) {
		if (it->loc == filter->loc) {
			for (i = 0; i < MCE_SIGN_NODE_MAX_ENTRY; i++) {
				if (it->node_info.key[i].sign_hash ==
				    filter->signhash)
					return it;
			}
		}
	}

	return NULL;
}

/**
 * @brief Find a node within a hash entry that has free capacity.
 *
 * Scans the node list for a node whose bit-used count is less than
 * @p max_entry and returns it for insertion; NULL when none are free.
 *
 * @param hash_entry Hash entry to scan
 * @param max_entry Maximum per-node entries allowed
 * @return Pointer to node with space or NULL
 */
static struct mce_fdir_node *
mce_fdir_find_insert_node(struct mce_fdir_hash_entry *hash_entry,
			  uint8_t max_entry)
{
	struct mce_fdir_node *it;
	uint8_t bit_num = 0;
	void *temp = NULL;

	RTE_TAILQ_FOREACH_SAFE(it, &hash_entry->node_entrys, entry, temp) {
		bit_num = __builtin_popcountll(it->node_info.bit_used);
		if (bit_num < max_entry)
			return it;
	}

	return NULL;
}

/**
 * @brief Encapsulate sign-mode filter fields into a node meta structure.
 *
 * Populates the node sign metadata from the filter's inset and signhash.
 * When @p new_node is true the node is initialized; otherwise the
 * first available slot is filled.
 *
 * @param filter Source filter containing hw_inset and signhash
 * @param node Destination node to populate
 * @param new_node True if node is newly created, false to append
 */
static void mce_fdir_sign_encap_node(struct mce_fdir_filter *filter,
					 struct mce_fdir_node *node, bool new_node)
{
	struct mce_node_info *node_info = &node->node_info;
	struct mce_hw_rule_inset *inset = &filter->hw_inset;
	union mce_sign_atr_input *input = &node->sign_meta;
	uint8_t *sign_hash = (uint8_t *)&filter->signhash;
	int i = 0;

	if (new_node) {
		input->entry[i].actions = inset->action;
		input->entry[i].priority = inset->priority;
		input->entry[i].profile_id = inset->profile_id;
		input->entry[i].e_vld = 1;
		input->entry[i].port = inset->port;
		input->entry[i].sign_p1 = sign_hash[0];
		input->entry[i].sign[0] = sign_hash[1];
		input->entry[i].sign[1] = sign_hash[2];
		input->entry[i].sign[2] = sign_hash[3];

		input->end = 1;
		input->next_fd_ptr = 0xfff;
		node->type = MCE_FDIR_SIGN_M_MODE;
		node->loc = filter->loc;
		node_info->bit_used = RTE_BIT32(i);
		node_info->key[i].sign_hash = filter->signhash;
		node_info->key[i].used = 1;
	} else {
		for (i = 0; i < MCE_SIGN_NODE_MAX_ENTRY; i++) {
			if (node_info->key[i].used == 0) {
				input->entry[i].actions = inset->action;
				input->entry[i].priority = inset->priority;
				input->entry[i].profile_id = inset->profile_id;
				input->entry[i].port = inset->port;
				input->entry[i].e_vld = 1;
				input->entry[i].sign_p1 = sign_hash[0];
				input->entry[i].sign[0] = sign_hash[1];
				input->entry[i].sign[1] = sign_hash[2];
				input->entry[i].sign[2] = sign_hash[3];

				node_info->bit_used = RTE_BIT32(i);
				node_info->key[i].sign_hash = filter->signhash;
				node_info->key[i].used = 1;
				break;
			}
		}
	}

	memcpy(&filter->data.dword_stream,
	       &input->dword_stream, sizeof(input->dword_stream));
}

/**
 * @brief Encapsulate exact-match filter fields into a node meta structure.
 *
 * Copies hardware inset keys and action/priority/port into the node's
 * exact metadata. Initializes node bookkeeping fields when @p new_node
 * is true.
 *
 * @param filter Source filter with hw_inset and flags
 * @param node Destination node to populate
 * @param new_node True if node is newly created, false to append
 */
static void mce_fdir_exact_encap_node(struct mce_fdir_filter *filter,
					  struct mce_fdir_node *node, bool new_node)
{
	struct mce_node_info *node_info = &node->node_info;
	struct mce_hw_rule_inset *inset = &filter->hw_inset;
	union mce_exact_atr_input *input = &node->exact_meta;
	int i = 0;

	if (new_node) {
		if (filter->is_ipv6) {
			input->v6.inset_ex = inset->keys.inset_ex;
			input->v6.inset = inset->keys.inset;
			input->v6.e_vld = 1;
			input->v6.end = 1;
			input->v6.next_fd_ptr = 0xfff;
			input->v6.action = inset->action;
			input->v6.priority = inset->priority;
			input->v6.profile_id = inset->profile_id;
			input->v6.port = inset->port;
		} else {
			input->v4.entry[i].action = inset->action;
			input->v4.entry[i].priority = inset->priority;
			input->v4.entry[i].profile_id = inset->profile_id;
			input->v4.entry[i].port = inset->port;
			input->v4.entry[i].inset = inset->keys.inset;
			input->v4.entry[i].e_vld = 1;
			input->v4.next_fd_ptr = 0xfff;
		}
		node_info->key[0].hw_inset = filter->hw_inset.keys;
		node->type = MCE_FDIR_EXACT_M_MODE;
		node->loc = filter->loc;
		node->is_ipv6 = filter->is_ipv6;
		if (filter->is_ipv6)
			node_info->bit_used = RTE_BIT32(0) | RTE_BIT32(1);
		else
			node_info->bit_used |= RTE_BIT32(i);
		node_info->key[i].used = 1;
	} else {
		for (i = 0; i < MCE_EXACT_NODE_MAX_ENTRY; i++) {
			if (node_info->key[i].used == 0) {
				input->v4.entry[i].action = inset->action;
				input->v4.entry[i].priority = inset->priority;
				input->v4.entry[i].profile_id =
					inset->profile_id;
				input->v4.entry[i].e_vld = 1;
				input->v4.entry[i].port = inset->port;
				input->v4.entry[i].inset = inset->keys.inset;

				node_info->key[i].hw_inset.inset =
					inset->keys.inset;
				node_info->bit_used |= RTE_BIT32(i);
				node_info->key[i].used = 1;
				break;
			}
		}
		assert(filter->is_ipv6 == 0);
	}
	memcpy(&filter->data.dword_stream,
	       &input->dword_stream, sizeof(input->dword_stream));
}

/**
 * @brief Insert a sign-mode FDIR entry (signature-based) into HW and lists.
 *
 * Manages node creation or addition to an existing node and programs
 * hardware metadata accordingly.
 *
 * @param handle FDIR handle
 * @param vport VPort for hw access
 * @param filter Filter to insert
 * @return 0 on success or negative errno
 */
static int mce_fdir_sign_insert_entry(struct mce_fdir_handle *handle,
					  struct mce_vport *vport,
					  struct mce_fdir_filter *filter)
{
	struct mce_fdir_node *node = NULL, *first_node;
	struct mce_fdir_hash_entry *hash_node;
	struct mce_hw *hw = vport->hw;
	bool is_ipv6 = filter->is_ipv6;
	struct mce_fdir_node *cur;
	uint16_t first_bit = 0;
	int i = 0;

	hash_node = mce_fdir_find_hash(handle, filter->fdirhash, is_ipv6);
	if (hash_node) {
		cur = mce_fdir_find_insert_node(hash_node,
						MCE_SIGN_NODE_MAX_ENTRY);
		if (cur == NULL) {
			/* add a new node */
			/* edit last node to the new node and last node end = 0
			 */
			if (mce_get_valid_entry_loc(handle, &filter->loc) < 0)
				return -EBUSY;
			first_node = TAILQ_LAST(&hash_node->node_entrys,
						mce_fdir_node_entry);
			first_bit = first_node->loc;
			first_node->sign_meta.next_fd_ptr = filter->loc;
			first_node->sign_meta.end = 1;
			/* edit node filter->entry */
			MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT, first_bit);
			for (i = 0; i < MCE_FDIR_META_LEN; i++)
				MCE_E_REG_WRITE(
					hw, MCE_FDIR_ENTRY_META_EDIT(i),
					first_node->sign_meta.dword_stream[i]);
			MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);
			node = rte_zmalloc(NULL, sizeof(*node), 0);

			node->is_ipv6 = is_ipv6;
			mce_fdir_sign_encap_node(filter, node, 1);
			TAILQ_INSERT_TAIL(&hash_node->node_entrys, node, entry);
			mce_set_fdir_entry_bit(handle, filter->loc);
		} else {
			/* a node can insert a entry */
			/* redit filter->mce_fdir[0]
			 * add new entry to the node entry
			 */
			filter->loc = cur->loc;
			node = cur;
			mce_fdir_sign_encap_node(filter, node, 0);
		}
		filter->hash_child = 1;
		hash_node->nb_child++;
	} else {
		if (mce_check_hash_entry_max(handle, filter) < 0)
			return -EBUSY;
		if (mce_get_valid_entry_loc(handle, &filter->loc) < 0)
			return -EBUSY;
		hash_node = rte_zmalloc(NULL, sizeof(*hash_node), 0);
		hash_node->fdir_hash = filter->fdirhash;
		node = rte_zmalloc(NULL, sizeof(*node), 0);
		filter->hash_child = 0;
		mce_fdir_sign_encap_node(filter, node, 1);
		TAILQ_INIT(&hash_node->node_entrys);
		TAILQ_INSERT_TAIL(&hash_node->node_entrys, node, entry);
		mce_fdir_hash_entry_insert(handle, hash_node, is_ipv6);
		mce_set_fdir_entry_bit(handle, filter->loc);
		mce_update_hash_entry_num(handle, filter, 1);
	}

	return 0;
}

/**
 * @brief Insert an FDIR entry according to the handle mode.
 *
 * Dispatches to sign-mode or exact-mode insert helpers based on the
 * current handle mode.
 *
 * @param handle FDIR handle
 * @param vport VPort for hw access
 * @param filter Filter to insert
 * @return 0 on success or negative errno from helper
 */
int mce_fdir_insert_entry(struct mce_fdir_handle *handle,
			  struct mce_vport *vport,
			  struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_fdir_sign_insert_entry(handle, vport, filter);
	else
		return mce_fdir_exact_insert_entry(handle, vport, filter);
}

/**
 * @brief Reverse a 64-byte command buffer in-place.
 *
 * Hardware expects bytes reversed in command payloads; this helper
 * performs the required byte-order swap for the 64-byte buffer layout.
 *
 * @param data Pointer to 64-byte buffer to reverse
 */
static void mce_edit_cmd_buf_swap(u8 *data)
{
	u8 data_temp[64];
	int i = 0;

	for (i = 0; i < 64; i++)
		data_temp[i] = data[63 - i];

	memcpy(data, data_temp, 64);
}

/**
 * @brief Program or enqueue an exact-match rule into hardware.
 *
 * Writes the rule metadata and updates the quick-find hash table or
 * appends program commands to the PF commit buffer when flush mode is
 * enabled.
 *
 * @param vport VPort providing HW access and PF context
 * @param filter Filter containing prepared metadata and loc/hash
 */
static void mce_edit_exact_rule(struct mce_vport *vport,
				struct mce_fdir_filter *filter)
{
	struct mce_pf *pf = MCE_DEV_TO_PF(vport->dev);
	struct mce_hw *hw = vport->hw;
	uint16_t loc = filter->loc;
	uint32_t fdir_hash = 0;
	uint32_t hw_state = 0;
	uint32_t hw_code = 0;
	int i = 0;

	do {
		hw_state = MCE_E_REG_READ(hw, MCE_FDIR_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	if (pf->fdir_flush_en) {
		struct mce_fdir_prog_cmd *cmd_buf =
			&pf->commit.cmd_buf[pf->commit.cmd_block];

		memcpy(&cmd_buf->data, &filter->data.dword_stream,
		       BIT_TO_BYTES(384));
		cmd_buf->loc = loc;
		cmd_buf->cmd_type = 2;
		/* hardware request table data send by pkt according to
		 * byte[63],byte[62]...byte[1],byte[0]
		 */
		mce_edit_cmd_buf_swap((u8 *)cmd_buf);
		pf->commit.cmd_block++;
	} else {
		/* 1. edit hw meta table */
		for (i = 0; i < MCE_FDIR_META_LEN; i++) {
			MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_META_EDIT(i),
					filter->data.dword_stream[i]);
		}
		/* 2. flush meta code to hw table */
		MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT, loc);
		MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
	/* 3. edit hw quick find hash table */
	if (filter->hash_child == 0) {
		fdir_hash = filter->fdirhash;
		if (pf->fdir_flush_en) {
			struct mce_fdir_prog_cmd *cmd_buf =
				&pf->commit.cmd_buf[pf->commit.cmd_block];
			u32 data = loc | MCE_HASH_ENTRY_EN;
			memcpy(&cmd_buf->data, &data, sizeof(data));
			cmd_buf->loc = fdir_hash;
			cmd_buf->cmd_type = filter->is_ipv6 ? 1 : 0;
			/* hardware request table data send by pkt according to
			 * byte[63],byte[62]...byte[1],byte[0]
			 */
			mce_edit_cmd_buf_swap((u8 *)cmd_buf);
			pf->commit.cmd_block++;
		} else {
			if (filter->is_ipv6) {
				do {
					hw_state = MCE_E_REG_READ(
						hw, MCE_FDIR_EX_HASH_CTRL);
					if (!(hw_state & MCE_FDIR_HW_RD))
						break;
				} while (1);
				MCE_E_REG_WRITE(hw, MCE_FDIR_EX_HASH_ADDR_W,
						fdir_hash);
				hw_code = MCE_HASH_ENTRY_EN | loc;
				MCE_E_REG_WRITE(hw, MCE_FDIR_EX_HASH_DATA_W,
						hw_code);
				MCE_E_REG_WRITE(hw, MCE_FDIR_EX_HASH_CTRL,
						MCE_FDIR_WR_CMD);
			} else {
				do {
					hw_state = MCE_E_REG_READ(
						hw, MCE_FDIR_HASH_CMD_CTRL);
					if (!(hw_state & MCE_FDIR_HW_RD))
						break;
				} while (1);
				MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_ADDR_W,
						fdir_hash);
				hw_code = MCE_HASH_ENTRY_EN | loc;
				MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_DATA_W,
						hw_code);
				MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_CMD_CTRL,
						MCE_FDIR_WR_CMD);
			}
		}
	}
}

/**
 * @brief Program or enqueue a sign-mode rule into hardware.
 *
 * Similar to exact-rule editing but handles sign-mode metadata and
 * additionally dumps debug registers when enabled.
 *
 * @param vport VPort providing HW access
 * @param filter Filter containing prepared metadata and loc/hash
 */
static void mce_edit_sign_rule(struct mce_vport *vport,
			   struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = vport->hw;
	uint16_t loc = filter->loc;
	uint32_t fdir_hash = 0;
	uint32_t hw_state = 0;
	uint32_t hw_code = 0;
	int i = 0;

	do {
		hw_state = MCE_E_REG_READ(hw, MCE_FDIR_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);

	fdir_hash = filter->fdirhash;
	MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT, loc);
	for (i = 0; i < MCE_FDIR_META_LEN; i++) {
		MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_META_EDIT(i),
				filter->data.dword_stream[i]);
	}
	/* 2. flush meta code to hw table */
	MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);

	do {
		hw_state = MCE_E_REG_READ(hw, MCE_FDIR_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_READ, loc);
	MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_RD_CMD);

	printf("dump hash entry table offset 0xe0=> 0x%.2x\n",
	       MCE_E_REG_READ(hw, MCE_FDIR_ENTRY_ID_READ));
	for (i = 0; i < MCE_FDIR_META_LEN; i++)
		printf("dump entry_meta offset 0x%.2x=>0x%.2x\n",
		       0xe4 + 0x4 * i,
		       MCE_E_REG_READ(hw, MCE_FDIR_ENTRY_META_READ(i)));

	/* 3. edit hw quick find hash table */
	if (filter->hash_child == 0) {
		do {
			hw_state = MCE_E_REG_READ(hw, MCE_FDIR_HASH_CMD_CTRL);
			if (!(hw_state & MCE_FDIR_HW_RD))
				break;
		} while (1);
		MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
		hw_code = MCE_HASH_ENTRY_EN | loc;
		MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_DATA_W, hw_code);
		MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
#ifdef MCE_FD_DEBUG
	do {
		hw_state = MCE_E_REG_READ(hw, MCE_FDIR_HASH_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_ENTRY_R, fdir_hash);
	MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_RD_CMD);

	printf("dump hash entry table offset 0x4c=> 0x%.2x\n",
	       MCE_E_REG_READ(hw, MCE_FDIR_HASH_ENTRY_R));
	printf("dump hash entry table offset 0x44=> 0x%.2x\n",
	       MCE_E_REG_READ(hw, MCE_FDIR_HASH_ADDR_W));
	printf("dump hash entry table offset 0x50=> 0x%.2x\n",
	       MCE_E_REG_READ(hw, MCE_FDIR_HASH_ENTRY_V));
#endif
}

/**
 * @brief Clear an exact-match rule in hardware.
 *
 * Zeroes the entry metadata and clears the quick-find hash table slot
 * when appropriate.
 *
 * @param vport VPort with HW access
 * @param filter Filter containing loc/hash
 */
static void mce_clear_exact_rule(struct mce_vport *vport,
				 struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = vport->hw;
	uint32_t fdir_hash = 0;
	uint32_t hw_state = 0;
	uint16_t loc = 0;
	int i = 0;

	do {
		hw_state = MCE_E_REG_READ(hw, MCE_FDIR_CMD_CTRL);
		if (!(hw_state & MCE_FDIR_HW_RD))
			break;
	} while (1);
	/* 1 first input key */
	fdir_hash = filter->fdirhash;
	loc = filter->loc;
	MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT, loc);
	for (i = 0; i < MCE_FDIR_META_LEN; i++)
		MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_META_EDIT(i),
				filter->data.dword_stream[i]);
	MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);
	/************************************************************/
	if (filter->hash_child == 0) {
		if (filter->is_ipv6) {
			do {
				hw_state = MCE_E_REG_READ(
					hw, MCE_FDIR_EX_HASH_CTRL);
				if (!(hw_state & MCE_FDIR_HW_RD))
					break;
			} while (1);
			MCE_E_REG_WRITE(hw, MCE_FDIR_EX_HASH_ADDR_W, fdir_hash);
			MCE_E_REG_WRITE(hw, MCE_FDIR_EX_HASH_DATA_W, 0);
			MCE_E_REG_WRITE(hw, MCE_FDIR_EX_HASH_CTRL,
					MCE_FDIR_WR_CMD);
		} else {
			do {
				hw_state = MCE_E_REG_READ(
					hw, MCE_FDIR_HASH_CMD_CTRL);
				if (!(hw_state & MCE_FDIR_HW_RD))
					break;
			} while (1);
			MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
			MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_DATA_W, 0);
			MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_CMD_CTRL,
					MCE_FDIR_WR_CMD);
		}
	}
}

/**
 * @brief Clear a sign-mode rule in hardware.
 *
 * Clears the entry metadata and the hash table mapping for sign-mode
 * entries when requested.
 *
 * @param vport VPort with HW access
 * @param filter Filter containing loc/hash and clear flags
 */
static void mce_clear_sign_rule(struct mce_vport *vport,
				struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = vport->hw;
	uint32_t fdir_hash = 0;
	uint32_t hw_state = 0;
	uint16_t loc = 0;
	int i = 0;

	if (filter->clear_node) {
		do {
			hw_state = MCE_E_REG_READ(hw, MCE_FDIR_CMD_CTRL);
			if (!(hw_state & MCE_FDIR_HW_RD))
				break;
		} while (1);
		/* 1 first input key */
		fdir_hash = filter->fdirhash;
		loc = filter->loc;
		MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT, loc);
		for (i = 0; i < MCE_FDIR_META_LEN; i++)
			MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_META_EDIT(i), 0);
		MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
	/************************************************************/
	if (filter->hash_child == 0) {
		do {
			hw_state = MCE_E_REG_READ(hw, MCE_FDIR_HASH_CMD_CTRL);
			if (!(hw_state & MCE_FDIR_HW_RD))
				break;
		} while (1);
		MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
		MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_DATA_W, 0);
		MCE_E_REG_WRITE(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
}

/**
 * @brief Clear a hardware rule according to handle mode.
 *
 * Dispatches to sign/exact clear helpers based on the handle mode.
 *
 * @param handle FDIR handle
 * @param port VPort for HW access
 * @param filter Filter indicating rule to clear
 */
void mce_clear_hw_rule(struct mce_fdir_handle *handle, struct mce_vport *port,
			   struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_clear_sign_rule(port, filter);
	return mce_clear_exact_rule(port, filter);
}

/**
 * @brief Edit a hardware rule according to handle mode.
 *
 * Dispatches to sign/exact edit helpers based on the handle mode.
 *
 * @param handle FDIR handle
 * @param port VPort for HW access
 * @param filter Filter containing metadata to program
 */
void mce_edit_hw_rule(struct mce_fdir_handle *handle, struct mce_vport *port,
			  struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_edit_sign_rule(port, filter);
	return mce_edit_exact_rule(port, filter);
}

/**
 * @brief Clear the entry allocation bit for a given hardware loc.
 *
 * Clears the bit in the handle's bitmap that marks the given
 * hardware entry index as allocated.
 *
 * @param handle FDIR handle
 * @param loc Entry index to clear
 */
static void mce_clear_fdir_entry_bit(struct mce_fdir_handle *handle,
					 uint16_t loc)
{
	uint16_t rank = loc / 32;
	uint16_t cow = loc % 32;

	handle->entry_bitmap[rank] &= ~(1 << cow);
}

/**
 * @brief Remove a sign-mode entry from hardware and software lists.
 *
 * Finds the node containing the signature, clears the entry slot and
 * updates hardware pointers and hash mappings as necessary.
 *
 * @param handle FDIR handle
 * @param vport VPort for HW access
 * @param filter Filter describing entry to remove
 */
static void mce_fdir_sign_remove_entry(struct mce_fdir_handle *handle,
					   struct mce_vport *vport,
					   struct mce_fdir_filter *filter)
{
	struct mce_hw *hw = vport->hw;
	struct mce_fdir_hash_entry *hash_node;
	bool is_ipv6 = filter->is_ipv6;
	struct mce_fdir_node *it;
	struct mce_fdir_node *next;
	struct mce_fdir_node *pre;
	bool find = false;
	int i = 0;

	hash_node =
		mce_fdir_find_hash(handle, filter->fdirhash, filter->is_ipv6);
	if (hash_node) {
		it = mce_fdir_sign_search_node(hash_node, filter);
		for (i = 0; i < MCE_SIGN_NODE_MAX_ENTRY; i++) {
			if (it->node_info.key[i].sign_hash ==
			    filter->signhash) {
				find = 1;
				it->node_info.key[i].sign_hash = 0;
				it->node_info.key[i].used = 0;
				it->node_info.bit_used &= ~RTE_BIT32(i);
				memset(&it->sign_meta.entry[i], 0,
				       sizeof(it->sign_meta.entry[i]));
				break;
			}
		}
		assert(find != 0);
		next = TAILQ_NEXT(it, entry);
		pre = TAILQ_PREV(it, mce_fdir_node_entry, entry);
		memcpy(&filter->data, &it->sign_meta, sizeof(filter->data));
		if (it->node_info.bit_used == 0) {
			filter->clear_node = 1;
			TAILQ_REMOVE(&hash_node->node_entrys, it, entry);
			memset(it, 0, sizeof(*it));
			memset(&filter->data, 0, sizeof(filter->data));
			hash_node->nb_child--;
			rte_free(it);
		}
		if (filter->clear_node &&
		    !TAILQ_EMPTY(&hash_node->node_entrys)) {
			if (pre) {
				if (next == NULL) {
					pre->sign_meta.next_fd_ptr = 0xfff;
					pre->sign_meta.end = 1;
				} else {
					pre->sign_meta.next_fd_ptr = next->loc;
				}
				MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT,
						pre->loc);
				for (i = 0; i < MCE_FDIR_META_LEN; i++)
					MCE_E_REG_WRITE(
						hw, MCE_FDIR_ENTRY_META_EDIT(i),
						pre->exact_meta.dword_stream[i]);
				MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL,
						MCE_FDIR_WR_CMD);
			} else {
				if (next != NULL) {
					/* need to update the hash point first_node */
					u32 reg = 0;
					u32 hw_state;
					reg = MCE_HASH_ENTRY_EN | next->loc;
					do {
						hw_state = MCE_E_REG_READ(hw,
							MCE_FDIR_HASH_CMD_CTRL);
						if (!(hw_state & MCE_FDIR_HW_RD))
							break;
					} while (1);
					MCE_E_REG_WRITE(hw,
							MCE_FDIR_HASH_ADDR_W,
							hash_node->fdir_hash);
					MCE_E_REG_WRITE(
						hw, MCE_FDIR_HASH_DATA_W, reg);
					MCE_E_REG_WRITE(hw,
							MCE_FDIR_HASH_CMD_CTRL,
							MCE_FDIR_WR_CMD);
				}
			}
			mce_clear_fdir_entry_bit(handle, filter->loc);
		}
		mce_update_hash_entry_num(handle, filter, 0);
	}
	if (TAILQ_EMPTY(&hash_node->node_entrys))
		mce_fdir_hash_entry_remove(handle, hash_node, is_ipv6);
}

/**
 * @brief Find an exact-mode node by loc within a hash entry.
 *
 * @param hash_node Hash entry to search
 * @param filter Filter containing target loc
 * @return Pointer to node or NULL
 */
static struct mce_fdir_node *
mce_exact_search_node(struct mce_fdir_hash_entry *hash_node,
			  struct mce_fdir_filter *filter)
{
	struct mce_fdir_node *it;
	void *temp = NULL;

	RTE_TAILQ_FOREACH_SAFE(it, &hash_node->node_entrys, entry, temp) {
		if (it->loc == filter->loc)
			return it;
	}

	return NULL;
}

/**
 * @brief Remove an exact-match entry from hardware and software lists.
 *
 * Clears the matching key slot within a node or removes the node
 * entirely if empty, updating hardware pointing entries as required.
 *
 * @param handle FDIR handle
 * @param vport VPort for HW access
 * @param filter Filter describing entry to remove
 */
static void mce_fdir_exact_remove_entry(struct mce_fdir_handle *handle,
					struct mce_vport *vport,
					struct mce_fdir_filter *filter)
{
	struct mce_fdir_hash_entry *hash_node = NULL;
	struct mce_hw *hw = vport->hw;
	struct mce_fdir_node *node = NULL;
	struct mce_fdir_node *next = NULL;
	struct mce_fdir_node *pre = NULL;
	struct mce_fdir_node *it = NULL;
	bool is_ipv6 = filter->is_ipv6;
	bool find = false;
	int i = 0;

	hash_node =
		mce_fdir_find_hash(handle, filter->fdirhash, filter->is_ipv6);
	if (hash_node == NULL)
		return;
	if (hash_node->nb_child == 0) {
		/* this is the final node do nothing */
		node = TAILQ_FIRST(&hash_node->node_entrys);
		assert(node != NULL);
	}
	if (hash_node) {
		it = mce_exact_search_node(hash_node, filter);
		if (!filter->is_ipv6) {
			for (i = 0; i < MCE_EXACT_NODE_MAX_ENTRY; i++) {
				if (!memcmp(&it->node_info.key[i].hw_inset,
							&filter->hw_inset.keys,
							sizeof(filter->hw_inset.keys))) {
					find = 1;
					memset(&it->node_info.key[i], 0,
							sizeof(struct mce_node_key));
					memset(&it->exact_meta.v4.entry[i], 0,
							sizeof(it->exact_meta.v4.entry[i]));
					it->node_info.key[i].used = 0;
					it->node_info.bit_used &= ~RTE_BIT32(i);
					break;
				}
			}
			assert(find != 0);
		}
		next = TAILQ_NEXT(it, entry);
		pre = TAILQ_PREV(it, mce_fdir_node_entry, entry);
		memcpy(&filter->data, &it->exact_meta, sizeof(filter->data));
		if (filter->is_ipv6 || it->node_info.bit_used == 0) {
			filter->clear_node = 1;
			TAILQ_REMOVE(&hash_node->node_entrys, it, entry);
			memset(it, 0, sizeof(*it));
			memset(&filter->data, 0, sizeof(filter->data));
			hash_node->nb_child--;
			rte_free(it);
		}
		if (filter->clear_node &&
		    !TAILQ_EMPTY(&hash_node->node_entrys)) {
			if (pre) {
				if (next == NULL) {
					if (pre->is_ipv6) {
						pre->exact_meta.v6.next_fd_ptr =
							0x1fff;
						pre->exact_meta.v6.end = 1;
					} else {
						pre->exact_meta.v4.next_fd_ptr =
							0x1fff;
						pre->exact_meta.v4.end = 1;
					}
				} else {
					if (pre->is_ipv6) {
						pre->exact_meta.v6.next_fd_ptr =
							next->loc;
					} else {
						pre->exact_meta.v4.next_fd_ptr =
							next->loc;
					}
				}
				MCE_E_REG_WRITE(hw, MCE_FDIR_ENTRY_ID_EDIT,
						pre->loc);
				for (i = 0; i < MCE_FDIR_META_LEN; i++)
					MCE_E_REG_WRITE(
						hw, MCE_FDIR_ENTRY_META_EDIT(i),
						pre->exact_meta.dword_stream[i]);
				MCE_E_REG_WRITE(hw, MCE_FDIR_CMD_CTRL,
						MCE_FDIR_WR_CMD);
			} else {
				if (next != NULL) {
					/* need to update the hash point firt_node */
					u32 reg = 0;
					u32 hw_state;
					reg = MCE_HASH_ENTRY_EN | next->loc;
					if (next->is_ipv6) {
						do {
							hw_state = MCE_E_REG_READ(hw,
								MCE_FDIR_EX_HASH_CTRL);
							if (!(hw_state & MCE_FDIR_HW_RD))
								break;
						} while (1);
						MCE_E_REG_WRITE(
							hw,
							MCE_FDIR_EX_HASH_ADDR_W,
							hash_node->fdir_hash);
						MCE_E_REG_WRITE(
							hw,
							MCE_FDIR_EX_HASH_DATA_W,
							reg);
						MCE_E_REG_WRITE(
							hw,
							MCE_FDIR_EX_HASH_CTRL,
							MCE_FDIR_WR_CMD);
					} else {
						do {
							hw_state = MCE_E_REG_READ(
								hw,
								MCE_FDIR_HASH_CMD_CTRL);
							if (!(hw_state &
							      MCE_FDIR_HW_RD))
								break;
						} while (1);
						MCE_E_REG_WRITE(
							hw,
							MCE_FDIR_HASH_ADDR_W,
							hash_node->fdir_hash);
						MCE_E_REG_WRITE(
							hw,
							MCE_FDIR_HASH_DATA_W,
							reg);
						MCE_E_REG_WRITE(
							hw,
							MCE_FDIR_HASH_CMD_CTRL,
							MCE_FDIR_WR_CMD);
					}
				}
			}
			mce_clear_fdir_entry_bit(handle, filter->loc);
		}
		mce_update_hash_entry_num(handle, filter, 0);
	}
	if (TAILQ_EMPTY(&hash_node->node_entrys))
		mce_fdir_hash_entry_remove(handle, hash_node, is_ipv6);
}

/**
 * @brief Remove an FDIR entry according to the handle mode.
 *
 * Dispatches to sign-mode or exact-mode remove helpers.
 *
 * @param handle FDIR handle
 * @param vport VPort for HW access
 * @param filter Filter describing entry to remove
 */
void mce_fdir_remove_entry(struct mce_fdir_handle *handle,
			   struct mce_vport *vport,
			   struct mce_fdir_filter *filter)
{
	if (handle->mode == MCE_FDIR_SIGN_M_MODE)
		return mce_fdir_sign_remove_entry(handle, vport, filter);
	else
		return mce_fdir_exact_remove_entry(handle, vport, filter);
}

/**
 * @brief Lookup an FDIR filter from the software hash map.
 *
 * Uses the rte_hash associated with the handle to find an existing
 * filter matching the provided lookup pattern.
 *
 * @param handle FDIR handle containing hash structures
 * @param filter Lookup pattern to search for
 * @return Pointer to stored filter or NULL if not found
 */
struct mce_fdir_filter *
mce_fdir_entry_lookup(struct mce_fdir_handle *handle,
			  const struct mce_fdir_filter *filter)
{
	struct mce_fdir_filter **hash_map = NULL;
	struct rte_hash *hash_handle = NULL;
	int ret;

	if (filter->is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE) {
		hash_handle = handle->ex_hash_handle;
		hash_map = handle->ex_hash_map;
	} else {
		hash_handle = handle->hash_handle;
		hash_map = handle->hash_map;
	}

	ret = rte_hash_lookup(hash_handle, &filter->lkup_pattern);

	if (ret < 0)
		return NULL;
	return hash_map[ret];
}

/**
 * @brief Insert a filter into the software hash map for fast lookup.
 *
 * Adds the filter's lookup pattern to the rte_hash and stores the
 * filter pointer in the map array.
 *
 * @param handle FDIR handle
 * @param filter Filter to add
 * @return 0 on success or negative rte_hash error
 */
int mce_fdir_insert_hash_map(struct mce_fdir_handle *handle,
				 struct mce_fdir_filter *filter)
{
	struct mce_fdir_filter **hash_map = NULL;
	struct rte_hash *hash_handle = NULL;
	int ret;

	if (filter->is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE) {
		hash_handle = handle->ex_hash_handle;
		hash_map = handle->ex_hash_map;
	} else {
		hash_handle = handle->hash_handle;
		hash_map = handle->hash_map;
	}
	ret = rte_hash_add_key(hash_handle, &filter->lkup_pattern);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to insert fdir entry to hash table %d!",
			    ret);
		return ret;
	}
	hash_map[ret] = filter;

	return 0;
}

/**
 * @brief Remove a filter from the software hash map.
 *
 * Deletes the lookup key from the rte_hash and clears the map slot.
 *
 * @param handle FDIR handle
 * @param filter Filter whose lookup key will be removed
 * @return 0 on success or negative on error
 */
int mce_fdir_remove_hash_map(struct mce_fdir_handle *handle,
				 const struct mce_fdir_filter *filter)
{
	struct mce_fdir_filter **hash_map = NULL;
	struct rte_hash *hash_handle = NULL;
	int ret;

	if (filter->is_ipv6 && handle->mode == MCE_FDIR_EXACT_M_MODE) {
		hash_handle = handle->ex_hash_handle;
		hash_map = handle->ex_hash_map;
	} else {
		hash_handle = handle->hash_handle;
		hash_map = handle->hash_map;
	}
	ret = rte_hash_del_key(hash_handle, &filter->lkup_pattern);
	if (ret < 0) {
		PMD_DRV_LOG(ERR,
			    "Failed to delete fdir filter to hash table %d!",
			    ret);
		return ret;
	}
	hash_map[ret] = NULL;

	return 0;
}

/**
 * @brief Find a free hardware entry location and return it in loc.
 *
 * Scans the handle's entry bitmap for a free slot and returns the
 * computed index.
 *
 * @param handle FDIR handle containing the bitmap
 * @param loc Out parameter receiving located index
 * @return 0 on success, -ENOMEM if none available
 */
int mce_get_valid_entry_loc(struct mce_fdir_handle *handle, uint16_t *loc)
{
	uint32_t wish_bit = 0x1;
	uint32_t bitmap = 0;
	char find_loc = 0;
	int i = 0, j = 0;

	wish_bit = 0x1;
	for (i = 0; i < 128; i++) {
		bitmap = ~handle->entry_bitmap[i];
		if (!__builtin_popcount(bitmap))
			continue;
		for (j = 0; j < 32; j++) {
			if ((bitmap & wish_bit) == wish_bit) {
				find_loc = 1;
				break;
			}
			bitmap >>= 1;
		}
		if (find_loc) {
			*loc = i * 32 + j;
			break;
		}
	}
	if (!find_loc)
		return -ENOMEM;
	return 0;
}

/**
 * @brief Mark a hardware entry index as allocated in the handle bitmap.
 *
 * @param handle FDIR handle
 * @param loc Entry index to mark
 */
void mce_set_fdir_entry_bit(struct mce_fdir_handle *handle, uint16_t loc)
{
	uint16_t rank = loc / 32;
	uint16_t cow = loc % 32;

	handle->entry_bitmap[rank] |= (1 << cow);
}

/**
 * @brief Encode L2-only lookup fields into the hardware inset keys.
 *
 * Handles Ethernet type, VLAN and MAC fields for L2 profiles.
 *
 * @param filter Filter containing lookup pattern and hw_inset
 * @return 0 on success
 */
static int mce_fdir_l2_encode(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_inset_key *key = &filter->hw_inset.keys.inset;

	if (filter->options & MCE_OPT_ETHTYPE)
		key->inset_key0 = lkup_pattern->formatted.ether_type;
	/* check ether_type is valid */

	return 0;
}

/**
 * @brief Encode L2 fields (MAC/VLAN/ethertype) into inset keys.
 *
 * Populates the two 64-bit inset key words from the lookup pattern.
 *
 * @param filter Filter with lookup pattern and hw_inset
 * @return 0 on success
 */
static int mce_fdir_l2_only_encode(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_hw_inset_key *keys = &filter->hw_inset.keys;
	struct mce_inset_key *key = &keys->inset;
	u64 inset0 = 0, inset1 = 0;
	u8 *inset_temp = NULL;

	if (filter->options & (MCE_OPT_SMAC | MCE_OPT_DMAC)) {
		inset_temp = (u8 *)(&inset0);
		inset_temp[4] = lkup_pattern->formatted.src_mac[5];
		inset_temp[5] = lkup_pattern->formatted.src_mac[4];
		inset_temp[6] = lkup_pattern->formatted.src_mac[3];
		inset_temp[7] = lkup_pattern->formatted.src_mac[2];
		inset_temp = (u8 *)(&inset1);
		inset_temp[0] = lkup_pattern->formatted.src_mac[1];
		inset_temp[1] = lkup_pattern->formatted.src_mac[0];
		inset_temp[2] = lkup_pattern->formatted.dst_mac[5];
		inset_temp[3] = lkup_pattern->formatted.dst_mac[4];
		inset_temp[4] = lkup_pattern->formatted.dst_mac[3];
		inset_temp[5] = lkup_pattern->formatted.dst_mac[2];
		inset_temp[6] = lkup_pattern->formatted.dst_mac[1];
		inset_temp[7] = lkup_pattern->formatted.dst_mac[0];
	}
	if (filter->options & MCE_OPT_VLAN_VID) {
		inset0 |= lkup_pattern->formatted.vlan_id;
	} else if (filter->options & MCE_OPT_ETHTYPE)
		inset0 |= lkup_pattern->formatted.ether_type;
	key->inset_key0 = inset0;
	key->inset_key1 = inset1;

	return 0;
}

/**
 * @brief Encode IPv4/IPv6 address and DSCP fields into inset keys.
 *
 * Handles both IPv4 and IPv6 cases and writes into hw_inset keys.
 *
 * @param filter Filter containing lookup pattern and hw_inset
 * @return 0 on success
 */
static int mce_fdir_encode_ip(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_hw_inset_key *keys = &filter->hw_inset.keys;
	struct mce_inset_key_extend *ex_key = &keys->inset_ex;
	struct mce_inset_key *key = &keys->inset;
	u64 inset = 0;

	if (filter->is_ipv6) {
		if (filter->options & MCE_OPT_IPV6_DIP ||
		    filter->options & MCE_OPT_OUT_IPV6_DIP) {
			inset = lkup_pattern->formatted.dst_addr[0];
			inset = inset << 32;
			key->inset_key0 = inset;

			ex_key->dword_key[3] =
				lkup_pattern->formatted.dst_addr[1];
			ex_key->dword_key[4] =
				lkup_pattern->formatted.dst_addr[2];
			ex_key->dword_key[5] =
				lkup_pattern->formatted.dst_addr[3];
		}
		if (filter->options & MCE_OPT_IPV6_SIP ||
		    filter->options & MCE_OPT_OUT_IPV6_SIP) {
			inset = lkup_pattern->formatted.src_addr[0];
			key->inset_key0 |= inset;

			ex_key->dword_key[0] =
				lkup_pattern->formatted.src_addr[1];
			ex_key->dword_key[1] =
				lkup_pattern->formatted.src_addr[2];
			ex_key->dword_key[2] =
				lkup_pattern->formatted.src_addr[3];
		}
		if (filter->options & MCE_OPT_IPV6_DSCP) {
			inset = lkup_pattern->formatted.ip_tos >> 2;
			inset <<= 32;
			key->inset_key1 |= inset;
		}
	} else {
		if (filter->options & MCE_OPT_IPV4_DIP ||
		    filter->options & MCE_OPT_OUT_IPV4_DIP) {
			inset = lkup_pattern->formatted.dst_addr[0];
			inset = inset << 32;
		}
		if (filter->options & MCE_OPT_IPV4_SIP ||
		    filter->options & MCE_OPT_OUT_IPV4_SIP)
			inset |= lkup_pattern->formatted.src_addr[0];
		key->inset_key0 = inset;
		if (filter->options & MCE_OPT_IPV4_DSCP) {
			inset = lkup_pattern->formatted.ip_tos >> 2;
			inset <<= 32;
			key->inset_key1 |= inset;
		}
	}

	return 0;
}

/**
 * @brief Encode L4 port fields into the inset keys.
 *
 * Sets source/destination port bits used for L4 profile encodings.
 *
 * @param filter Filter containing lookup pattern and hw_inset
 * @return 0 on success
 */
static int mce_fdir_encode_l4_port(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_inset_key *keys = &filter->hw_inset.keys.inset;
	u64 inset = 0;

	if (filter->options & MCE_OPT_L4_DPORT) {
		inset = lkup_pattern->formatted.l4_dport;
		inset <<= 16;
	}
	if (filter->options & MCE_OPT_L4_SPORT)
		inset |= lkup_pattern->formatted.l4_sport;
	keys->inset_key1 |= inset;

	return 0;
}

/**
 * @brief Encode inner tunnel IP/L4 fields into inset keys.
 *
 * Calls IP and L4 helpers for inner tunnel profiles.
 *
 * @param filter Filter to encode
 * @return 0 on success
 */
static int mce_fdir_tun_inner_encode(struct mce_fdir_filter *filter)
{
	mce_fdir_encode_ip(filter);
	mce_fdir_encode_l4_port(filter);

	return 0;
}

/**
 * @brief Encode IP fragment profile keys.
 *
 * Uses IP encoding helper for fragment profiles.
 *
 * @param filter Filter to encode
 * @return 0 on success
 */
static int mce_fdir_ip_frag_encode(struct mce_fdir_filter *filter)
{
	return mce_fdir_encode_ip(filter);
}

/**
 * @brief Encode IP payload-based keys (proto and other payload fields).
 *
 * Populates inset keys that depend on IP payload fields.
 *
 * @param filter Filter to encode
 * @return 0 on success
 */
static int mce_fdir_ip_pay_encode(struct mce_fdir_filter *filter)
{
	mce_fdir_encode_ip(filter);
	/* todo add ip_proto inset key */

	return 0;
}

/**
 * @brief Encode TCP SYN-specific keys (used by sync profile).
 *
 * Calls IP and L4 port encoders to populate keys used by TCP sync.
 *
 * @param filter Filter to encode
 * @return 0 on success
 */
static int mce_fdir_tcp_sync(struct mce_fdir_filter *filter)
{
	mce_fdir_encode_ip(filter);
	mce_fdir_encode_l4_port(filter);

	return 0;
}

/**
 * @brief Encode outer-tunnel specific keys (VNI/TEID/ESP/other).
 *
 * Handles VXLAN/GENEVE/GTP/ESP/other outer tunnel fields.
 *
 * @param filter Filter to encode
 * @return 0 on success
 */
static int mce_fdir_tun_out_encode(struct mce_fdir_filter *filter)
{
	union mce_fdir_pattern *lkup_pattern = &filter->lkup_pattern;
	struct mce_inset_key *keys = &filter->hw_inset.keys.inset;
	u64 inset = 0;

	mce_fdir_encode_ip(filter);
	if (filter->profile_id != MCE_PTYPE_TUN_IPV4_GRE)
		mce_fdir_encode_l4_port(filter);
	if (filter->options & (MCE_OPT_VXLAN_VNI | MCE_OPT_GENEVE_VNI)) {
		inset = lkup_pattern->formatted.vni;
		inset <<= 32;
	} else if (filter->options &
		   (MCE_OPT_GTP_U_TEID | MCE_OPT_GTP_C_TEID)) {
		inset = (lkup_pattern->formatted.teid);
		inset <<= 32;
	} else if (filter->options & MCE_OPT_ESP_SPI) {
		inset = lkup_pattern->formatted.esp_spi;
	} else if (filter->options & MCE_OPT_NVGRE_TNI) {
		inset = lkup_pattern->formatted.key;
		inset >>= 8;
		inset <<= 32;
	} else {
		inset = 0;
	}
	keys->inset_key1 |= inset;

	return 0;
}

static struct mce_fdir_key_encode mce_profile_encode[] = {
	{ MCE_PTYPE_UNKNOW, NULL }, /* 0 */
	{ MCE_PTYPE_L2_ONLY, mce_fdir_l2_only_encode }, /* 1 */
	{ MCE_PTYPE_TUN_INNER_L2_ONLY, mce_fdir_l2_only_encode }, /* 2 */
	{ MCE_PTYPE_TUN_OUTER_L2_ONLY, mce_fdir_l2_only_encode }, /* 3 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_FRAG, mce_fdir_ip_frag_encode }, /* 4 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_FRAG, mce_fdir_ip_frag_encode }, /* 5 */
	{ MCE_PTYPE_L2_ETHTYPE, mce_fdir_l2_encode }, /* 6 */
	{ MCE_PTYPE_TUN_INNER_L2_ETHTYPE, mce_fdir_l2_encode }, /* 7 */
	{ MCE_PTYPE_IPV4_FRAG, mce_fdir_ip_frag_encode }, /* 8*/
	{ MCE_PTYPE_IPV4_TCP_SYNC, mce_fdir_tcp_sync }, /* 9 */
	{ MCE_PTYPE_IPV4_TCP, mce_fdir_tun_inner_encode }, /* 10 */
	{ MCE_PTYPE_IPV4_UDP, mce_fdir_tun_inner_encode }, /* 11 */
	{ MCE_PTYPE_IPV4_SCTP, mce_fdir_tun_inner_encode }, /* 12 */
	{ MCE_PTYPE_IPV4_ESP, mce_fdir_tun_out_encode }, /* 13 */
	{ MCE_PTYPE_IPV4_PAY, mce_fdir_ip_pay_encode }, /* 14 */
	{ 0, 0 }, /* 15 */
	{ MCE_PTYPE_IPV6_FRAG, mce_fdir_ip_pay_encode }, /* 16 */
	{ MCE_PTYPE_IPV6_TCP_SYNC, mce_fdir_tcp_sync }, /* 17 */
	{ MCE_PTYPE_IPV6_TCP, mce_fdir_tun_inner_encode }, /* 18 */
	{ MCE_PTYPE_IPV6_UDP, mce_fdir_tun_inner_encode }, /* 19 */
	{ MCE_PTYPE_IPV6_SCTP, mce_fdir_tun_inner_encode }, /* 20 */
	{ MCE_PTYPE_IPV6_ESP, mce_fdir_tun_inner_encode }, /* 21 */
	{ MCE_PTYPE_IPV6_PAY, mce_fdir_ip_pay_encode }, /* 22 */
	{ 0, 0 }, /* 23 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_PAY, mce_fdir_ip_pay_encode }, /* 24 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_TCP, mce_fdir_tun_inner_encode }, /* 25 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_UDP, mce_fdir_tun_inner_encode }, /* 26 */
	{ MCE_PTYPE_GTP_U_INNER_IPV4_SCTP, mce_fdir_tun_inner_encode }, /* 27 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_PAY, mce_fdir_ip_pay_encode }, /* 28 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_TCP, mce_fdir_tun_inner_encode }, /* 29 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_UDP, mce_fdir_tun_inner_encode }, /* 30 */
	{ MCE_PTYPE_GTP_U_INNER_IPV6_SCTP, mce_fdir_tun_inner_encode }, /* 31 */
	/* outer gtp_u/gtp_c pattern */
	{ MCE_PTYPE_GTP_U_GPDU_IPV4, mce_fdir_tun_out_encode }, /* 32 */
	{ MCE_PTYPE_GTP_U_IPV4, mce_fdir_ip_pay_encode }, /* 33 */
	{ MCE_PTYPE_GTP_C_TEID_IPV4, mce_fdir_tun_out_encode }, /* 34 */
	{ MCE_PTYPE_GTP_C_IPV4, mce_fdir_tun_out_encode }, /* 35 */
	{ MCE_PTYPE_GTP_U_GPDU_IPV6, mce_fdir_tun_out_encode }, /* 36 */
	{ MCE_PTYPE_GTP_U_IPV6, mce_fdir_tun_out_encode }, /* 37 */
	{ MCE_PTYPE_GTP_C_TEID_IPV6, mce_fdir_tun_out_encode }, /* 38 */
	{ MCE_PTYPE_GTP_C_IPV6, mce_fdir_tun_out_encode }, /* 39 */

	{ MCE_PTYPE_TUN_INNER_IPV4_FRAG, mce_fdir_ip_frag_encode }, /* 40 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP_SYNC, mce_fdir_tcp_sync }, /* 41 */
	{ MCE_PTYPE_TUN_INNER_IPV4_TCP, mce_fdir_tun_inner_encode }, /* 42 */
	{ MCE_PTYPE_TUN_INNER_IPV4_UDP, mce_fdir_tun_inner_encode }, /* 43 */
	{ MCE_PTYPE_TUN_INNER_IPV4_SCTP, mce_fdir_tun_inner_encode }, /* 44 */
	{ MCE_PTYPE_TUN_INNER_IPV4_ESP, mce_fdir_tun_inner_encode }, /* 45 */
	{ MCE_PTYPE_TUN_INNER_IPV4_PAY, mce_fdir_ip_pay_encode }, /* 46 */
	{ 0, 0 }, /* 47 */
	{ MCE_PTYPE_TUN_INNER_IPV6_FRAG, mce_fdir_ip_frag_encode }, /* 48 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP_SYNC, mce_fdir_tun_out_encode }, /* 49 */
	{ MCE_PTYPE_TUN_INNER_IPV6_TCP, mce_fdir_tun_inner_encode }, /* 50 */
	{ MCE_PTYPE_TUN_INNER_IPV6_UDP, mce_fdir_tun_inner_encode }, /* 51 */
	{ MCE_PTYPE_TUN_INNER_IPV6_SCTP, mce_fdir_tun_inner_encode }, /* 52 */
	{ MCE_PTYPE_TUN_INNER_IPV6_ESP, mce_fdir_tun_inner_encode }, /* 53 */
	{ MCE_PTYPE_TUN_INNER_IPV6_PAY, mce_fdir_ip_pay_encode }, /* 54 */
	{ 0, 0 }, /* 55 */
	{ MCE_PTYPE_TUN_IPV4_VXLAN, mce_fdir_tun_out_encode }, /* 56 */
	{ MCE_PTYPE_TUN_IPV4_GENEVE, mce_fdir_tun_out_encode }, /* 57 */
	{ MCE_PTYPE_TUN_IPV4_GRE, mce_fdir_tun_out_encode }, /* 58 */
	{ 0, 0 }, /* 59 */
	{ MCE_PTYPE_TUN_IPV6_VXLAN, mce_fdir_tun_out_encode }, /* 60 */
	{ MCE_PTYPE_TUN_IPV6_GENEVE, mce_fdir_tun_out_encode }, /* 61 */
	{ MCE_PTYPE_TUN_IPV6_GRE, mce_fdir_tun_out_encode }, /* 62 */
};

int mce_fdir_key_setup(struct mce_fdir_filter *filter)
{
	return mce_profile_encode[filter->profile_id].key_encode(filter);
}
