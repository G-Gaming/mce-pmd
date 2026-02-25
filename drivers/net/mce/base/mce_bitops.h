#ifndef _MCE_BITOPS_H_
#define _MCE_BITOPS_H_

#include "mce_hw.h"
#include "mce_osdep.h"

/**
 * @brief Allocate and initialize a bitmap entry.
 *
 * Allocates backing memory for an `mce_bitmap_entry`'s bitmap and
 * initializes the bitmap structure.
 *
 * @param entry Pointer to bitmap entry to initialize
 * @param name_str Name used for allocation labeling
 * @param max_loc_num Maximum number of bits the bitmap will hold
 * @return 0 on success, -ENOMEM or negative on failure
 */
static int mce_bitmap_entry_alloc(struct mce_bitmap_entry *entry,
				  const char *name_str, u16 max_loc_num)
{
	u32 mem_size = 0;

	mem_size = rte_bitmap_get_memory_footprint(max_loc_num);
	entry->bitmap_mem =
		rte_zmalloc(name_str, mem_size, RTE_CACHE_LINE_SIZE);
	printf("%s bitmap_entry alloc mem %d\n", name_str, mem_size);
	if (entry->bitmap_mem == NULL) {
		PMD_INIT_LOG(ERR, "failed to alloc bitmemp_mem");
		return -ENOMEM;
	}
	entry->bitmap =
		rte_bitmap_init(max_loc_num, entry->bitmap_mem, mem_size);
	rte_strlcpy(entry->name, name_str, strlen(name_str));
	if (entry->bitmap == NULL) {
		PMD_INIT_LOG(ERR, "failed to init bitmap");
		return -1;
	}
	entry->max_bit = max_loc_num;
	entry->mem_store = (u32 *)entry->bitmap->array2;

	return 0;
}

/**
 * @brief Find a free bit location in the bitmap.
 *
 * Scans the bitmap for a free slot and returns its index in `loc`.
 *
 * @param entry Pointer to bitmap entry
 * @param loc Output pointer to store found location index
 * @return 0 on success, -ENOMEM if no free slot found
 */
static int mce_get_valid_location(struct mce_bitmap_entry *entry, u16 *loc)
{
	u32 index = 0;
	u64 slab = 0;

	if (rte_bitmap_scan(entry->bitmap, &index, &slab)) {
#if RTE_VERSION_NUM(19, 5, 0, 0) <= RTE_VERSION
		*loc = index + rte_bsf64(slab);
#else
		*loc = index + __builtin_ctzll(slab);
#endif
		return 0;
	}

	return -ENOMEM;
}

/**
 * @brief Mark a bitmap location as used (clear bit).
 *
 * @param entry Pointer to bitmap entry
 * @param loc Location index to mark used
 */
static void mce_set_used_location(struct mce_bitmap_entry *entry, u16 loc)
{
	struct rte_bitmap *bitmap = entry->bitmap;

	rte_bitmap_clear(bitmap, loc);
}

/**
 * @brief Free a previously used bitmap location (set bit).
 *
 * @param entry Pointer to bitmap entry
 * @param loc Location index to free
 */
static void mce_free_used_location(struct mce_bitmap_entry *entry, u16 loc)
{
	struct rte_bitmap *bitmap = entry->bitmap;

	rte_bitmap_set(bitmap, loc);
}

/**
 * @brief Initialize a range of bitmap entries as free.
 *
 * Sets bits in the range [start, end) to indicate availability.
 *
 * @param entry Pointer to bitmap entry
 * @param start Start index (inclusive)
 * @param end End index (exclusive)
 */
static void mce_entry_bitmap_init_range(struct mce_bitmap_entry *entry,
					u16 start, u16 end)
{
	struct rte_bitmap *bitmap = entry->bitmap;
	u16 bit = 0;

	if (end > entry->max_bit || start > entry->max_bit) {
		PMD_INIT_LOG(ERR, "start end is of range");
		return;
	}
	for (bit = start; bit < end; bit++)
		rte_bitmap_set(bitmap, bit);
}

#endif /* _MCE_BITOPS_H_ */
