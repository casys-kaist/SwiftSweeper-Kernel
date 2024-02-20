#include <linux/maple_tree.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sbpf.h>
#include <linux/string.h>

#include "sbpf_mem.h"

#ifdef USE_MAPLE_TREE
void *sbpf_reverse_init(unsigned long paddr)
{
	struct sbpf_reverse_map *map =
		kmalloc(sizeof(struct sbpf_reverse_map), GFP_KERNEL);
	struct maple_tree *mt = kmalloc(sizeof(struct maple_tree), GFP_KERNEL);

	mt_init(mt);
	map->mt = mt;
	map->paddr = paddr;

	return map;
}

int sbpf_reverse_insert(struct sbpf_reverse_map *map, unsigned long addr)
{
	return sbpf_reverse_insert_range(map, addr, addr + PAGE_SIZE);
}

int sbpf_reverse_insert_range(struct sbpf_reverse_map *map, unsigned long start,
			      unsigned long end)
{
	// FixMe.
	// This should be mtree_insert_range, but there exist multiple insertions with the overlapped range.
	return mtree_store_range(map->mt, start, end - 1, map, GFP_KERNEL);
}

int sbpf_reverse_remove(struct sbpf_reverse_map *map, unsigned long addr)
{
	return sbpf_reverse_remove_range(map, addr, addr + PAGE_SIZE);
}

int sbpf_reverse_remove_range(struct sbpf_reverse_map *map, unsigned long start,
			      uint64_t end)
{
	return mtree_store_range(map->mt, start, end - 1, NULL, GFP_KERNEL);
}

int sbpf_reverse_empty(struct sbpf_reverse_map *map)
{
	return mtree_empty(map->mt);
}

void sbpf_reverse_delete(struct sbpf_reverse_map *map)
{
	mtree_destroy(map->mt);
	kfree(map);
}

struct sbpf_reverse_map *sbpf_reverse_dup(struct sbpf_reverse_map *src)
{
	struct sbpf_reverse_map *new_map = sbpf_reverse_init(src->paddr);
	void *entry = NULL;
	MA_STATE(mas, src->mt, 0, 0);

	mas_for_each(&mas, entry, ULONG_MAX)
	{
		if (entry == NULL)
			continue;
		mtree_insert_range(new_map->mt, mas.index, mas.last, new_map, GFP_KERNEL);
	}

	return new_map;
}

void sbpf_reverse_dump(struct sbpf_reverse_map *map)
{
	void *entry = NULL;
	MA_STATE(mas, map->mt, 0, 0);

	printk(KERN_INFO "dump reverse map:\n");
	mas_for_each(&mas, entry, ULONG_MAX)
	{
		printk(KERN_INFO "\tstart: %lx, end: %lx entry 0x%lx\n",
		       mas.index & PAGE_MASK, (mas.last & PAGE_MASK) + PAGE_SIZE,
		       (unsigned long)entry);
	}
}

#else
static inline struct sbpf_reverse_map_elem *init_reverse_map_elem(unsigned long start,
								  unsigned long end)
{
	struct sbpf_reverse_map_elem *map_elem =
		kmalloc(sizeof(struct sbpf_reverse_map_elem), GFP_KERNEL);
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
	struct profile_t *profile = &current->sbpf->profile;
#endif
	map_elem->start = start;
	map_elem->end = end;
	INIT_LIST_HEAD(&map_elem->list);

	DEBUG_INC_COUNT(profile, reverse_insert_count);
	DEBUG_INC_VAL(profile, reverse_used, ksize(map_elem));
	DEBUG_CMP_INC_VAL(profile, reverse_max, reverse_used);
	return map_elem;
}

void *sbpf_reverse_init(unsigned long paddr)
{
	struct sbpf_reverse_map *map =
		kmalloc(sizeof(struct sbpf_reverse_map), GFP_KERNEL);
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
	struct profile_t *profile = &current->sbpf->profile;
#endif

	INIT_LIST_HEAD(&map->elem);
	map->cached_elem = NULL;
	map->paddr = paddr;
	map->size = 0;

	DEBUG_INC_COUNT(profile, reverse_insert_count);
	DEBUG_INC_VAL(profile, reverse_used, ksize(map));
	DEBUG_CMP_INC_VAL(profile, reverse_max, reverse_used);
	return map;
}

int sbpf_reverse_insert_range(struct sbpf_reverse_map *map, unsigned long start,
			      unsigned long end)
{
	struct sbpf_reverse_map_elem *cur = NULL;
	struct sbpf_reverse_map_elem *prev = NULL;
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
	struct profile_t *profile = &current->sbpf->profile;
#endif

	if (map == NULL)
		return -EINVAL;

	map->size += (end - start) / PAGE_SIZE;
	map->cached_elem = NULL; // Only enables cache when burst frees are processed

	list_for_each_entry_reverse (cur, &map->elem, list) {
		// new node should not be overlapped with other nodes
		if (unlikely(cur->start < end && start < cur->end)) {
			printk("mbpf: assertion failed in insert_range");
			return -EINVAL;
		}
		// cur || new node
		if (cur->end < start) {
			list_add(&init_reverse_map_elem(start, end)->list, &cur->list);
			return 0;
		}
		// [cur - new node]
		if (cur->end == start) { // Forward merge
			cur->end = end;
			return 0; // Backward merge was considered by previous cur
		}
		// [new node - cur]
		if (cur->start == end) { // Backward merge
			cur->start = start;
			prev = list_prev_entry(cur, list);
			// [prev - new node - cur]
			if (prev != NULL && prev->end == cur->start) {
				prev->end = cur->end;
				list_del(&cur->list);
				DEBUG_INC_COUNT(profile, reverse_remove_count);
				DEBUG_DEC_VAL(profile, reverse_used, ksize(cur));
				kfree(cur);
			}
			return 0;
		}
	}
	// new node is the smallest range
	list_add(&init_reverse_map_elem(start, end)->list, &map->elem);
	return 0;
}

int sbpf_reverse_remove_range(struct sbpf_reverse_map *map, unsigned long start,
			      uint64_t end)
{
	struct sbpf_reverse_map_elem *cur = NULL;
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
	struct profile_t *profile = &current->sbpf->profile;
#endif

	if (map == NULL)
		return -EINVAL;

	map->size -= (end - start) / PAGE_SIZE;

	if (map->cached_elem) {
		cur = list_entry(map->cached_elem, struct sbpf_reverse_map_elem, list);

		if (cur->start <= start) {
			// deleted node is right after cur or within cur
			list_for_each_entry_from (cur, &map->elem, list) {
				// guaranteed to be within one node
				if (cur->start <= start && end <= cur->end) {
					if (cur->start == start) {
						if (cur->end == end) {
							if (!list_is_last(&cur->list,
									  &map->elem)) {
								map->cached_elem =
									cur->list.next;
							} else if (!list_is_first(
									   &cur->list,
									   &map->elem)) {
								map->cached_elem =
									cur->list.prev;
							}
							list_del(&cur->list);
							DEBUG_INC_COUNT(
								profile,
								reverse_remove_count);
							DEBUG_DEC_VAL(profile,
								      reverse_used,
								      ksize(cur));
							kfree(cur);
						} else { // end < cur->end
							cur->start = end;
							map->cached_elem = &cur->list;
						}
					} else { // cur->start < start
						if (end < cur->end) {
							list_add(&init_reverse_map_elem(
									  end, cur->end)
									  ->list,
								 &cur->list);
						}
						cur->end = start;
						map->cached_elem = &cur->list;
					}
					return 0;
				}
			}
			return -EINVAL;
		} else {
			// deleted node is before cur
			if (unlikely(cur->start <= end)) {
				printk("mbpf: assertion failed in remove_range");
				return -EINVAL;
			}
			// Since it is checked, move the cursor
			cur = list_prev_entry(cur, list);
		}
	} else {
		cur = list_last_entry(&map->elem, struct sbpf_reverse_map_elem, list);
	}

	// list_for_each_entry(cur, &map->elem, list) {
	list_for_each_entry_from_reverse (cur, &map->elem, list) {
		// guaranteed to be within one node
		if (cur->start <= start && end <= cur->end) {
			if (cur->start == start) {
				if (cur->end == end) {
					if (!list_is_last(&cur->list, &map->elem)) {
						map->cached_elem = cur->list.next;
					} else if (!list_is_first(&cur->list,
								  &map->elem)) {
						map->cached_elem = cur->list.prev;
					}
					list_del(&cur->list);
					DEBUG_INC_COUNT(profile, reverse_remove_count);
					DEBUG_DEC_VAL(profile, reverse_used, ksize(cur));
					kfree(cur);
				} else { // end < cur->end
					cur->start = end;
					map->cached_elem = &cur->list;
				}
			} else { // cur->start < start
				if (end < cur->end) {
					list_add(&init_reverse_map_elem(end, cur->end)
							  ->list,
						 &cur->list);
				}
				cur->end = start;
				map->cached_elem = &cur->list;
			}
			return 0;
		}
	}
	return -EINVAL;
}

int sbpf_reverse_empty(struct sbpf_reverse_map *map)
{
	if (map == NULL || list_empty(&map->elem)) {
		return 1;
	}

	return 0;
}

void sbpf_reverse_delete(struct sbpf_reverse_map *map)
{
	struct sbpf_reverse_map_elem *cur = NULL;
	struct sbpf_reverse_map_elem *next = NULL;
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
	struct profile_t *profile = &current->sbpf->profile;
#endif

	if (map == NULL)
		return;

	list_for_each_entry_safe (cur, next, &map->elem, list) {
		list_del(&cur->list);
		DEBUG_INC_COUNT(profile, reverse_remove_count);
		DEBUG_DEC_VAL(profile, reverse_used, ksize(cur));
		kfree(cur);
	}
	DEBUG_INC_COUNT(profile, reverse_remove_count);
	DEBUG_DEC_VAL(profile, reverse_used, ksize(map));
	kfree(map);
}

struct sbpf_reverse_map *sbpf_reverse_dup(struct sbpf_reverse_map *src)
{
	struct sbpf_reverse_map *dst = NULL;
	struct sbpf_reverse_map_elem *cur = NULL;
	struct sbpf_reverse_map_elem *new = NULL;
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
	struct profile_t *profile = &current->sbpf->profile;
#endif

	if (src == NULL)
		return NULL;

	dst = sbpf_reverse_init(src->paddr);
	list_for_each_entry (cur, &src->elem, list) {
		new = kmalloc(sizeof(struct sbpf_reverse_map_elem), GFP_KERNEL);
		new->start = cur->start;
		new->end = cur->end;

		DEBUG_INC_COUNT(profile, reverse_insert_count);
		DEBUG_INC_VAL(profile, reverse_used, ksize(new));
		DEBUG_CMP_INC_VAL(profile, reverse_max, reverse_used);

		list_add_tail(&new->list, &dst->elem);
	}
	dst->size = src->size;

	return dst;
}

void sbpf_reverse_dump(struct sbpf_reverse_map *map)
{
	struct sbpf_reverse_map_elem *cur = NULL;

	if (map == NULL)
		return;

	printk(KERN_INFO "dump reverse map:\n");
	list_for_each_entry (cur, &map->elem, list) {
		printk(KERN_INFO "\tstart: %lx, end: %lx\n", cur->start, cur->end);
	}
}
#endif