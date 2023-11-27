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
struct sbpf_reverse_map_elem *init_reverse_map_elem(unsigned long addr)
{
	struct sbpf_reverse_map_elem *map_elem =
		kmalloc(sizeof(struct sbpf_reverse_map_elem), GFP_KERNEL);
	map_elem->start = addr;
	map_elem->end = addr + PAGE_SIZE;
	INIT_LIST_HEAD(&map_elem->list);
	return map_elem;
}

void *sbpf_reverse_init(unsigned long paddr)
{
	struct sbpf_reverse_map *map =
		kmalloc(sizeof(struct sbpf_reverse_map), GFP_KERNEL);
	INIT_LIST_HEAD(&map->elem);
	map->paddr = paddr;

	return map;
}

static inline int __sbpf_reverse_insert(struct sbpf_reverse_map_elem *map_elem,
					unsigned long addr)
{
	if (addr + PAGE_SIZE == map_elem->start) {
		map_elem->start = addr;
		return 0;
	} else if (addr == map_elem->end) {
		map_elem->end = addr + PAGE_SIZE;
		return 0;
	}

	return -EINVAL;
}

static inline int __sbpf_reverse_insert_range(struct sbpf_reverse_map_elem *map_elem,
					      unsigned long start, unsigned long end)
{
	if (start + (end - start) == map_elem->start) {
		map_elem->start = start;
		return 0;
	} else if (start == map_elem->end) {
		map_elem->end = end;
		return 0;
	}

	return -EINVAL;
}

static inline int
__sbpf_reverse_insert_range_reverse(struct sbpf_reverse_map_elem *map_elem,
				    unsigned long start, unsigned long end)
{
	if (start + (end - start) == map_elem->end) {
		map_elem->end = end;
		return 0;
	} else if (start == map_elem->start) {
		map_elem->start = start;
		return 0;
	}

	return -EINVAL;
}

int sbpf_reverse_insert(struct sbpf_reverse_map *map, unsigned long addr)
{
	struct sbpf_reverse_map_elem *cur = NULL;
	struct sbpf_reverse_map_elem *next = NULL;

	if (map == NULL)
		return -EINVAL;

	list_for_each_entry(cur, &map->elem, list) {
		next = list_next_entry(cur, list);
		// Merge
		if (next != NULL && cur->end == addr &&
		    cur->end + PAGE_SIZE == next->start) {
			cur->end = next->end;
			list_del(&next->list);
			kfree(next);
			return 0;
		}
		if (!__sbpf_reverse_insert(cur, addr))
			return 0;
	}

	next = init_reverse_map_elem(addr);
	list_add(&next->list, &map->elem);

	return 0;
}

int sbpf_reverse_insert_range(struct sbpf_reverse_map *map, unsigned long start,
			      unsigned long end)
{
	struct sbpf_reverse_map_elem *cur = NULL;
	struct sbpf_reverse_map_elem *prev = NULL;
	size_t len = end - start;

	if (map == NULL)
		return -EINVAL;

	// list_for_each_entry_reverse(cur, &map->elem, list) {
	// 	prev = list_prev_entry(cur, list);
	// 	// Merge
	// 	if (prev != NULL && cur->start == end && cur->start - len == prev->end) {
	// 		cur->start = prev->start;
	// 		list_del(&prev->list);
	// 		kfree(prev);
	// 		return 0;
	// 	}
	// 	if (!__sbpf_reverse_insert_range_reverse(cur, start, end))
	// 		return 0;
	// }

	// cur = init_reverse_map_elem(start);
	// cur->end = end;
	// list_add(&cur->list, &map->elem);

	while (start < end) {
		if (sbpf_reverse_insert(map, start))
			return 0;
		start += PAGE_SIZE;
	}

	return 0;
}

int __sbpf_reverse_remove(struct sbpf_reverse_map_elem *map_elem, unsigned long addr)
{
	struct sbpf_reverse_map_elem *new_elem;
	if (addr == map_elem->start) {
		map_elem->start = addr + PAGE_SIZE;
		return 0;
	} else if (addr + PAGE_SIZE == map_elem->end) {
		map_elem->end = addr;
		return 0;
	} else if (addr > map_elem->start && addr + PAGE_SIZE < map_elem->end) {
		new_elem = init_reverse_map_elem(addr + PAGE_SIZE);
		new_elem->end = map_elem->end;
		map_elem->end = addr;
		list_add(&new_elem->list, &map_elem->list);
		return 0;
	}

	return -EINVAL;
}

int sbpf_reverse_remove(struct sbpf_reverse_map *map, unsigned long addr)
{
	struct sbpf_reverse_map_elem *cur = NULL;

	if (map == NULL)
		return -EINVAL;

	list_for_each_entry(cur, &map->elem, list) {
		__sbpf_reverse_remove(cur, addr);
		if (cur->start == cur->end) {
			list_del(&cur->list);
			kfree(cur);
			return 0;
		}
	}

	return -ENOENT;
}

int sbpf_reverse_remove_range(struct sbpf_reverse_map *map, unsigned long start,
			      uint64_t end)
{
	struct sbpf_reverse_map_elem *cur = NULL;
	uint64_t addr = start;
	// struct sbpf_reverse_map_elem *temp = NULL;
	// struct sbpf_reverse_map_elem *new_elem = NULL;

	if (map == NULL)
		return -EINVAL;

	while (addr < end) {
		list_for_each_entry(cur, &map->elem, list) {
			__sbpf_reverse_remove(cur, addr);
			if (cur->start == cur->end) {
				list_del(&cur->list);
				kfree(cur);
				break;
			}
		}
		addr += PAGE_SIZE;
	}

	return 0;

	// list_for_each_entry_safe(cur, temp, &map->elem, list) {
	// 	if (cur->start >= end) {
	// 		break;
	// 	}

	// 	if (cur->start < start) {
	// 		if (cur->end <= start) {
	// 			continue;
	// 		} else if (cur->end <= end) {
	// 			cur->end = start;
	// 		} else {
	// 			new_elem = init_reverse_map_elem(end);
	// 			new_elem->end = cur->end;
	// 			cur->end = start;
	// 			list_add(&new_elem->list, &cur->list);
	// 		}
	// 	} else if (cur->start >= start) {
	// 		if (cur->end <= end) {
	// 			list_del(&cur->list);
	// 			kfree(cur);
	// 		} else {
	// 			cur->start = end;
	// 		}
	// 	}
	// }

	return 0;
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

	if (map == NULL)
		return;

	list_for_each_entry_safe(cur, next, &map->elem, list) {
		list_del(&cur->list);
		kfree(cur);
	}

	kfree(map);
}

struct sbpf_reverse_map *sbpf_reverse_dup(struct sbpf_reverse_map *src)
{
	struct sbpf_reverse_map *dst = NULL;
	struct sbpf_reverse_map_elem *cur = NULL;
	struct sbpf_reverse_map_elem *new = NULL;

	if (src == NULL)
		return NULL;

	dst = sbpf_reverse_init(src->paddr);
	list_for_each_entry(cur, &src->elem, list) {
		new = kmalloc(sizeof(struct sbpf_reverse_map_elem), GFP_KERNEL);
		new->start = cur->start;
		new->end = cur->end;
		list_add_tail(&new->list, &dst->elem);
	}

	return dst;
}

void sbpf_reverse_dump(struct sbpf_reverse_map *map)
{
	struct sbpf_reverse_map_elem *cur = NULL;

	if (map == NULL)
		return;

	printk(KERN_INFO "dump reverse map:\n");
	list_for_each_entry(cur, &map->elem, list) {
		printk(KERN_INFO "\tstart: %lx, end: %lx\n", cur->start, cur->end);
	}
}
#endif