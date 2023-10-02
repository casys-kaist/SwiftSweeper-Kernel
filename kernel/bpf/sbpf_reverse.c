#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sbpf.h>
#include <linux/string.h>

#include "sbpf_mem.h"

struct sbpf_reverse_map_elem *init_reverse_map_elem(unsigned long addr)
{
	struct sbpf_reverse_map_elem *map_elem =
		kmalloc(sizeof(struct sbpf_reverse_map_elem), GFP_KERNEL);
	map_elem->start = addr;
	map_elem->end = addr + PAGE_SIZE;
	INIT_LIST_HEAD(&map_elem->list);
	return map_elem;
}

void *sbpf_reverse_init(unsigned long addr, unsigned long paddr)
{
	struct sbpf_reverse_map *map =
		kmalloc(sizeof(struct sbpf_reverse_map), GFP_KERNEL);
	map->elem.start = addr;
	map->elem.end = addr + PAGE_SIZE;
	INIT_LIST_HEAD(&map->elem.list);
	map->paddr = paddr;
	return map;
}

int __sbpf_reverse_insert(struct sbpf_reverse_map_elem *map_elem, unsigned long addr)
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

int sbpf_reverse_insert(struct sbpf_reverse_map *map, unsigned long addr)
{
	struct sbpf_reverse_map_elem *cur = &map->elem;
	struct sbpf_reverse_map_elem *next = NULL;

	if (map == NULL)
		return -EINVAL;

	if (list_empty(&cur->list)) {
		if (!__sbpf_reverse_insert(cur, addr))
			return 0;

		next = init_reverse_map_elem(addr);
		list_add(&next->list, &cur->list);
		return 0;
	}

	list_for_each_entry(cur, &map->elem.list, list) {
		next = list_next_entry(cur, list);
		if (!__sbpf_reverse_insert(cur, addr))
			return 0;
		if (next == NULL) {
			next = init_reverse_map_elem(addr);
			list_add(&next->list, &cur->list);
			return 0;
		}
		if (addr + PAGE_SIZE == next->start) {
			next->start = addr;
		}

		// Merge
		if (cur->end == next->start) {
			cur->end = next->end;
			list_del(&next->list);
			kfree(next);
			return 0;
		}
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
	struct sbpf_reverse_map_elem *cur = &map->elem;

	if (map == NULL)
		return -EINVAL;

	if (list_empty(&cur->list)) {
		if (!__sbpf_reverse_remove(cur, addr))
			return 0;
		return -ENOENT;
	}

	list_for_each_entry(cur, &map->elem.list, list) {
		__sbpf_reverse_remove(cur, addr);
		if (cur->start + PAGE_SIZE == cur->end) {
			list_del(&cur->list);
			kfree(cur);
			return 0;
		}
	}

	return -EINVAL;
}

int sbpf_reverse_empty(struct sbpf_reverse_map *map)
{
	struct sbpf_reverse_map_elem *cur = &map->elem;

	if (map == NULL)
		return -EINVAL;

	if (list_empty(&cur->list)) {
		if (cur->start == cur->end)
			return 1;
		return 0;
	}

	list_for_each_entry(cur, &map->elem.list, list) {
		if (cur->start != cur->end)
			return 0;
	}

	return 1;
}

void sbpf_reverse_delete(struct sbpf_reverse_map *map)
{
	struct sbpf_reverse_map_elem *cur = &map->elem;
	struct sbpf_reverse_map_elem *next = NULL;

	if (map == NULL)
		return;

	if (list_empty(&cur->list)) {
		kfree(cur);
		return;
	}

	list_for_each_entry_safe(cur, next, &map->elem.list, list) {
		list_del(&cur->list);
		kfree(cur);
	}
}