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

void *sbpf_reverse_init(unsigned long paddr)
{
	struct sbpf_reverse_map *map =
		kmalloc(sizeof(struct sbpf_reverse_map), GFP_KERNEL);
	INIT_LIST_HEAD(&map->elem);
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

	if (src == NULL)
		return NULL;

	dst = sbpf_reverse_init(src->paddr);
	list_for_each_entry(cur, &src->elem, list) {
		sbpf_reverse_insert(dst, cur->start);
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