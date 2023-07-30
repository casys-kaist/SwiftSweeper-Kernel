#ifndef __SBPF_MEM_H__
#define __SBPF_MEM_H__

#include <linux/types.h>

extern const struct bpf_func_proto bpf_set_page_table_proto;

struct sbpf_page {
	uint64_t bpf_paddr;
	struct folio *kernel_page;
	struct list_head list;
};

// This structure is used for the internal pruposes.
struct sbpf_mm
{
	struct list_head pages;
};

#endif