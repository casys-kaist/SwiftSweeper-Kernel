#ifndef __SBPF_MEM_H__
#define __SBPF_MEM_H__

#include <linux/types.h>
#include <linux/radix-tree.h>

#define TRI_SIZE 512

/* struct sbpf_reverse_map: [start , end) */
struct sbpf_reverse_map_elem {
	unsigned long start;
	unsigned long end;
	struct list_head list;
};

struct sbpf_reverse_map {
	unsigned long paddr;
	struct sbpf_reverse_map_elem elem;
};

struct sbpf_mm_struct {
	struct sbpf_mm_struct *parent;
	struct list_head children;
	struct list_head elem;
	atomic_t refcnt;
	struct radix_tree_root paddr_to_folio;
};

struct trie_node {
	union {
		struct trie_node *trie_node[TRI_SIZE];
		uint64_t data[TRI_SIZE];
	};
};

inline pte_t *walk_page_table_pte(struct mm_struct *mm, unsigned long address);

extern const struct bpf_func_proto bpf_set_page_table_proto;

/* APIs for Trie */
void trie_init(struct trie_node **node);
int trie_remove(struct trie_node *root, uint64_t caddr);
int trie_insert(struct trie_node *root, uint64_t caddr, uint64_t data);
uint64_t trie_search(struct trie_node *root, uint64_t caddr);
void **trie_search_node(struct trie_node *root, uint64_t caddr);
int trie_free(struct trie_node *root);

/* APIs for reverse mapping */
void *sbpf_reverse_init(unsigned long addr, unsigned long paddr);
int sbpf_reverse_insert(struct sbpf_reverse_map *map, unsigned long addr);
int sbpf_reverse_remove(struct sbpf_reverse_map *map, unsigned long addr);
int sbpf_reverse_empty(struct sbpf_reverse_map *map);
void sbpf_reverse_delete(struct sbpf_reverse_map *map);

pte_t *sbpf_set_write_protected_pte(struct task_struct *tsk, unsigned long vaddr,
				    pgprot_t pgprot, struct folio *folio);
unsigned long sbpf_mem_get_paddr(struct radix_tree_root *vtp, unsigned long vaddr,
				 unsigned long paddr);
unsigned long sbpf_mem_put_paddr(struct radix_tree_root *vtp, unsigned long vaddr);
unsigned long sbpf_mem_lookup_paddr(struct radix_tree_root *vtp, unsigned long vaddr);
int sbpf_mem_insert_paddr(struct radix_tree_root *vtp, unsigned long vaddr,
			  unsigned long paddr);

#endif