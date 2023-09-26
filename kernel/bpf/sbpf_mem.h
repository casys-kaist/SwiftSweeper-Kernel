#ifndef __SBPF_MEM_H__
#define __SBPF_MEM_H__

#include <linux/types.h>
#include <linux/radix-tree.h>

#define USE_RADIX_TREE 1
#define TRI_SIZE 512

struct sbpf_mm_struct {
	struct sbpf_mm_struct *parent;
	struct list_head children;
	struct list_head elem;
	atomic_t refcnt;
#ifdef USE_RADIX_TREE
	struct radix_tree_root shadow_pages;
#else
	struct trie_node *shadow_pages;
#endif
};

struct sbpf_reverse_map {
	struct rb_node node;
	unsigned long vaddr;
};

inline static bool reverse_map_rb_less(struct rb_node *a, const struct rb_node *b)
{
	struct sbpf_reverse_map *ra = rb_entry(a, struct sbpf_reverse_map, node);
	struct sbpf_reverse_map *rb = rb_entry(b, struct sbpf_reverse_map, node);

	return ra->vaddr < rb->vaddr;
}

struct trie_node {
	union {
		struct trie_node *trie_node[TRI_SIZE];
		uint64_t data[TRI_SIZE];
	};
};

inline pte_t *walk_page_table_pte(struct mm_struct *mm, unsigned long address);

extern const struct bpf_func_proto bpf_set_page_table_proto;
void trie_init(struct trie_node **node);
int trie_remove(struct trie_node *root, uint64_t caddr);
int trie_insert(struct trie_node *root, uint64_t caddr, uint64_t data);
uint64_t trie_search(struct trie_node *root, uint64_t caddr);
void **trie_search_node(struct trie_node *root, uint64_t caddr);
int trie_free(struct trie_node *root);
pte_t *sbpf_set_write_protected_pte(struct task_struct *tsk, unsigned long vaddr,
				    pgprot_t pgprot, struct folio *folio);

#endif