#ifndef __SBPF_MEM_H__
#define __SBPF_MEM_H__

#include <linux/types.h>
#include <linux/radix-tree.h>
#include <linux/maple_tree.h>
#include <asm/pgtable_types.h>

#define TRI_SIZE 512

/* MAP TREE is more stable than the linked list, but requires more space and time. */
// #define BUD_REVERSE_USE_MAPLE_TREE 1
#define BUD_REVERSE_USE_LINKED_LIST 1

struct sbpf_reverse_map_elem {
	unsigned long start;
	unsigned long end;
	struct list_head list;
};

/* Holds the reverse map information for the BUDAlloc
 * The reverse map is used to track the folio to virtual addresses for replacing the Linux object-based reverse map.
 */
struct sbpf_reverse_map {
	unsigned long paddr; // Physical address of the memory region
	size_t size; // Size of the memory region
#ifdef BUD_REVERSE_USE_MAPLE_TREE
	struct maple_tree *mt;
#else
	struct list_head elem;
	struct list_head *cached_elem;
#endif
};

/* Holds the metadata for the BUDAlloc per user threads */
struct sbpf_mm_struct {
	struct radix_tree_root *
		user_shared_pages; // Cache for the user address to kernel address mapping
	rwlock_t user_shared_pages_lock; // Lock used for the user address to kernel address mapping
	struct sbpf_mm_struct *parent;
	struct list_head children;
	struct list_head elem;
	atomic_t refcnt; // Reference count for the sbpf_mm_struct
	spinlock_t pgtable_lock; // Lock used for protecting concurrent page table accesses
};

struct trie_node {
	union {
		struct trie_node *trie_node[TRI_SIZE];
		uint64_t data[TRI_SIZE];
	};
};

/* BUDAlloc page table walking states. These enums are used for APIs for page table management such as walk_page_table_pte_range. */
enum sbpf_pte_walk {
	SBPF_PTE_WALK_NEXT_PTE,
	SBPF_PTE_WALK_NEXT_PMD,
	SBPF_PTE_WALK_STOP,
};

/* BUDAlloc helper function prototypes */
typedef int (*pte_func)(pmd_t *pmd, pte_t *pte, unsigned long addr, void *aux);

extern const struct bpf_func_proto bpf_set_page_table_proto;
extern const struct bpf_func_proto bpf_unset_page_table_proto;
extern const struct bpf_func_proto bpf_touch_page_table_proto;
extern const struct bpf_func_proto bpf_iter_pte_touch_proto;

/* APIs for Trie */
void trie_init(struct trie_node **node);
int trie_remove(struct trie_node *root, uint64_t caddr);
int trie_insert(struct trie_node *root, uint64_t caddr, uint64_t data);
uint64_t trie_search(struct trie_node *root, uint64_t caddr);
void **trie_search_node(struct trie_node *root, uint64_t caddr);
int trie_free(struct trie_node *root);

/* APIs for reverse mapping */
void *sbpf_reverse_init(unsigned long paddr);
int sbpf_reverse_insert(struct sbpf_reverse_map *map, unsigned long addr);
int sbpf_reverse_insert_range(struct sbpf_reverse_map *map, unsigned long start,
			      unsigned long end);
int sbpf_reverse_remove(struct sbpf_reverse_map *map, unsigned long addr);
int sbpf_reverse_remove_range(struct sbpf_reverse_map *map, unsigned long start,
			      uint64_t end);
int sbpf_reverse_empty(struct sbpf_reverse_map *map);
void sbpf_reverse_delete(struct sbpf_reverse_map *map);
struct sbpf_reverse_map *sbpf_reverse_dup(struct sbpf_reverse_map *src);
void sbpf_reverse_dump(struct sbpf_reverse_map *map);

/* APIs for page table management */
int walk_page_table_pte_range(struct mm_struct *mm, unsigned long addr, unsigned long end,
			      pte_func func, void *aux, bool continue_walk);
int touch_page_table_pte_range(struct mm_struct *mm, unsigned long addr,
			       unsigned long end, pte_func func, void *aux);
struct folio *sbpf_mem_copy_on_write(struct sbpf_task *sbpf, struct folio *orig_folio);
#endif
