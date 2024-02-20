#ifndef _BPF_SBPF_H
#define _BPF_SBPF_H

#include <linux/types.h>
#include <linux/bpf.h>

/* handle_mm_fault() */
struct sbpf_vm_fault {
	unsigned long vaddr;
	size_t len;
	unsigned int flags;
	void *aux;
};

/* bpf_uaddr_to_kaddr() */
struct sbpf_alloc_kmem {
	size_t nr_pages;
	void *kaddr;
	void *uaddr;
};

#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
struct profile_t {
	long long reverse_insert_count; // reverse map insert count
	long long reverse_remove_count; // reverse map remove count
	long long reverse_used; // currently used reverse map size
	long long reverse_max; // maximun used reverse map size
};
#endif

/* generic task struct for handling BUDAlloc bpf program */
struct sbpf_task {
	// Used for reference counting of sbpf_task produced by the fork.
	atomic_t ref;

	// Used for handling sbpf function.
	struct {
		struct bpf_prog *prog;
		void *arg;
	} sbpf_func;

	// Used for handling page fault.
	struct {
		struct sbpf_mm_struct *sbpf_mm;
		struct bpf_prog *prog;
		void *aux;
	} page_fault;

	// Used for transparently merging tlb flush.
	struct mmu_gather *tlb;

	// Used for profiling the memory usage of BUDAlloc.
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
	struct profile_t profile;
#endif
};

/* Struct for linking bpf program to sbpf_task */
struct bpf_sbpf_link {
	struct bpf_link link;
	enum bpf_attach_type type;
};

/* sBPF global functions */
int bpf_sbpf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int bpf_prog_load_sbpf(struct bpf_prog *prog);
int sbpf_call_function(struct bpf_prog *prog, void *arg_ptr, size_t arg_len);
int sbpf_handle_page_fault(struct sbpf_task *sbpf, unsigned long fault_addr,
			   unsigned int flags);
int sbpf_munmap(struct sbpf_task *stask, unsigned long start, size_t len);

int copy_sbpf_page(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
		   pte_t *dst_pte, pte_t *src_pte, unsigned long addr, int *rss,
		   struct folio *folio);
int copy_sbpf(unsigned long clone_flags, struct task_struct *tsk);
void exit_sbpf(struct task_struct *tsk);

/* Marcro functions for profiling memory usages */
#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
#define DEBUG_INC_COUNT(profile, field_name) \
	__atomic_fetch_add(&(profile->field_name), 1, __ATOMIC_RELAXED);
#define DEBUG_DEC_COUNT(profile, field_name) \
	__atomic_fetch_sub(&(profile->field_name), 1, __ATOMIC_RELAXED);
#define DEBUG_INC_VAL(profile, field_name, value) \
	__atomic_fetch_add(&(profile->field_name), value, __ATOMIC_RELAXED);
#define DEBUG_DEC_VAL(profile, field_name, value) \
	__atomic_fetch_sub(&(profile->field_name), value, __ATOMIC_RELAXED);
#define DEBUG_CMP_INC_VAL(profile, tar_field_name, src_field_name)                    \
	do {                                                                          \
		bool success = false;                                                 \
		do {                                                                  \
			long long current_value = __atomic_load_n(                    \
				&(profile->tar_field_name), __ATOMIC_RELAXED);        \
			long long new_value = __atomic_load_n(                        \
				&(profile->src_field_name), __ATOMIC_RELAXED);        \
			if ((new_value) > (current_value)) {                          \
				success = __atomic_compare_exchange_n(                \
					&(profile->tar_field_name), &(current_value), \
					(new_value), false, __ATOMIC_RELAXED,         \
					__ATOMIC_RELAXED);                            \
			} else {                                                      \
				success = true;                                       \
			}                                                             \
		} while (!success);                                                   \
	} while (0)

void print_debug_info(struct task_struct *tsk);

#else
#define DEBUG_INC_COUNT(profile, field_name)
#define DEBUG_DEC_COUNT(profile, field_name)
#define DEBUG_INC_VAL(profile, field_name, value)
#define DEBUG_DEC_VAL(profile, field_name, value)
#define DEBUG_CMP_INC_VAL(profile, tar_field_name, src_field_name)
#endif

/* APIs for the page table modification */
static inline void pte_ref_set(pgtable_t pte, int count)
{
	atomic_set(&pte->pte_refcount, count);
}
#endif