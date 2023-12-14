#ifndef _BPF_SBPF_H
#define _BPF_SBPF_H

#include <linux/types.h>
#include <linux/bpf.h>

struct sbpf_vm_fault {
	unsigned long vaddr;
	size_t len;
	unsigned int flags;
	void *aux;
};

struct sbpf_alloc_kmem {
	size_t nr_pages;
	void *kaddr;
	void *uaddr;
};

struct sbpf_task {
	struct radix_tree_root user_shared_pages;
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
};

struct bpf_sbpf_link {
	struct bpf_link link;
	enum bpf_attach_type type;
};

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

#endif