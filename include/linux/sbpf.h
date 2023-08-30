#ifndef _BPF_SBPF_H
#define _BPF_SBPF_H

#include <linux/types.h>
#include <linux/bpf.h>

#define SBPF_USER_VADDR_START 0x1000

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
	struct list_head list;
};

struct sbpf_alloc_folio {
	struct folio *folio;
	struct list_head list;
};

struct sbpf_task {
	struct list_head alloc_kmems;
	struct list_head alloc_folios;
	// FixMe!. This max_alloc_end is dangerous to use with the kernel mmap struct.
	// Have to use free_pgd_range with user space vma informations.
	unsigned long max_alloc_end;
	// Used for reference counting of sbpf_task produced by the fork.
	atomic_t ref;

	// Used for handling sbpf function.
	struct {
		struct bpf_prog *prog;
		void *arg;
	} sbpf_func;
	// Used for handling page fault.
	struct {
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
int call_sbpf_function(struct bpf_prog *prog, void *arg_ptr, size_t arg_len);

int copy_sbpf(struct task_struct *tsk);
void exit_sbpf(struct task_struct *tsk);

#endif