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

struct sbpf_alloc_page {
	size_t nr_pages;
	void *kaddr;
	void *uaddr;
	struct list_head list;
};

struct sbpf_task {
	struct list_head allocated_pages;

	// Used for handling sbpf function.
	struct {
		struct bpf_prog *prog;
		void *arg;
	} sbpf_func;
	// Used for handling page fault.
	struct {
		struct bpf_prog *prog;
		void *aux;
	} mm;
};

struct bpf_sbpf_link {
	struct bpf_link link;
	enum bpf_attach_type type;
};

int bpf_sbpf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int bpf_prog_load_sbpf(struct bpf_prog *prog);
int call_sbpf_function(struct bpf_prog *prog, void *arg_ptr, size_t arg_len);
void exit_sbpf(struct task_struct *tsk);

#endif