#include <linux/maple_tree.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/sbpf.h>
#include <linux/stddef.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/radix-tree.h>
#include <linux/mmap_lock.h>
#include <linux/preempt.h>
#include <asm/tlb.h>

#include "sbpf_mem.h"

/* This function is called when BUDAlloc manually execute the eBPF program for the page table modification. */
int sbpf_call_function(struct bpf_prog *prog, void *arg_ptr, size_t arg_len)
{
	int ret = -EINVAL;
	struct mmu_gather tlb;

	mmap_read_lock(current->mm);
	read_lock(&current->sbpf->page_fault.sbpf_mm->user_shared_pages_lock);

	tlb_gather_mmu(&tlb, current->mm);
	current->sbpf->tlb = &tlb;

	if (arg_ptr != NULL && prog != NULL &&
	    copy_from_user(current->sbpf->sbpf_func.arg, arg_ptr, arg_len)) {
		goto done;
	}

	ret = prog->bpf_func(current->sbpf->sbpf_func.arg, NULL);

	tlb_finish_mmu(&tlb);
done:
	read_unlock(&current->sbpf->page_fault.sbpf_mm->user_shared_pages_lock);
	mmap_read_unlock(current->mm);

	return ret;
}

/** 
* This function is check the page fault and call copy on write function.
* If the page fault is not faulted by the copy on write, it returns STOP.
*/
static int __handle_page_fault(pmd_t *pmd, pte_t *pte, unsigned long addr, void *aux)
{
	struct folio *orig_folio = page_folio(pte_page(*pte));
	struct sbpf_task *sbpf = aux;
	void *ret;

	ret = sbpf_mem_copy_on_write(sbpf, orig_folio);
	if (IS_ERR_OR_NULL(ret)) {
		printk("mbpf: copy on write failed (%ld) on __handle_page_fault 0x%lx\n",
		       PTR_ERR(ret), addr);
		return -EINVAL;
	}

	return SBPF_PTE_WALK_STOP;
}

/* This function is called when a page fault occurs in the predefined BUDAlloc range. */
int sbpf_handle_page_fault(struct sbpf_task *sbpf, struct vm_area_struct *vma,
			   unsigned long fault_addr, unsigned int flags)
{
	unsigned long vaddr = fault_addr & PAGE_MASK;
	struct sbpf_vm_fault sbpf_fault;
	struct mmu_gather tlb;
	int ret = 0;
	tlb_gather_mmu(&tlb, current->mm);
	current->sbpf->tlb = &tlb;
	read_lock(&current->sbpf->page_fault.sbpf_mm->user_shared_pages_lock);

	if (flags & FAULT_FLAG_SBPF_EXEC) {
		if (sbpf->wp_page_fault.prog) {
			sbpf_fault.vaddr = fault_addr;
			sbpf_fault.flags = flags;
			sbpf_fault.len = PAGE_SIZE;
			sbpf_fault.aux = sbpf->wp_page_fault.aux;

			// Call page fault function.
			ret = sbpf->wp_page_fault.prog->bpf_func(&sbpf_fault, NULL);
			goto done;
		}
		ret = -EINVAL;
		goto abort;
	} else if (flags & FAULT_FLAG_WRITE) {
		// If the other thread is accessing the same page, we could return
		// to reduce the contention points.

		// Walk the page table and call the page fault function.
		// __handle_page_fault do copy_on_write.
		ret = walk_page_table_pte_range(current->mm, vaddr, vaddr + PAGE_SIZE,
						__handle_page_fault, sbpf, false, true);

		// Sucessfully copy on write.
		if (!ret) {
			goto done;
		}
	}

	sbpf_fault.vaddr = fault_addr;
	sbpf_fault.flags = flags;
	sbpf_fault.len = PAGE_SIZE;
	sbpf_fault.aux = sbpf->page_fault.aux;

	// Call page fault function.
	ret = current->sbpf->page_fault.prog->bpf_func(&sbpf_fault, NULL);

done:
	// Have to manually update the resident set size for the page fault.
	update_hiwater_rss(current->mm);
	tlb_finish_mmu(&tlb);
	// Due to recursive page fault, nullifying the sbpf->tlb incurs #PF.
	// Fixing this problem by skipping the nullification, might incur
	// subtle concurrency bugs (?), but just skip it for now.

abort:
	read_unlock(&current->sbpf->page_fault.sbpf_mm->user_shared_pages_lock);

	return ret;
}

int sbpf_munmap(struct sbpf_task *stask, unsigned long start, size_t len)
{
	unsigned long end;
	struct sbpf_alloc_kmem *alloc_kmem;
	int ret = 0;

	end = PAGE_ALIGN(start + len);
	start = PAGE_ALIGN_DOWN(start);

	write_lock(&stask->page_fault.sbpf_mm->user_shared_pages_lock);

	if (end <= start || stask == NULL) {
		ret = -EINVAL;
		goto done;
	}

	for (; start < end; start += PAGE_SIZE) {
		alloc_kmem = radix_tree_delete(
			stask->page_fault.sbpf_mm->user_shared_pages, start);
		if (alloc_kmem) {
			vfree(alloc_kmem->kaddr);
			kfree(alloc_kmem);
		}
	}

done:
	write_unlock(&stask->page_fault.sbpf_mm->user_shared_pages_lock);

	return ret;
}

static struct sbpf_alloc_kmem *uaddr_to_kaddr(void *uaddr, size_t len)
{
	struct page **pages;
	size_t nr_pages;
	int page_index;
	void *kaddr = NULL;
	int ret;
	struct sbpf_alloc_kmem *allocated_mem = NULL;
	struct sbpf_alloc_kmem *cur = NULL;
	uint64_t offset;

	if (!current->sbpf)
		return NULL;

	mmap_assert_locked(current->mm);

	uaddr = untagged_addr(uaddr);
	offset = (uint64_t)uaddr & (PAGE_SIZE - 1);
	uaddr = (void *)PAGE_ALIGN_DOWN((uint64_t)uaddr);

	// Todo: Optimize this entry to trie
	cur = radix_tree_lookup(current->sbpf->page_fault.sbpf_mm->user_shared_pages,
				((unsigned long)uaddr));
	if (cur && cur->nr_pages * PAGE_SIZE > len + offset)
		return cur;
	else
		allocated_mem = cur;

	len = PAGE_ALIGN(len + offset);
	nr_pages = len / PAGE_SIZE;

	pages = kmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL | GFP_ATOMIC);

	ret = get_user_pages_remote(current->mm, (unsigned long)uaddr, nr_pages,
				    FOLL_WRITE | FOLL_NOFAULT, pages, NULL);
	if (ret <= 0 || ret != nr_pages)
		goto err;

	kaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);

	if (!allocated_mem) {
		allocated_mem = kmalloc(sizeof(struct sbpf_alloc_kmem), GFP_KERNEL);
		if (!allocated_mem)
			goto err;
	}

	allocated_mem->nr_pages = nr_pages;
	allocated_mem->kaddr = kaddr;
	allocated_mem->uaddr = uaddr;

	radix_tree_insert(current->sbpf->page_fault.sbpf_mm->user_shared_pages,
			  (unsigned long)uaddr, allocated_mem);

err:
	for (page_index = 0; page_index < ret; page_index++)
		put_page(pages[page_index]);

	kfree(pages);

	return allocated_mem;
}

BPF_CALL_2(bpf_get_shared_page, void *, kaddr, size_t, len)
{
	struct sbpf_alloc_kmem *cur;
	struct sbpf_task *sbpf;
	off_t offset;

	if (!current->sbpf || !kaddr)
		return 0;

	panic("Implementation should be reversed. bpf_get_shared_page is dupulicated");

	sbpf = current->sbpf;
	offset = kaddr - (void *)PAGE_ALIGN_DOWN((uint64_t)kaddr);

	cur = radix_tree_lookup(sbpf->page_fault.sbpf_mm->user_shared_pages,
				((unsigned long)(kaddr - offset)));
	if (cur && (len + offset) < PAGE_SIZE * cur->nr_pages) {
		return (unsigned long)(cur->kaddr + offset);
	}

	return 0;
}

const struct bpf_func_proto bpf_get_shared_page_proto = {
	.func = bpf_get_shared_page,
	.gpl_only = false,
	.ret_type = RET_PTR_TO_DYNPTR_MEM_OR_NULL,
	.arg1_type = ARG_ANYTHING,
	.arg2_type = ARG_CONST_ALLOC_SIZE_OR_ZERO,
};

BPF_CALL_2(bpf_uaddr_to_kaddr, void *, uaddr, size_t, len)
{
	struct sbpf_alloc_kmem *allocated_page;

	allocated_page = uaddr_to_kaddr(uaddr, len);
	if (allocated_page != NULL && allocated_page->kaddr) {
		return (unsigned long)(allocated_page->kaddr +
				       (uaddr - allocated_page->uaddr));
	}

	return 0;
}

const struct bpf_func_proto bpf_uaddr_to_kaddr_proto = {
	.func = bpf_uaddr_to_kaddr,
	.gpl_only = false,
	.ret_type = RET_PTR_TO_DYNPTR_MEM_OR_NULL,
	.arg1_type = ARG_ANYTHING,
	.arg2_type = ARG_CONST_ALLOC_SIZE_OR_ZERO,
};

BPF_CALL_2(bpf_kmap_uaddr, void *, uaddr, size_t, len)
{
	struct page *page;
	void *kaddr;
	uint64_t offset;

	uaddr = untagged_addr(uaddr);
	offset = (uint64_t)uaddr & (PAGE_SIZE - 1);
	uaddr = (void *)PAGE_ALIGN_DOWN((unsigned long)uaddr);

	if (get_user_pages_remote(current->mm, (unsigned long)uaddr, 1,
				  FOLL_WRITE | FOLL_NOFAULT, &page, NULL) <= 0)
		return 0;

	kaddr = kmap_local_page(page);
	put_page(page);
	kaddr += offset;

	return (unsigned long)kaddr;
}

const struct bpf_func_proto bpf_kmap_uaddr_proto = {
	.func = bpf_kmap_uaddr,
	.gpl_only = false,
	.ret_type = RET_PTR_TO_DYNPTR_MEM_OR_NULL,
	.arg1_type = ARG_ANYTHING,
	.arg2_type = ARG_CONST_ALLOC_SIZE_OR_ZERO,
};

BPF_CALL_1(bpf_kunmap_uaddr, void *, kaddr)
{
	kaddr = (void *)PAGE_ALIGN_DOWN((unsigned long)kaddr);
	kunmap_local(kaddr);

	return 0;
}

const struct bpf_func_proto bpf_kunmap_uaddr_proto = {
	.func = bpf_kunmap_uaddr,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_ANYTHING,
};

static const struct bpf_func_proto *bpf_sbpf_func_proto(enum bpf_func_id func_id,
							const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_uaddr_to_kaddr:
		return &bpf_uaddr_to_kaddr_proto;
	case BPF_FUNC_get_shared_page:
		return &bpf_get_shared_page_proto;
	case BPF_FUNC_set_page_table:
		return &bpf_set_page_table_proto;
	case BPF_FUNC_unset_page_table:
		return &bpf_unset_page_table_proto;
	case BPF_FUNC_touch_page_table:
		return &bpf_touch_page_table_proto;
	case BPF_FUNC_iter_pte_touch:
		return &bpf_iter_pte_touch_proto;
	case BPF_FUNC_kmap_uaddr:
		return &bpf_kmap_uaddr_proto;
	case BPF_FUNC_kunmap_uaddr:
		return &bpf_kunmap_uaddr_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static void bpf_sbpf_link_release(struct bpf_link *link)
{
	return;
}

static void bpf_sbpf_link_dealloc(struct bpf_link *link)
{
	return;
}

static const struct bpf_link_ops bpf_sbpf_link_ops = {
	.release = bpf_sbpf_link_release,
	.dealloc = bpf_sbpf_link_dealloc,
};

static int init_sbpf_page_fault(struct sbpf_task *sbpf, void *aux_ptr,
				struct bpf_prog *prog)
{
	struct sbpf_alloc_kmem *aux_page;
	off_t offset;

	sbpf->page_fault.prog = prog;

	sbpf->page_fault.sbpf_mm =
		kmalloc(sizeof(struct sbpf_mm_struct), GFP_KERNEL | GFP_ATOMIC);
	sbpf->page_fault.sbpf_mm->user_shared_pages =
		kmalloc(sizeof(struct radix_tree_root), GFP_KERNEL | GFP_ATOMIC);

	sbpf->page_fault.sbpf_mm->parent = NULL;
	INIT_LIST_HEAD(&current->sbpf->page_fault.sbpf_mm->children);
	INIT_RADIX_TREE(sbpf->page_fault.sbpf_mm->user_shared_pages, GFP_KERNEL);
	atomic_set(&sbpf->page_fault.sbpf_mm->refcnt, 1);
	rwlock_init(&sbpf->page_fault.sbpf_mm->user_shared_pages_lock);
	for (int i = 0; i < PGTABLE_LOCK_SIZE; i++)
		spin_lock_init(&sbpf->page_fault.sbpf_mm->pgtable_locks[i]);

	if (aux_ptr) {
		aux_page = uaddr_to_kaddr(aux_ptr, PAGE_SIZE);
		offset = aux_ptr - aux_page->uaddr;
		sbpf->page_fault.aux = aux_page->uaddr + offset;
	} else {
		sbpf->page_fault.aux = NULL;
	}

	return 0;
}

static int init_sbpf_function(struct sbpf_task *sbpf, struct bpf_prog *prog)
{
	sbpf->sbpf_func.prog = prog;
	sbpf->sbpf_func.arg = kmalloc(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);

	return 0;
}

static int init_sbpf_wp_page_fault(struct sbpf_task *sbpf, void *aux_ptr,
				   struct bpf_prog *prog)
{
	struct sbpf_alloc_kmem *aux_page;
	off_t offset;

	sbpf->wp_page_fault.prog = prog;
	if (aux_ptr) {
		aux_page = uaddr_to_kaddr(aux_ptr, PAGE_SIZE);
		offset = aux_ptr - aux_page->uaddr;
		sbpf->wp_page_fault.aux = aux_page->uaddr + offset;
	} else {
		sbpf->wp_page_fault.aux = NULL;
	}

	return 0;
}

int bpf_sbpf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	struct bpf_link_primer link_primer;
	struct bpf_sbpf_link *link;
	struct sbpf_task *sbpf;
	int err;

	if (!current->sbpf)
		return -EINVAL;

	sbpf = current->sbpf;

	mmap_write_lock_killable(current->mm);

	if (attr->link_create.attach_type == BPF_SBPF_PAGE_FAULT) {
		init_sbpf_page_fault(sbpf, attr->link_create.sbpf.aux_ptr, prog);
	} else if (attr->link_create.attach_type == BPF_SBPF_FUNCTION) {
		init_sbpf_function(sbpf, prog);
	} else if (attr->link_create.attach_type == BPF_SBPF_WP_PAGE_FAULT) {
		init_sbpf_wp_page_fault(sbpf, attr->link_create.sbpf.aux_ptr, prog);
	} else {
		err = -EINVAL;
		goto out_sbpf;
	}

	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto out_sbpf;
	}

	bpf_link_init(&link->link, BPF_LINK_TYPE_SBPF, &bpf_sbpf_link_ops, prog);
	link->type = attr->link_create.attach_type;
	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		goto out_sbpf;
	}

	mmap_write_unlock(current->mm);

	return bpf_link_settle(&link_primer);

out_sbpf:
	mmap_write_unlock(current->mm);

	return err;
}

static void release_sbpf_mm(struct task_struct *tsk, struct sbpf_mm_struct *sbpf_mm)
{
	struct sbpf_alloc_kmem *alloc_kmem;
	struct radix_tree_iter iter;
	void __rcu **slot;
	if (sbpf_mm == NULL || !atomic_dec_and_test(&sbpf_mm->refcnt))
		return;

	radix_tree_for_each_slot (slot, sbpf_mm->user_shared_pages, &iter, 0) {
		alloc_kmem = rcu_dereference_protected(*slot, true);
		vfree(alloc_kmem->kaddr);
		kfree(alloc_kmem);
		radix_tree_iter_delete(sbpf_mm->user_shared_pages, &iter, slot);
	}

	kfree(sbpf_mm->user_shared_pages);
	kfree(sbpf_mm);
}

static void release_sbpf(struct task_struct *tsk, struct sbpf_task *sbpf)
{
	if (sbpf->sbpf_func.prog) {
		bpf_prog_put(sbpf->sbpf_func.prog);
	}

	if (sbpf->wp_page_fault.prog) {
		bpf_prog_put(sbpf->wp_page_fault.prog);
	}

	if (sbpf->page_fault.prog) {
		bpf_prog_put(sbpf->page_fault.prog);
	}

	release_sbpf_mm(tsk, sbpf->page_fault.sbpf_mm);
	kfree(sbpf);
}

int copy_sbpf_page(struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
		   pte_t *dst_pte, pte_t *src_pte, unsigned long addr, int *rss,
		   struct folio *folio)
{
	if (!folio || folio->page.sbpf_reverse == NULL)
		return -EINVAL;

	folio_get(folio);
	atomic_inc(&folio->_mapcount);

	return 0;
}

// Copy sbpf from current to tsk.
// This function is used for clone.
int copy_sbpf(unsigned long clone_flags, struct task_struct *tsk)
{
	struct sbpf_task *old_sbpf;
	struct radix_tree_iter iter;
	struct sbpf_alloc_kmem *alloc_kmem;
	void __rcu **slot;

	if (current->sbpf == NULL) {
		tsk->sbpf = NULL;
		return 0;
	}

	old_sbpf = current->sbpf;
	write_lock(&old_sbpf->page_fault.sbpf_mm->user_shared_pages_lock);
	tsk->sbpf = kmalloc(sizeof(struct sbpf_task), GFP_KERNEL);

	/* Initialize the sbpf_mm struct. */
	if (old_sbpf->page_fault.prog != NULL) {
		if (clone_flags & CLONE_VM) {
			tsk->sbpf->page_fault.sbpf_mm = old_sbpf->page_fault.sbpf_mm;
			tsk->sbpf->page_fault.aux = old_sbpf->page_fault.aux;
			tsk->sbpf->page_fault.prog = old_sbpf->page_fault.prog;
			atomic_inc(&tsk->sbpf->page_fault.sbpf_mm->refcnt);
		} else {
			init_sbpf_page_fault(tsk->sbpf, NULL, old_sbpf->page_fault.prog);
			tsk->sbpf->page_fault.aux = old_sbpf->page_fault.aux;
			tsk->sbpf->page_fault.sbpf_mm->parent =
				old_sbpf->page_fault.sbpf_mm;
			list_add(&tsk->sbpf->page_fault.sbpf_mm->elem,
				 &old_sbpf->page_fault.sbpf_mm->children);
		}
		bpf_prog_inc(tsk->sbpf->page_fault.prog);
	} else {
		// Currently, we do not support the case that the parent process does not have a page fault function.
		return -EINVAL;
	}

	if (old_sbpf->sbpf_func.prog != NULL) {
		init_sbpf_function(tsk->sbpf, old_sbpf->sbpf_func.prog);
		bpf_prog_inc(tsk->sbpf->sbpf_func.prog);
		memcpy(tsk->sbpf->sbpf_func.arg, old_sbpf->sbpf_func.arg, PAGE_SIZE);
	}

	if (old_sbpf->wp_page_fault.prog != NULL) {
		init_sbpf_wp_page_fault(tsk->sbpf, NULL, old_sbpf->wp_page_fault.prog);
		bpf_prog_inc(tsk->sbpf->wp_page_fault.prog);
		tsk->sbpf->wp_page_fault.aux = old_sbpf->wp_page_fault.aux;
	}

	// We have to clean up user shared pages in case of fork.
	// This is because the parent process (current) will has a different page
	// from the original process. If we do not clean up, the parent process and
	// bpf functions will have a wrong page view from the user space view.
	radix_tree_for_each_slot (slot, old_sbpf->page_fault.sbpf_mm->user_shared_pages,
				  &iter, 0) {
		alloc_kmem = rcu_dereference_protected(*slot, true);
		vfree(alloc_kmem->kaddr);
		kfree(alloc_kmem);
		radix_tree_iter_delete(old_sbpf->page_fault.sbpf_mm->user_shared_pages,
				       &iter, slot);
	}
	write_unlock(&old_sbpf->page_fault.sbpf_mm->user_shared_pages_lock);

	return 0;
}

static bool verify_sbpf(int off, int size, enum bpf_access_type type,
			const struct bpf_prog *prog, struct bpf_insn_access_aux *info)
{
	if (off < 0 || off + size > PAGE_SIZE)
		return false;

	return true;
}

const struct bpf_verifier_ops sbpf_verifier_ops = {
	.get_func_proto = bpf_sbpf_func_proto,
	.is_valid_access = verify_sbpf,
};

const struct bpf_prog_ops sbpf_prog_ops = {};

int bpf_prog_load_sbpf(struct bpf_prog *prog)
{
	if (current->sbpf)
		return 0;

	current->sbpf = kmalloc(sizeof(struct sbpf_task), GFP_KERNEL);

	if (current->sbpf == NULL)
		return -ENOMEM;

	return 0;
}

void exit_sbpf(struct task_struct *tsk)
{
	if (!tsk->sbpf)
		return;

	release_sbpf(tsk, tsk->sbpf);
}

#ifdef CONFIG_BPF_SBPF_MEM_DEBUG
void print_debug_info(struct task_struct *tsk)
{
	struct profile_t *debug;
	char process_name[TASK_COMM_LEN];

	if (!tsk->sbpf) {
		return;
	}

	debug = &tsk->sbpf->profile;

	if (debug == NULL) {
		printk("NULL ptr in debug_info\n");
		return;
	}

	get_task_comm(process_name, tsk);

	printk("--------------------DEBUG INFO--------------------\n");
	printk("PID: %d, NAME: %s\n", task_pid_nr(tsk), process_name);
	printk("--------------------------------------------------\n");
	printk("%-30s %s\n", "ELEMENT", "COUNT");
	printk("%-30s %lld\n", "reverse_insert_count", debug->reverse_insert_count);
	printk("%-30s %lld\n", "reverse_remove_count", debug->reverse_remove_count);
	printk("%-30s 0x%llx\n", "reverse_used", debug->reverse_used);
	printk("%-30s 0x%llx\n", "reverse_max", debug->reverse_max);
	printk("\n");
}
#endif