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
#include <asm/tlb.h>

#include "sbpf_mem.h"

int sbpf_call_function(struct bpf_prog *prog, void *arg_ptr, size_t arg_len)
{
	int ret = -EINVAL;

	if (arg_ptr != NULL && prog != NULL &&
	    copy_from_user(current->sbpf->sbpf_func.arg, arg_ptr, arg_len)) {
		goto err;
	}

	ret = prog->bpf_func(current->sbpf->sbpf_func.arg, NULL);

err:
	return ret;
}

int sbpf_handle_page_fault(struct sbpf_task *sbpf, unsigned long fault_addr,
			   unsigned int flags)
{
	struct sbpf_vm_fault sbpf_fault;
#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
	unsigned long vaddr;
	unsigned long paddr;
	struct folio *orig_folio;
	struct folio *folio;
	void __rcu **slot;
	pte_t *pte;
	pte_t entry;
#endif

	sbpf_fault.vaddr = fault_addr;
	sbpf_fault.flags = flags;
	sbpf_fault.len = PAGE_SIZE;
	sbpf_fault.aux = current->sbpf->page_fault.aux;

	// Cow routine.
#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
	vaddr = fault_addr & PAGE_MASK;
	pte = walk_page_table_pte(current->mm, vaddr);
	orig_folio = page_folio(pte_page(*pte));
	if (orig_folio->page.sbpf_reverse == NULL)
		goto out;
	paddr = orig_folio->page.sbpf_reverse->paddr;
	if (orig_folio != NULL && paddr != 0) {
		slot = radix_tree_lookup_slot(&sbpf->page_fault.sbpf_mm->paddr_to_folio,
					      paddr);
		// When the page is shared, we have to copy the page.
		if (pte != NULL && folio_ref_count(orig_folio) > 1) {
			// We have to make the parent page as a read only.
			folio = folio_alloc(GFP_USER | __GFP_ZERO, 0);
			if (unlikely(!folio))
				return -ENOMEM;
			if (mem_cgroup_charge(folio, current->mm, GFP_KERNEL))
				return -ENOMEM;

			folio_copy(folio, orig_folio);

			radix_tree_replace_slot(&sbpf->page_fault.sbpf_mm->paddr_to_folio,
						slot, folio);
			entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
			entry = pte_sw_mkyoung(entry);
			entry = pte_mkwrite(entry);
			folio_put(orig_folio);
			inc_mm_counter(current->mm, MM_ANONPAGES);

			set_pte(pte, entry);
		} else if (pte != NULL && folio_ref_count(orig_folio) == 1) {
			// Reuse the original folio, becuase it is not shared among process.
			pte = walk_page_table_pte(current->mm, vaddr);
			entry = mk_pte(&orig_folio->page, PAGE_SHARED_EXEC);
			entry = pte_sw_mkyoung(entry);
			entry = pte_mkwrite(entry);
			inc_mm_counter(current->mm, MM_ANONPAGES);

			set_pte(pte, entry);
		} else {
			printk("Error in folio ref cnt:%d addr:0x%lx, paddr:0x%lx",
			       folio_ref_count(orig_folio), vaddr, paddr);
			return -EINVAL;
		}

		return 0;
	}
#endif

out:
	// Call page fault function.
	return current->sbpf->page_fault.prog->bpf_func(&sbpf_fault, NULL);
}

int sbpf_munmap(struct sbpf_task *stask, unsigned long start, size_t len)
{
	unsigned long end;

	end = PAGE_ALIGN(start + len);
	start = PAGE_ALIGN_DOWN(start);

	if (end <= start || stask == NULL)
		return -EINVAL;

	for (; start < end; start += PAGE_SIZE) {
		radix_tree_delete(&stask->user_shared_pages, start);
	}

	return 0;
}

struct sbpf_alloc_kmem *uaddr_to_kaddr(void *uaddr, size_t len)
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

	uaddr = untagged_addr(uaddr);
	offset = (uint64_t)uaddr & (PAGE_SIZE - 1);
	uaddr = (void *)PAGE_ALIGN_DOWN((uint64_t)uaddr);

	// Todo: Optimize this entry to trie
	cur = radix_tree_lookup(&current->sbpf->user_shared_pages,
				((unsigned long)uaddr));
	if (cur)
		return cur;

	len = PAGE_ALIGN(len + offset);
	nr_pages = len / PAGE_SIZE;

	pages = kmalloc_array(nr_pages, sizeof(*pages), GFP_KERNEL | GFP_ATOMIC);

	ret = get_user_pages_remote(current->mm, (unsigned long)uaddr, nr_pages,
				    FOLL_WRITE, pages, NULL, NULL);
	if (ret <= 0 || ret != nr_pages)
		goto err;

	kaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);

	allocated_mem = kmalloc(sizeof(struct sbpf_alloc_kmem), GFP_KERNEL);
	if (!allocated_mem)
		goto err;

	allocated_mem->nr_pages = nr_pages;
	allocated_mem->kaddr = kaddr;
	allocated_mem->uaddr = uaddr;

	radix_tree_insert(&current->sbpf->user_shared_pages, (unsigned long)uaddr,
			  allocated_mem);

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

	cur = radix_tree_lookup(&sbpf->user_shared_pages,
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
	default:
		return bpf_base_func_proto(func_id);
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

	if (aux_ptr) {
		aux_page = uaddr_to_kaddr(aux_ptr, PAGE_SIZE);
		offset = aux_ptr - aux_page->uaddr;
		sbpf->page_fault.aux = aux_page->uaddr + offset;
	} else {
		sbpf->page_fault.aux = NULL;
	}
	sbpf->page_fault.prog = prog;
	sbpf->page_fault.sbpf_mm = kmalloc(sizeof(struct sbpf_mm_struct), GFP_KERNEL);
	sbpf->page_fault.sbpf_mm->parent = NULL;
	INIT_LIST_HEAD(&current->sbpf->page_fault.sbpf_mm->children);
	INIT_RADIX_TREE(&sbpf->page_fault.sbpf_mm->paddr_to_folio, GFP_ATOMIC);
	atomic_set(&sbpf->page_fault.sbpf_mm->refcnt, 1);
	bpf_prog_inc(prog);

	return 0;
}

static int init_sbpf_function(struct sbpf_task *sbpf, const union bpf_attr *attr,
			      struct bpf_prog *prog)
{
	sbpf->sbpf_func.prog = prog;
	sbpf->sbpf_func.arg = kmalloc(PAGE_SIZE, GFP_KERNEL | __GFP_ZERO);
	bpf_prog_inc(prog);

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

	if (attr->link_create.attach_type == BPF_SBPF_PAGE_FAULT) {
		init_sbpf_page_fault(sbpf, attr->link_create.sbpf.aux_ptr, prog);
	} else if (attr->link_create.attach_type == BPF_SBPF_FUNCTION) {
		init_sbpf_function(sbpf, attr, prog);
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

	return bpf_link_settle(&link_primer);

out_sbpf:

	return err;
}

static void release_sbpf_mm_struct(struct task_struct *tsk,
				   struct sbpf_mm_struct *sbpf_mm)
{
	struct radix_tree_iter iter;
	void __rcu **slot;
	struct folio *folio;

	if (sbpf_mm == NULL || !atomic_dec_and_test(&sbpf_mm->refcnt))
		return;

	radix_tree_for_each_slot(slot, &sbpf_mm->paddr_to_folio, &iter, 0) {
		folio = rcu_dereference_protected(*slot, true);
		if (folio_ref_count(folio) > 0) {
			folio_put(folio);
			dec_mm_counter(tsk->mm, MM_ANONPAGES);
		}
		radix_tree_iter_delete(&sbpf_mm->paddr_to_folio, &iter, slot);
	}
}

static void release_sbpf(struct task_struct *tsk, struct sbpf_task *sbpf)
{
	struct sbpf_alloc_kmem *alloc_kmem;
	struct mmu_gather tlb;
	struct radix_tree_iter iter;
	void __rcu **slot;

	if (!atomic_dec_and_test(&sbpf->ref)) {
		radix_tree_for_each_slot(slot, &sbpf->user_shared_pages, &iter, 0) {
			alloc_kmem = rcu_dereference_protected(*slot, true);
			vfree(alloc_kmem->kaddr);
			kfree(alloc_kmem);
			radix_tree_iter_delete(&sbpf->user_shared_pages, &iter, slot);
		}

		tlb_gather_mmu(&tlb, tsk->mm);
		free_pgd_range(&tlb, SBPF_USER_VADDR_START, sbpf->max_alloc_end,
			       SBPF_USER_VADDR_START, sbpf->max_alloc_end + (1UL << 39));
		tlb_finish_mmu(&tlb);

		if (sbpf->sbpf_func.prog) {
			bpf_prog_put(sbpf->sbpf_func.prog);
			kfree(sbpf->sbpf_func.arg);
		}

		if (sbpf->page_fault.prog) {
			release_sbpf_mm_struct(tsk, sbpf->page_fault.sbpf_mm);
			bpf_prog_put(sbpf->page_fault.prog);
			kfree(sbpf->page_fault.sbpf_mm);
		}

		kfree(sbpf);
	}
}

// Copy sbpf from current to tsk.
// This function is used for clone.
int copy_sbpf(struct task_struct *tsk)
{
	struct sbpf_task *old_sbpf;
	struct radix_tree_iter iter;
	struct folio *folio;
	void __rcu **slot;
#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
	pte_t *pte;
	pte_t *cpte;
#endif

	if (current->sbpf == NULL) {
		tsk->sbpf = NULL;
		return 0;
	}

	old_sbpf = current->sbpf;
	tsk->sbpf = kmalloc(sizeof(struct sbpf_task), GFP_KERNEL);

	/* Initialize the sbpf_mm struct. */
	if (old_sbpf->page_fault.prog != NULL) {
		init_sbpf_page_fault(tsk->sbpf, NULL, old_sbpf->page_fault.prog);
		tsk->sbpf->page_fault.aux = old_sbpf->page_fault.aux;
		tsk->sbpf->page_fault.sbpf_mm->parent = old_sbpf->page_fault.sbpf_mm;
		tsk->sbpf->page_fault.prog = old_sbpf->page_fault.prog;

		list_add(&tsk->sbpf->page_fault.sbpf_mm->elem,
			 &old_sbpf->page_fault.sbpf_mm->children);
		tsk->sbpf->page_fault.sbpf_mm->parent = old_sbpf->page_fault.sbpf_mm;

		/* Copy the folio from the parent process and increase the folio reference count. */
		radix_tree_for_each_slot(
			slot, &old_sbpf->page_fault.sbpf_mm->paddr_to_folio, &iter, 0) {
			folio = rcu_dereference_protected(*slot, true);
			folio_get(folio);
			radix_tree_insert(&tsk->sbpf->page_fault.sbpf_mm->paddr_to_folio,
					  iter.index, folio);
			/* Copy the pte from the parent process and make the parent pte as an write protected. */
#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
			ptep_set_wrprotect(current->mm, iter.index, pte);
			cpte = sbpf_set_write_protected_pte(tsk, iter.index,
							    pte_pgprot(*pte),
							    page_folio(pte_page(*pte)));

#endif
		}
	}

	if (current->sbpf->sbpf_func.prog != NULL) {
		init_sbpf_function(tsk->sbpf, NULL, current->sbpf->sbpf_func.prog);
		memcpy(tsk->sbpf->sbpf_func.arg, current->sbpf->sbpf_func.arg, PAGE_SIZE);
	}

	INIT_RADIX_TREE(&tsk->sbpf->user_shared_pages, GFP_ATOMIC);
	tsk->sbpf->max_alloc_end = current->sbpf->max_alloc_end;
	atomic_inc(&current->sbpf->ref);

	// We have to clean up user shared pages in case of fork.
	// This is because the parent process (current) will has a different page
	// from the original process. If we do not clean up, the parent process and
	// bpf functions will have a wrong page view from the user space view.
	radix_tree_for_each_slot(slot, &current->sbpf->user_shared_pages, &iter, 0) {
		radix_tree_iter_delete(&current->sbpf->user_shared_pages, &iter, slot);
	}

	return 0;
}

bool verify_sbpf(int off, int size, enum bpf_access_type type,
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

	INIT_RADIX_TREE(&current->sbpf->user_shared_pages, GFP_ATOMIC);
	current->sbpf->max_alloc_end = SBPF_USER_VADDR_START;

	return 0;
}

void exit_sbpf(struct task_struct *tsk)
{
	if (!tsk->sbpf)
		return;

	release_sbpf(tsk, tsk->sbpf);
}
