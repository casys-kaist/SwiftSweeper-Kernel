#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/gfp_types.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/sbpf.h>
#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/pgtable.h>
#include <asm/tlb.h>

#include "sbpf_mem.h"

int walk_page_table_pte_range(struct mm_struct *mm, unsigned long start,
			      unsigned long end, pte_func func, void *aux)
{
	int ret;
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pud_t *pud;
	pte_t *pte;
	unsigned long next_pgd;
	unsigned long next_p4d;
	unsigned long next_pud;
	unsigned long next_pmd;
	unsigned long addr = start & PAGE_MASK;

	if (start >= end || !mm || !func)
		return -EINVAL;

	pgd = pgd_offset(mm, addr);
	do {
		next_pgd = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			return -ENOENT;

		p4d = p4d_offset(pgd, addr);
		do {
			next_p4d = p4d_addr_end(addr, end);
			if (p4d_none_or_clear_bad(p4d))
				return -ENOENT;

			pud = pud_offset(p4d, addr);
			do {
				next_pud = pud_addr_end(addr, end);
				if (pud_none_or_clear_bad(pud))
					return -ENOENT;

				pmd = pmd_offset(pud, addr);
				do {
					next_pmd = pmd_addr_end(addr, end);
					if (pmd_none_or_clear_bad(pmd))
						return -ENOENT;

					pte = pte_offset_map(pmd, addr);
					do {
						if (pte_none(*pte))
							return -ENOENT;
						ret = func(pte, addr, aux);
						if (unlikely(ret))
							return ret;
					} while (pte++, addr += PAGE_SIZE,
						 addr != next_pmd);
				} while (pmd++, addr = next_pmd, addr != next_pud);
			} while (pud++, addr = next_pud, addr != next_p4d);
		} while (p4d++, addr = next_pgd, addr != next_pgd);
	} while (pgd++, addr = next_pgd, addr != end);

	return 0;
}

int touch_page_table_pte_range(struct mm_struct *mm, unsigned long start,
			       unsigned long end, pte_func func, void *aux)
{
	int ret;
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pud_t *pud;
	pte_t *pte;
	pte_t orig_pte;
	unsigned long next_pgd;
	unsigned long next_p4d;
	unsigned long next_pud;
	unsigned long next_pmd;

	unsigned long addr = start & PAGE_MASK;

	if (start >= end || !mm || !func)
		return -EINVAL;

	pgd = pgd_offset(mm, addr);
	do {
		next_pgd = pgd_addr_end(addr, end);

		p4d = p4d_alloc(mm, pgd, addr);
		if (unlikely(!p4d))
			return -ENOMEM;
		do {
			next_p4d = p4d_addr_end(addr, next_pgd);
			pud = pud_alloc(mm, p4d, addr);
			if (unlikely(!pud))
				return -ENOMEM;
			do {
				next_pud = pud_addr_end(addr, next_p4d);
				pmd = pmd_alloc(mm, pud, addr);
				if (unlikely(!pmd))
					return -ENOMEM;
				do {
					next_pmd = pmd_addr_end(addr, next_pud);
					if (unlikely(pmd_none(*pmd)))
						pte = NULL;
					else {
						pte = pte_offset_map(pmd, addr);
						orig_pte = *pte;
						barrier();
						if (pte_none(orig_pte)) {
							pte_unmap(*pte);
							pte = NULL;
						}
					}

					if (!pte && pte_alloc(mm, pmd))
						return -ENOMEM;
					else
						pte = pte_offset_map(pmd, addr);

					do {
						ret = func(pte, addr, aux);
						if (unlikely(ret))
							return ret;
					} while (pte++, addr += PAGE_SIZE,
						 addr != next_pmd);
				} while (pmd++, addr = next_pmd, addr != next_pud);
			} while (pud++, addr = next_pud, addr != next_p4d);
		} while (p4d++, addr = next_pgd, addr != next_pgd);
	} while (pgd++, addr = next_pgd, addr != end);

	return 0;
}

int __sbpf_touch_write_protected_pte(pte_t *pte, unsigned long addr, void *aux)
{
	pte_t entry;
	pgprot_t pgprot;

	pgprot.pgprot = *(unsigned long *)aux;
	entry = mk_pte(pte_page(*pte), pgprot);
	entry = pte_sw_mkyoung(entry);
	entry = pte_wrprotect(entry);
	set_pte(pte, entry);

	return 0;
}

int sbpf_touch_write_protected_pte(struct task_struct *tsk, unsigned long vaddr,
				   pgprot_t pgprot, struct folio *folio)
{
	int ret;

	ret = touch_page_table_pte_range(tsk->mm, vaddr, vaddr + PAGE_SIZE,
					 __sbpf_touch_write_protected_pte, &pgprot);

	if (unlikely(!ret)) {
		printk("Invalid pte at the new task %d ret: %d 0x%lx\n", tsk->pid, ret,
		       vaddr);
		return -EINVAL;
	}

	return 0;
}

int sbpf_mem_insert_paddr(struct radix_tree_root *vtp, unsigned long vaddr,
			  unsigned long paddr)
{
	int ret;

	ret = radix_tree_insert(vtp, vaddr, (void *)(paddr + 1));
	if (unlikely(ret)) {
		printk("Error in radix_tree_insert v:0x%lx p:0x%lx error %d\n", vaddr,
		       paddr, ret);
		return 0;
	}

	return 1;
}

unsigned long sbpf_mem_lookup_paddr(struct radix_tree_root *vtp, unsigned long vaddr)
{
	void __rcu *slot;
	unsigned long paddr;

	slot = radix_tree_lookup_slot(vtp, vaddr);
	if (!slot) {
		return 0;
	}
	paddr = *(unsigned long *)slot;
	if ((paddr & (PAGE_SIZE - 1)) >= 4096) {
		printk("Overflow vaddr to paddr reference 0x%lx\n", paddr);
		return 0;
	}

	return paddr & PAGE_MASK;
}

unsigned long sbpf_mem_get_paddr(struct radix_tree_root *vtp, unsigned long vaddr,
				 unsigned long _paddr)
{
	void __rcu *slot;
	unsigned long paddr;

	slot = radix_tree_lookup_slot(vtp, vaddr);
	if (!slot) {
		sbpf_mem_insert_paddr(vtp, vaddr, _paddr);
		return _paddr;
	}
	paddr = *(unsigned long *)slot;
	if ((paddr & (PAGE_SIZE - 1)) >= 4096) {
		printk("Overflow vaddr to paddr reference 0x%lx\n", paddr);
		return 0;
	}
	radix_tree_replace_slot(vtp, slot, (void *)(paddr + 1));

	return paddr & PAGE_MASK;
}

unsigned long sbpf_mem_put_paddr(struct radix_tree_root *vtp, unsigned long vaddr)
{
	void __rcu *slot;
	unsigned long paddr;

	slot = radix_tree_lookup_slot(vtp, vaddr);
	if (!slot) {
		return 0;
	}
	paddr = *(unsigned long *)slot;
	if ((paddr & (PAGE_SIZE - 1)) == 0) {
		printk("Overflow vaddr to paddr reference 0x%lx\n", paddr);
		return 0;
	}
	if ((paddr & (PAGE_SIZE - 1)) == 1) {
		radix_tree_delete(vtp, vaddr);
		return paddr & PAGE_MASK;
	} else
		radix_tree_replace_slot(vtp, slot, (void *)(paddr - 1));

	return 0;
}

static int __set_pte(pte_t *pte, unsigned long addr, void *aux)
{
	pte_t entry = *(pte_t *)aux;
	set_pte_at(current->mm, addr, pte, entry);
	return 0;
}

struct folio *sbpf_mem_copy_on_write(struct sbpf_task *sbpf, struct folio *orig_folio,
				     void __rcu **slot, int update_mappings)
{
	struct sbpf_reverse_map_elem *cur;
	unsigned long paddr;
	struct folio *folio;
	int ret;
	pte_t entry;

	if (unlikely(orig_folio == NULL || orig_folio->page.sbpf_reverse == NULL))
		return ERR_PTR(-EINVAL);

	paddr = orig_folio->page.sbpf_reverse->paddr;
	if (unlikely(paddr == 0))
		return ERR_PTR(-EINVAL);

	// When the page is shared, we have to copy the page (folio).
	if (folio_ref_count(orig_folio) > 1) {
		// We have to make the parent page as a read only.
		folio = folio_alloc(GFP_USER | __GFP_ZERO, 0);
		if (unlikely(!folio))
			return ERR_PTR(-ENOMEM);
		if (mem_cgroup_charge(folio, current->mm, GFP_KERNEL))
			return ERR_PTR(-ENOMEM);

		folio_copy(folio, orig_folio);
		folio->page.sbpf_reverse =
			sbpf_reverse_dup(orig_folio->page.sbpf_reverse);

		if (slot == NULL) {
			slot = radix_tree_lookup_slot(
				&sbpf->page_fault.sbpf_mm->paddr_to_folio, paddr);
		}
		radix_tree_replace_slot(&sbpf->page_fault.sbpf_mm->paddr_to_folio, slot,
					folio);
		entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
		entry = pte_sw_mkyoung(entry);
		entry = pte_mkwrite(entry);
		folio_put(orig_folio);
	} else if (folio_ref_count(orig_folio) == 1) {
		// Reuse the original folio, becuase it is not shared among process.
		folio = orig_folio;
		entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
		entry = pte_sw_mkyoung(entry);
		entry = pte_mkwrite(entry);
	} else {
		printk("Error in folio ref cnt:%d paddr:0x%lx",
		       folio_ref_count(orig_folio), paddr);
		return ERR_PTR(-EINVAL);
	}

	if (update_mappings) {
		list_for_each_entry(cur, &folio->page.sbpf_reverse->elem, list) {
			ret = walk_page_table_pte_range(current->mm, cur->start, cur->end,
							__set_pte, &entry);
			if (unlikely(ret)) {
				printk("Error in set addr range (%d): [0x%lx, 0x%lx)\n",
				       ret, cur->start, cur->end);
			}
		}
	}

	return folio;
}

// If paddr is 0, kernel allocates the memory.
static int bpf_set_pte(unsigned long vaddr, size_t len, unsigned long paddr,
		       unsigned long vmf_flags, unsigned long prot)
{
	struct mm_struct *mm = current->mm;
	struct folio *orig_folio = NULL;
	struct folio *folio = NULL;
	void __rcu **slot = NULL;
	struct radix_tree_root *paddr_to_folio;
	int ret;
	int new_folio = 0;
	pte_t *pte;
	pte_t entry;
	pgprot_t pgprot;
	pgprot.pgprot = prot;

	if (!current->sbpf)
		return 0;

	paddr_to_folio = &current->sbpf->page_fault.sbpf_mm->paddr_to_folio;

	vaddr = vaddr & PAGE_MASK;
	paddr = paddr & PAGE_MASK;

	if (paddr == 0)
		return -EINVAL;

	// When mmap first allocates a pgprot of a pte, it marks the page with no write permission.
	// Thus, to use the zero page frame, we have to check pgprot doesn't have RW permission.
	// Note that, paddr (sbpf physical address) starts from 1 and 0 means zero page (Not fixed yet).
	if (paddr) {
		// This optimization slows down the overall performance. Disable temporary before delete.
		slot = radix_tree_lookup_slot(paddr_to_folio, paddr);
		orig_folio = slot != NULL ? rcu_dereference_protected(*slot, true) : NULL;
		if (orig_folio != NULL && folio_ref_count(orig_folio) > 1) {
			folio = sbpf_mem_copy_on_write(current->sbpf, orig_folio, slot,
						       true);
		} else {
			folio = orig_folio;
		}
		if (!IS_ERR_OR_NULL(folio)) {
			entry = mk_pte(&folio->page, pgprot);
			entry = pte_sw_mkyoung(entry);
			entry = pte_mkwrite(entry);
			goto set_pte;
		}
	}

	folio = folio_alloc(GFP_USER | __GFP_ZERO, 0);
#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
	folio->page.sbpf_reverse = sbpf_reverse_init(paddr);
	sbpf_reverse_insert_range(folio->page.sbpf_reverse, vaddr, vaddr + len);
#endif
	new_folio = 1;
	if (unlikely(!folio))
		return 0;
	if (mem_cgroup_charge(folio, mm, GFP_KERNEL))
		return 0;

	entry = mk_pte(&folio->page, pgprot);
	entry = pte_sw_mkyoung(entry);
	entry = pte_mkwrite(entry);

	inc_mm_counter(mm, MM_ANONPAGES);

set_pte:
	ret = touch_page_table_pte_range(current->mm, vaddr, vaddr + len, __set_pte,
					 &entry);
	if (unlikely(ret)) {
		printk("Invalid copy-on-write task %d ret: %d 0x%lx\n", current->pid, ret,
		       vaddr);
		return 1;
	}

#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
	if (!new_folio) {
		ret = sbpf_reverse_insert_range(folio->page.sbpf_reverse, vaddr,
						vaddr + len);
		atomic_inc(&folio->_mapcount);
		if (unlikely(ret)) {
			printk("Error in radix_tree_insert 0x%lx error %d\n", vaddr, ret);
			return 0;
		}
	}
#endif
	// We allocate new page, but original paddr is empty.
	// Thus, we have to touch the trie structure for the shadow page and set the shared pte.
	// Todo! After allocation, pgprot will be different from the kernel's vma, so we have to fix it.
	if (paddr && folio != NULL && new_folio) {
		// Caching the pte entry to the shadow page trie.
		if (!slot) {
			ret = radix_tree_insert(paddr_to_folio, paddr, folio);
			if (unlikely(ret)) {
				printk("Error in trie_insert 0x%lx error %d\n", paddr,
				       ret);
				return 0;
			}
		} else {
			radix_tree_replace_slot(paddr_to_folio, slot, folio);
		}
	}
	pte_unmap(pte);
	// TODO!. We have to elaborate the boundary mechanism.
	if (current->sbpf->max_alloc_end < vaddr + PAGE_SIZE) {
		current->sbpf->max_alloc_end = vaddr + PAGE_SIZE;
	}

	return 0;
}

static int __unset_pte(pte_t *pte, unsigned long addr, void *aux)
{
	struct folio *folio;
	unsigned long paddr;
	struct mmu_gather *tlb = aux;

	folio = page_folio(pte_page(*pte));
#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
	if (folio_ref_count(folio) > 1) {
		folio = sbpf_mem_copy_on_write(current->sbpf, folio, NULL, true);
		if (IS_ERR_OR_NULL(folio)) {
			printk("Error in copy on write on bpf_unmap_pte 0x%lx\n", addr);
			return -EINVAL;
		}
	}
#endif
	ptep_get_and_clear(current->mm, addr, pte);
	pte_clear(current->mm, addr, pte);
#ifndef CONFIG_BPF_SBPF_DISABLE_REVERSE
	sbpf_reverse_remove(folio->page.sbpf_reverse, addr);
	if (sbpf_reverse_empty(folio->page.sbpf_reverse)) {
		paddr = folio->page.sbpf_reverse->paddr;
		radix_tree_delete(&current->sbpf->page_fault.sbpf_mm->paddr_to_folio,
				  paddr);
		paddr = folio->page.sbpf_reverse->paddr;
		radix_tree_delete(&current->sbpf->page_fault.sbpf_mm->paddr_to_folio,
				  paddr);
		atomic_set(&folio->_mapcount, -1);
		kfree(folio->page.sbpf_reverse);
		folio->page.sbpf_reverse = NULL;
		folio_put(folio);
		dec_mm_counter(current->mm, MM_ANONPAGES);
		tlb_remove_tlb_entry(tlb, pte, addr);
	}
#else
	folio_put(folio);
	dec_mm_counter(current->mm, MM_ANONPAGES);
#endif

	return 0;
}

static int bpf_unset_pte(unsigned long address, size_t len)
{
	struct mm_struct *mm = current->mm;
	struct mmu_gather tlb;
	int ret;

	tlb_gather_mmu(&tlb, mm);

	address = address & PAGE_MASK;
	ret = walk_page_table_pte_range(mm, address, address + len, __unset_pte, &tlb);
	if (unlikely(ret)) {
		return 0;
	}
	tlb_finish_mmu(&tlb);

	return 1;
}

static int bpf_touch_pte(unsigned long address, size_t len, unsigned long vmf_flags,
			 unsigned long prot)
{
	struct mm_struct *mm = current->mm;
	struct mmu_gather tlb;
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pud_t *pud;
	pte_t *pte;
	pte_t oldpte;
	pte_t newpte;
	unsigned long newprot;
	pgprot_t new_pgprot;
	struct page *page;
	const int grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);

	prot &= ~(PROT_GROWSDOWN | PROT_GROWSUP);
	if (grows == (PROT_GROWSDOWN | PROT_GROWSUP)) /* can't be both */
		return -EINVAL;
	if (!arch_validate_prot(prot, address)) {
		printk("error in arch_validate_prot");
		return -EINVAL;
	}
	newprot = calc_vm_prot_bits(prot, 0);
	new_pgprot = vm_get_page_prot(newprot);

	tlb_gather_mmu(&tlb, mm);
	// mprotect_fixup
	// change_protection
	// change_protection_range
	pgd = pgd_offset(mm, address);
	if (pgd_none_or_clear_bad(pgd))
		goto error;
	// change_p4d_range
	p4d = p4d_offset(pgd, address);
	if (p4d_none_or_clear_bad(p4d))
		goto error;
	// change_pud_range
	pud = pud_offset(p4d, address);
	if (pud_none_or_clear_bad(pud))
		goto error;
	// change_pmd_range
	pmd = pmd_offset(pud, address);
	if (pmd_none_or_trans_huge_or_clear_bad(pmd))
		goto error;
	// change_pte_range
	pte = pte_offset_map(pmd, address);
	oldpte = *pte;
	if (pte_none(oldpte))
		goto error;
	if (pte_present(oldpte)) {
		page = pte_page(oldpte);
		if (!page)
			goto error;
		newpte = pte_modify(oldpte, new_pgprot);
		if (prot & PROT_WRITE)
			newpte = pte_mkwrite(newpte);
		set_pte_at(mm, address, pte, newpte);

		if (pte_needs_flush(oldpte, newpte))
			tlb_flush_pte_range(&tlb, address, PAGE_SIZE);

		// TODO: COW.
	}
	tlb_finish_mmu(&tlb);

	return 1;
error:
	return 0;
}

BPF_CALL_5(bpf_set_page_table, unsigned long, vaddr, size_t, len, unsigned long, paddr,
	   unsigned long, vmf_flags, unsigned long, prot)
{
	vaddr = vaddr & PAGE_MASK;

	if (!current->sbpf)
		return 0;

	return bpf_set_pte(vaddr, len, paddr, vmf_flags, prot);
}

const struct bpf_func_proto bpf_set_page_table_proto = {
	.func = bpf_set_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};

BPF_CALL_2(bpf_unset_page_table, unsigned long, vaddr, size_t, len)
{
	vaddr = vaddr & PAGE_MASK;

	if (!current->sbpf)
		return 0;

	return bpf_unset_pte(vaddr, len);
}

const struct bpf_func_proto bpf_unset_page_table_proto = {
	.func = bpf_unset_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};

BPF_CALL_5(bpf_touch_page_table, unsigned long, vaddr, size_t, len, unsigned long, paddr,
	   unsigned long, vmf_flags, unsigned long, prot)
{
	vaddr = vaddr & PAGE_MASK;

	if (!current->sbpf)
		return 0;

	return bpf_touch_pte(vaddr, len, vmf_flags, prot);
}

const struct bpf_func_proto bpf_touch_page_table_proto = {
	.func = bpf_touch_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};