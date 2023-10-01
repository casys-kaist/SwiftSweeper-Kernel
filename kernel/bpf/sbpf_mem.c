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
#include <asm/page_types.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/tlb.h>

#include "sbpf_mem.h"

inline pte_t *walk_page_table_pte(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pud_t *pud;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	if (pgd_none_or_clear_bad(pgd))
		return NULL;
	// zap_p4d_range
	p4d = p4d_offset(pgd, address);
	if (p4d_none_or_clear_bad(p4d))
		return NULL;
	// zap_pud_range
	pud = pud_offset(p4d, address);
	if (pud_none_or_clear_bad(pud))
		return NULL;
	// zap_pmd_range
	pmd = pmd_offset(pud, address);
	if (pmd_none_or_trans_huge_or_clear_bad(pmd))
		return NULL;
	// zap_pte_range
	pte = pte_offset_map(pmd, address);

	return pte;
}

inline int touch_page_table_pte(struct mm_struct *mm, unsigned long vaddr, pte_t **pte)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t orig_pte;

	vaddr = vaddr & PAGE_MASK;
	pgd = pgd_offset(mm, vaddr);
	p4d = p4d_alloc(mm, pgd, vaddr);
	if (!p4d)
		return -EINVAL;

	pud = pud_alloc(mm, p4d, vaddr);
	if (!pud)
		return -EINVAL;

	pmd = pmd_alloc(mm, pud, vaddr);
	if (!pmd)
		return -EINVAL;

	if (unlikely(pmd_none(*pmd))) {
		*pte = NULL;
	} else {
		*pte = pte_offset_map(pmd, vaddr);
		orig_pte = **pte;

		barrier();
		if (pte_none(orig_pte)) {
			pte_unmap(*pte);
			*pte = NULL;
		}
	}

	if (!*pte) {
		if (pte_alloc(mm, pmd))
			return -EINVAL;
	} else {
		*pte = pte_offset_map(pmd, vaddr);
		return -EEXIST;
	}

	*pte = pte_offset_map(pmd, vaddr);
	return 0;
}

pte_t *sbpf_set_write_protected_pte(struct task_struct *tsk, unsigned long vaddr,
				    pgprot_t pgprot, struct folio *folio)
{
	int ret;
	pte_t *pte;
	pte_t entry;

	ret = touch_page_table_pte(tsk->mm, vaddr, &pte);

	if (likely(!ret)) {
		entry = mk_pte(&folio->page, pgprot);
		entry = pte_sw_mkyoung(entry);
		entry = pte_wrprotect(entry);
		set_pte_at(tsk->mm, vaddr, pte, entry);
		pte_unmap(pte);
	} else {
		printk("Invalid pte at the new task %d 0x%lx\n", tsk->pid, vaddr);
		return NULL;
	}

	return pte;
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

// If paddr is 0, kernel allocates the memory.
static int bpf_map_pte(unsigned long vaddr, unsigned long paddr, unsigned long vmf_flags,
		       unsigned long prot, unsigned long vm_flags)
{
	struct mm_struct *mm = current->mm;
	struct folio *folio = NULL;
	void __rcu **slot = NULL;
#ifdef USE_RADIX_TREE
	struct radix_tree_root *paddr_to_folio;
#else
	struct trie_node *spages;
#endif
	int ret;
	int new_folio = 0;
	pte_t *pte;
	pte_t entry;
	pgprot_t pgprot;
	pgprot.pgprot = prot;

	if (!current->sbpf)
		return 0;

#ifdef USE_RADIX_TREE
	paddr_to_folio = &current->sbpf->page_fault.sbpf_mm->paddr_to_folio;
#else
	spages = current->sbpf->page_fault.sbpf_mm->shadow_pages;
#endif

	vaddr = vaddr & PAGE_MASK;
	paddr = paddr & PAGE_MASK;
	ret = touch_page_table_pte(mm, vaddr, &pte);

	if (paddr == 0)
		return -EINVAL;

	if (likely(!ret)) {
		// When mmap first allocates a pgprot of a pte, it marks the page with no write permission.
		// Thus, to use the zero page frame, we have to check pgprot doesn't have RW permission.
		// Note that, paddr (sbpf physical address) starts from 1 and 0 means zero page (Not fixed yet).
		if (!(vmf_flags & FAULT_FLAG_WRITE) && !(pgprot_val(pgprot) & _PAGE_RW) &&
		    !paddr) {
			entry = pfn_pte(my_zero_pfn(vaddr), pgprot);
			entry = pte_mkspecial(entry);
		} else {
			if (paddr) {
				// This optimization slows down the overall performance. Disable temporary before delete.
#ifdef USE_RADIX_TREE
				slot = radix_tree_lookup_slot(paddr_to_folio, paddr);
				folio = slot != NULL ?
						rcu_dereference_protected(*slot, true) :
						NULL;
#else
				ppte = (pte_t *)trie_search(spages, paddr);
#endif
				if (!IS_ERR_OR_NULL(folio) &&
				    folio_ref_count(folio) > 0) {
					entry = mk_pte(&folio->page, pgprot);
					entry = pte_sw_mkyoung(entry);
					entry = pte_mkwrite(entry);
					goto set_pte;
				}
			}

			folio = folio_alloc(GFP_USER | __GFP_ZERO, 0);
			new_folio = 1;
			if (unlikely(!folio))
				return 0;
			if (mem_cgroup_charge(folio, mm, GFP_KERNEL))
				return 0;

			entry = mk_pte(&folio->page, pgprot);
			entry = pte_sw_mkyoung(entry);
			entry = pte_mkwrite(entry);

			inc_mm_counter(mm, MM_ANONPAGES);
		}

set_pte:
		set_pte_at(mm, vaddr, pte, entry);
		ret = sbpf_mem_insert_paddr(
			&current->sbpf->page_fault.sbpf_mm->vaddr_to_paddr, vaddr, paddr);
		if (unlikely(!ret)) {
			printk("Error in radix_tree_insert 0x%lx error %d\n", vaddr, ret);
			return 0;
		}
		// We allocate new page, but original paddr is empty.
		// Thus, we have to touch the trie structure for the shadow page and set the shared pte.
		// Todo! After allocation, pgprot will be different from the kernel's vma, so we have to fix it.
		if (paddr && folio != NULL && new_folio) {
			// Caching the pte entry to the shadow page trie.
#ifdef USE_RADIX_TREE
			if (!slot) {
				ret = radix_tree_insert(paddr_to_folio, paddr, folio);
				if (unlikely(ret)) {
					printk("Error in trie_insert 0x%lx error %d\n",
					       paddr, ret);
					return 0;
				}
			} else {
				radix_tree_replace_slot(paddr_to_folio, slot, folio);
			}
#else
			if (trie_insert(spages, paddr, (uint64_t)pte)) {
				printk("Error in trie_insert 0x%lx", paddr);
				return 0;
			}
#endif
		}
		pte_unmap(pte);
		// TODO!. We have to elaborate the boundary mechanism.
		if (current->sbpf->max_alloc_end < vaddr + PAGE_SIZE) {
			current->sbpf->max_alloc_end = vaddr + PAGE_SIZE;
		}

		return 1;
	} else {
		// printk("COW Not implemented yet");
	}

	return 0;
}

static int bpf_unmap_pte(unsigned long address, unsigned long vm_flags,
			 unsigned long prot, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct mmu_gather tlb;
	unsigned long paddr;
	pte_t *pte;
	pte_t ptent;
	struct page *page = NULL;
	struct folio *folio = NULL;

	// unmap_region
	tlb_gather_mmu(&tlb, mm);

	// unmap_vmas
	// unmap_single_vma
	// unmap_page_range
	address = address & PAGE_MASK;
	pte = walk_page_table_pte(mm, address);
	if (pte == NULL)
		goto error;
	ptent = *pte;
	if (pte_none(ptent))
		goto error;
	if (pte_present(ptent)) {
		page = pte_page(ptent);
		if (!page)
			goto error;
		ptep_get_and_clear(mm, address, pte);
		tlb_remove_tlb_entry(&tlb, pte, address);
		folio = page_folio(page);
	}
	pte_clear(mm, address, pte);
	paddr = sbpf_mem_put_paddr(&current->sbpf->page_fault.sbpf_mm->vaddr_to_paddr,
				   address);
	if (paddr) {
		if (folio != NULL)
			folio_put(folio);
		radix_tree_delete(&current->sbpf->page_fault.sbpf_mm->paddr_to_folio,
				  paddr);
		dec_mm_counter(current->mm, MM_ANONPAGES);
	}

	tlb_finish_mmu(&tlb);

	return 1;
error:
	return 0;
}

static int bpf_set_prot_pte(unsigned long address, unsigned long vm_flags,
			    unsigned long prot, unsigned long flags)
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

BPF_CALL_5(bpf_set_page_table, unsigned long, vaddr, unsigned long, paddr, unsigned long,
	   vmf_flags, unsigned long, prot, unsigned long, vm_flags)
{
	unsigned long op = vm_flags & 3;
	vm_flags = vm_flags & (~3UL);
	vaddr = vaddr & PAGE_MASK;

	if (!current->sbpf)
		return 0;

	switch ((unsigned long)op) {
	case PTE_MAP:
		return bpf_map_pte(vaddr, paddr, vmf_flags, prot, vm_flags);
	case PTE_UNMAP:
		return bpf_unmap_pte(vaddr, vmf_flags, prot, vm_flags);
	case PTE_SET_PROT:
		return bpf_set_prot_pte(vaddr, vmf_flags, prot, vm_flags);
	default:
		return 0;
	}
}

const struct bpf_func_proto bpf_set_page_table_proto = {
	.func = bpf_set_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};
