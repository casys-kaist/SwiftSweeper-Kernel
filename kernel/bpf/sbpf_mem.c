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
#include <asm/page_types.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>

#include "sbpf_mem.h"

BPF_CALL_4(bpf_set_page_table, unsigned long, address, unsigned long, vmf_flags,
	   unsigned long, prot, unsigned long, vm_flags)
{
	struct mm_struct *mm = current->mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t orig_pte;
	pte_t entry;
	pgprot_t pgprot;
	pgprot.pgprot = prot;

	if (!current->sbpf)
		return 0;

	address = address & PAGE_MASK;
	pgd = pgd_offset(mm, address);
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return 0;

	pud = pud_alloc(mm, p4d, address);
	if (!pud)
		return 0;

	if (pud_none(*pud) && (vm_flags & VM_HUGEPAGE))
		return -ENOTSUPP;

	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		return 0;

	if (pmd_none(*pmd) && (vm_flags & VM_HUGEPAGE))
		return 0;

	if (unlikely(pmd_none(*pmd))) {
		pte = NULL;
	} else {
		pte = pte_offset_map(pmd, address);
		orig_pte = *pte;

		barrier();
		if (pte_none(orig_pte)) {
			pte_unmap(pte);
			pte = NULL;
		}
	}

	if (!pte) {
		// Do pte missing
		if (pte_alloc(mm, pmd))
			return 0;

		// When mmap first allocates a pgprot of a pte, it marks the page with no write permission.
		// Thus, to use the zero page frame, we have to check pgprot doesn't have RW permission.
		if (!(vmf_flags & FAULT_FLAG_WRITE) &&
		    !(pgprot_val(pgprot) & _PAGE_RW)) {
			entry = pfn_pte(my_zero_pfn(address), pgprot);
			entry = pte_mkspecial(entry);
			pte = pte_offset_map(pmd, address);
		} else {
			struct folio *folio =
				folio_alloc(GFP_USER | __GFP_ZERO, 0);
			struct sbpf_alloc_folio *allocated_folio;

			if (!folio)
				return 0;
			if (mem_cgroup_charge(folio, mm, GFP_KERNEL))
				return 0;

			entry = mk_pte(&folio->page, pgprot);
			entry = pte_sw_mkyoung(entry);
			entry = pte_mkwrite(entry);
			pte = pte_offset_map(pmd, address);

			inc_mm_counter(mm, MM_ANONPAGES);

			allocated_folio = kmalloc(
				sizeof(struct sbpf_alloc_folio), GFP_KERNEL);
			INIT_LIST_HEAD(&allocated_folio->list);
			allocated_folio->folio = folio;
			list_add(&allocated_folio->list,
				 &current->sbpf->alloc_folios);
		}
		set_pte_at(mm, address, pte, entry);
		pte_unmap(pte);

		return 1;
	}

	printk("COW Not implemented yet");

	return 0;
}

const struct bpf_func_proto bpf_set_page_table_proto = {
	.func = bpf_set_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};
