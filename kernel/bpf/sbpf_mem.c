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
#include <asm-generic/pgalloc.h>

#include "sbpf_mem.h"

/**
 * walk the page table range from the [start, end) 
 * continue_walk: if true, continue to walk the page table even if there exists hole in the page table.
 * The 'func' is expected to return one of the following values:
 * SBPF_PTE_WALK_NEXT_PTE: Continue to the next PTE.
 * SBPF_PTE_WALK_NEXT_PMD: Skip to the next PMD.
 * SBPF_PTE_WALK_STOP: Stop the iteration.
 * Negative value: Return the value as an error code.
 */
int walk_page_table_pte_range(struct mm_struct *mm, unsigned long start,
			      unsigned long end, pte_func func, void *aux,
			      bool continue_walk)
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
		if (pgd_none_or_clear_bad(pgd)) {
			if (continue_walk)
				continue;
			return -ENOENT;
		}

		p4d = p4d_offset(pgd, addr);
		do {
			next_p4d = p4d_addr_end(addr, next_pgd);
			if (p4d_none_or_clear_bad(p4d)) {
				if (continue_walk)
					continue;
				return -ENOENT;
			}

			pud = pud_offset(p4d, addr);
			do {
				next_pud = pud_addr_end(addr, next_p4d);
				if (pud_none_or_clear_bad(pud)) {
					if (continue_walk)
						continue;
					return -ENOENT;
				}

				pmd = pmd_offset(pud, addr);
				do {
					next_pmd = pmd_addr_end(addr, next_pud);
					if (pmd_none_or_clear_bad(pmd)) {
						if (continue_walk)
							continue;
						return -ENOENT;
					}

					pte = pte_offset_map(pmd, addr);
					do {
						if (pte_none(*pte)) {
							if (continue_walk)
								continue;
							return -ENOENT;
						}
						ret = func(pmd, pte, addr, aux);
						switch (ret) {
						case SBPF_PTE_WALK_NEXT_PTE:
							break;
						case SBPF_PTE_WALK_NEXT_PMD:
							addr = next_pmd - PAGE_SIZE;
							break;
						case SBPF_PTE_WALK_STOP:
							return 0;
						default:
							if (unlikely(ret))
								return ret;
						}
					} while (pte++, addr += PAGE_SIZE,
						 addr != next_pmd);
				} while (pmd++, addr = next_pmd, addr != next_pud);
			} while (pud++, addr = next_pud, addr != next_p4d);
		} while (p4d++, addr = next_p4d, addr != next_pgd);
	} while (pgd++, addr = next_pgd, addr != end);

	return 0;
}

/**
* Unlike walk_page_table(), this function touches each PTE in the given range
* and calls the provided function 'func' for each PTE.
* The 'func' is expected to return one of the following values:
* SBPF_PTE_WALK_NEXT_PTE: Continue to the next PTE.
* SBPF_PTE_WALK_NEXT_PMD: Skip to the next PMD.
* SBPF_PTE_WALK_STOP: Stop the iteration.
* Negative value: Return the value as an error code.
*/
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
						ret = func(pmd, pte, addr, aux);
						switch (ret) {
						case SBPF_PTE_WALK_NEXT_PTE:
							break;
						case SBPF_PTE_WALK_NEXT_PMD:
							addr = next_pmd - PAGE_SIZE;
							ret = 0;
							break;
						case SBPF_PTE_WALK_STOP:
							return 0;
						default:
							if (unlikely(ret))
								return ret;
						}
					} while (pte++, addr += PAGE_SIZE,
						 addr != next_pmd);
				} while (pmd++, addr = next_pmd, addr != next_pud);
			} while (pud++, addr = next_pud, addr != next_p4d);
		} while (p4d++, addr = next_p4d, addr != next_pgd);
	} while (pgd++, addr = next_pgd, addr != end);

	return 0;
}

static int __get_wp_pte(pmd_t *pmd, pte_t *pte, unsigned long addr, void *aux)
{
	struct folio *folio;

	folio = page_folio(pte_page(*pte));
	if (likely(!IS_ERR_OR_NULL(folio))) {
		if (!(pte_flags(*pte) & _PAGE_RW)) {
			folio = sbpf_mem_copy_on_write(current->sbpf, folio);
			if (unlikely(IS_ERR_OR_NULL(folio))) {
				printk("mbpf: copy on write failed on __get_wp_pte 0x%lx\n",
				       addr);
				return -EINVAL;
			}
		}
	} else {
		printk("mbpf: __get_wp_pte failed 0x%lx\n", addr);
		return -EINVAL;
	}

	*(pte_t *)aux = *pte;

	return SBPF_PTE_WALK_STOP;
}

struct set_pte_aux {
	pte_t *entry;
	bool update_pmd;
};

static int __set_write(pmd_t *pmd, pte_t *pte, unsigned long addr, void *aux_)
{
	struct folio *folio;
	struct set_pte_aux *aux = aux_;

	// This function doesn't require TLB flush, because the page is soley mapped.
	pte_t entry = *(aux->entry);
	folio = page_folio(pte_page(entry));
	set_pte_at(current->mm, addr, pte, entry);

	return SBPF_PTE_WALK_NEXT_PTE;
}

static int __set_pte(pmd_t *pmd, pte_t *pte, unsigned long addr, void *aux_)
{
	struct folio *folio;
	struct set_pte_aux *aux = aux_;

	pte_t entry = *(aux->entry);
	folio = page_folio(pte_page(entry));
	atomic_inc(&folio->_mapcount);
	folio_get(folio);
	set_pte_at(current->mm, addr, pte, entry);
	tlb_flush_pte_range(current->sbpf->tlb, addr, PAGE_SIZE);
	if (aux->update_pmd) {
		atomic_inc(&pmd_pgtable(*pmd)->pte_refcount);
	}

	return SBPF_PTE_WALK_NEXT_PTE;
}

/**
 * Copy-on-write function for the orig_folio.
 * This function performs copy-on-write operation on the orig_folio,
 * creating a new folio if necessary and updating the necessary metadata.
 *
 * @param orig_folio The original folio to perform copy-on-write on.
 * @return The new folio after the copy-on-write operation.
 */
struct folio *sbpf_mem_copy_on_write(struct sbpf_task *sbpf, struct folio *orig_folio)
{
	unsigned long paddr;
	struct folio *folio;
	int ret;
	pte_t entry;
	struct set_pte_aux aux;
#ifdef USE_MAPLE_TREE
	struct sbpf_reverse_map *smap;
	MA_STATE(mas, NULL, 0, 0);
#else
	struct sbpf_reverse_map_elem *cur;
#endif

	if (unlikely(orig_folio == NULL || orig_folio->page.sbpf_reverse == NULL))
		return ERR_PTR(-EINVAL);

	if ((unsigned long)orig_folio->page.sbpf_reverse & 0xf) {
		paddr = (unsigned long)orig_folio->page.sbpf_reverse & PAGE_MASK;
		if (unlikely(paddr == 0))
			return ERR_PTR(-EINVAL);

		folio = orig_folio;
		entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
		entry = pte_sw_mkyoung(entry);
		entry = pte_mkwrite(entry);
		aux.entry = &entry;
		aux.update_pmd = false;
		ret = walk_page_table_pte_range(current->mm, paddr, paddr + PAGE_SIZE,
						__set_write, &aux, false);
		if (unlikely(ret)) {
			printk("mbpf: set addr range failed (%d): [0x%lx, 0x%lx)\n", ret,
			       paddr, paddr + PAGE_SIZE);
			return ERR_PTR(ret);
		}
		return folio;
	}

	paddr = orig_folio->page.sbpf_reverse->paddr;
	if (unlikely(paddr == 0))
		return ERR_PTR(-EINVAL);

	// When the page is shared, we have to copy the page (folio).
	// We have to make the parent page as a read only.
	if ((unsigned long)orig_folio->page.sbpf_reverse->size !=
	    folio_ref_count(orig_folio)) {
		folio = folio_alloc(GFP_USER | __GFP_ZERO, 0);
		inc_mm_counter(current->mm, MM_ANONPAGES);
		folio_set_mbpf(folio);
		if (unlikely(!folio))
			return ERR_PTR(-ENOMEM);
		if (mem_cgroup_charge(folio, current->mm, GFP_KERNEL))
			return ERR_PTR(-ENOMEM);

		folio_copy(folio, orig_folio);
		folio->page.sbpf_reverse =
			sbpf_reverse_dup(orig_folio->page.sbpf_reverse);

		entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
		entry = pte_sw_mkyoung(entry);
		entry = pte_mkwrite(entry);

		aux.entry = &entry;
		aux.update_pmd = false;
#ifdef USE_MAPLE_TREE
		mas.tree = folio->page.sbpf_reverse->mt;
		mas_for_each(&mas, smap, ULONG_MAX)
		{
			if (smap == NULL)
				continue;
			ret = walk_page_table_pte_range(
				current->mm, mas.index & PAGE_MASK,
				(mas.last & PAGE_MASK) + PAGE_SIZE, __set_pte, &entry,
				false);
			if (unlikely(ret)) {
				printk("Error in set addr range (%d): [0x%lx, 0x%lx)\n",
				       ret, s mas.index, mas.last);
			}
		}
#else
		list_for_each_entry (cur, &folio->page.sbpf_reverse->elem, list) {
			ret = walk_page_table_pte_range(current->mm, cur->start, cur->end,
							__set_pte, &aux, false);
			if (unlikely(ret)) {
				printk("mbpf: set addr range failed (%d): [0x%lx, 0x%lx)\n",
				       ret, cur->start, cur->end);
				return ERR_PTR(ret);
			}
		}
#endif
		folio_put(folio);
		atomic_sub(folio_ref_count(folio), &orig_folio->_mapcount);
		folio_put_refs(orig_folio, folio_ref_count(folio));
	} else {
		folio = orig_folio;
		entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
		entry = pte_sw_mkyoung(entry);
		entry = pte_mkwrite(entry);
		aux.entry = &entry;
		aux.update_pmd = false;
#ifdef USE_MAPLE_TREE
		mas.tree = folio->page.sbpf_reverse->mt;
		mas_for_each(&mas, smap, ULONG_MAX)
		{
			if (smap == NULL)
				continue;
			ret = walk_page_table_pte_range(
				current->mm, mas.index & PAGE_MASK,
				(mas.last & PAGE_MASK) + PAGE_SIZE, __set_write, NULL,
				false);
			if (unlikely(ret)) {
				printk("Error in set addr range (%d): [0x%lx, 0x%lx)\n",
				       ret, s mas.index, mas.last);
			}
		}
#else
		list_for_each_entry (cur, &folio->page.sbpf_reverse->elem, list) {
			ret = walk_page_table_pte_range(current->mm, cur->start, cur->end,
							__set_write, &aux, false);
			if (unlikely(ret)) {
				printk("mbpf: set addr range failed (%d): [0x%lx, 0x%lx)\n",
				       ret, cur->start, cur->end);
				return ERR_PTR(ret);
			}
		}
#endif
	}

	return folio;
}

/**
 * Set the page table entry (PTE) for a given virtual address.
 *
 * @vaddr: The virtual address for which the PTE needs to be set.
 * @len: The length of the memory region to be mapped [vaddr, vaddr + len).
 * @paddr: The pseudo-physical address to be mapped to the virtual address. 
 * If the value is 0, then the virtual address is used as the physical address, i.e., Idential mapping.
 * @vmf_flags: The flags for the virtual memory region.
 * @prot: The protection flags for the virtual memory region.
 *
 * This function sets the page table entry (PTE) for the specified virtual address
 * to the provided value. The PTE determines the attributes and physical address
 * mapping for the given virtual address in the page table.
 */
static int bpf_set_pte(unsigned long vaddr, size_t len, unsigned long paddr,
		       unsigned long vmf_flags, unsigned long prot)
{
	struct mm_struct *mm = current->mm;
	struct folio *folio = NULL;
	int ret;
	struct set_pte_aux aux;
	pte_t entry;
	pgprot_t pgprot;
	pgprot.pgprot = prot;

	if (unlikely(!current->sbpf))
		return -EINVAL;
	else if (unlikely(len == 0))
		return -EINVAL;

	if (!paddr)
		paddr = vaddr;

	vaddr = vaddr & PAGE_MASK;
	paddr = paddr & PAGE_MASK;

	// When mmap first allocates a pgprot of a pte, it marks the page with no write permission.
	// Thus, to use the zero page frame, we have to check pgprot doesn't have RW permission.
	// Note that, paddr (sbpf physical address) starts from 1 and 0 means zero page (Not fixed yet).
	// This optimization slows down the overall performance. Disable temporary before delete.
	ret = walk_page_table_pte_range(mm, paddr, paddr + PAGE_SIZE, __get_wp_pte,
					&entry, false);
	if (ret) {
		if (likely(ret == -ENOENT)) {
			folio = folio_alloc(GFP_USER | __GFP_ZERO, 0);
			if (unlikely(!folio))
				return -ENOMEM;

			folio_set_mbpf(folio);
			folio->page.sbpf_reverse = __sbpf_reverse_init(paddr);
			if (mem_cgroup_charge(folio, current->mm, GFP_KERNEL))
				return -ENOMEM;

			entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
			entry = pte_sw_mkyoung(entry);
			entry = pte_mkwrite(entry);
			aux.entry = &entry;
			aux.update_pmd = true;

			if (paddr != vaddr) {
				ret = touch_page_table_pte_range(current->mm, paddr,
								 paddr + PAGE_SIZE,
								 __set_pte, &aux);
				ret |= sbpf_reverse_insert_range(folio->page.sbpf_reverse,
								 paddr,
								 paddr + PAGE_SIZE);
			} else {
				ret = touch_page_table_pte_range(
					current->mm, paddr, paddr + len, __set_pte, &aux);
				ret |= sbpf_reverse_insert_range(folio->page.sbpf_reverse,
								 paddr, paddr + len);
			}
			if (unlikely(ret)) {
				printk("mbpf: invalid touch page pte pid %d ret %d paddr 0x%lx\n",
				       current->pid, ret, paddr);
				return -EINVAL;
			}
			folio_put(folio);
			inc_mm_counter(current->mm, MM_ANONPAGES);
		} else {
			printk("mbpf: invalid paddr pte pid %d ret %d range [0x%lx, 0x%lx)\n",
			       current->pid, ret, paddr, paddr + PAGE_SIZE);
			return ret;
		}
	} else {
		folio = page_folio(pte_page(entry));
		aux.entry = &entry;
		aux.update_pmd = true;

		if (unlikely(folio->page.sbpf_reverse == NULL)) {
			printk("mbpf: invalid remapping request without BPF_MBPF mmap flags 0x%lx\n",
			       paddr);
			return -EINVAL;
		}
	}

	if (paddr != vaddr) {
		ret = touch_page_table_pte_range(current->mm, vaddr, vaddr + len,
						 __set_pte, &aux);
		ret |= sbpf_reverse_insert_range(folio->page.sbpf_reverse, vaddr,
						 vaddr + len);
		if (unlikely(ret)) {
			printk("mbpf: invalid touch page pte range %d ret: %d [0x%lx, 0x%lx)\n",
			       current->pid, ret, vaddr, vaddr + len);
			return -EINVAL;
		}
	}

	if (unlikely(ret)) {
		printk("mbpf: insert reverse map failed 0x%lx (0x%lx) error %d\n", vaddr,
		       len, ret);
		sbpf_reverse_dump(folio->page.sbpf_reverse);
		return -EINVAL;
	}

	return 0;
}

struct unset_pte_aux {
	uint64_t start_addr;
	uint64_t end_addr;
	struct folio *folio;
};

static inline int unset_trie_entry(uint64_t start, uint64_t end, struct folio *folio)
{
	int ret;

	ret = sbpf_reverse_remove_range(folio->page.sbpf_reverse, start, end);
	if (unlikely(ret)) {
		printk("mbpf: sbpf_reverse_remove_range failed 0x%lx 0x%lx\n",
		       (unsigned long)start, (unsigned long)end);
		return -EINVAL;
	}
	if (sbpf_reverse_empty(folio->page.sbpf_reverse)) {
		BUG_ON(folio_ref_count(folio) == 0);
		sbpf_reverse_delete(folio->page.sbpf_reverse);
		folio->page.sbpf_reverse = NULL;
		dec_mm_counter(current->mm, MM_ANONPAGES);
		return 0;
	}

	return 0;
}

static int __unset_pte_single(pmd_t *pmd, pte_t *pte, unsigned long addr, void *_aux)
{
	struct folio *folio;
	struct page *pmd_page;
	int ret = SBPF_PTE_WALK_STOP;

	folio = page_folio(pte_page(*pte));
	// Temporary check the pte is mBPF folio by checking the reverse mapping exists.
	if (!folio || !folio->page.sbpf_reverse)
		return 0;

	// If the folio is shared, we have to copy the page before remove (folio).
	if ((!(pte_flags(*pte) & _PAGE_RW))) {
		if ((unsigned long)folio->page.sbpf_reverse & 0xf) {
			if (folio_ref_count(folio) != 1) {
				folio = sbpf_mem_copy_on_write(current->sbpf, folio);
				if (IS_ERR_OR_NULL(folio)) {
					printk("mbpf: copy on write failed on bpf_unset_pte 0x%lx\n",
					       addr);
					return -EINVAL;
				}
			}
		} else {
			if (folio->page.sbpf_reverse->size != folio_ref_count(folio)) {
				folio = sbpf_mem_copy_on_write(current->sbpf, folio);
				if (IS_ERR_OR_NULL(folio)) {
					printk("mbpf: copy on write failed on bpf_unset_pte 0x%lx\n",
					       addr);
					return -EINVAL;
				}
			}
		}
	}

	atomic_dec(&folio->_mapcount);
	pte_clear(current->mm, addr, pte);
	tlb_remove_tlb_entry(current->sbpf->tlb, pte, addr);

	if (atomic_dec_and_test(&pmd_pgtable(*pmd)->pte_refcount)) {
		pmd_page = pmd_pgtable(*pmd);
		pmd_clear(pmd);
		tlb_remove_pmd_tlb_entry(current->sbpf->tlb, pmd, addr & PMD_MASK);
		mm_dec_nr_ptes(current->sbpf->tlb->mm);
		pte_free(current->mm, pmd_page);
	}

	ret = unset_trie_entry(addr, addr + PAGE_SIZE, folio);
	folio_put(folio);

	return ret;
}

static int __unset_pte(pmd_t *pmd, pte_t *pte, unsigned long addr, void *_aux)
{
	struct folio *folio;
	struct unset_pte_aux *aux = _aux;
	struct page *pmd_page;
	int ret = SBPF_PTE_WALK_NEXT_PTE;

	folio = page_folio(pte_page(*pte));
	// Temporary check the pte is mBPF folio by checking the reverse mapping exists.
	if (!folio || !folio->page.sbpf_reverse)
		return 0;

	// If the folio is shared, we have to copy the page before remove (folio).
	if ((!(pte_flags(*pte) & _PAGE_RW))) {
		if ((unsigned long)folio->page.sbpf_reverse & 0xf) {
			if (folio_ref_count(folio) != 1) {
				folio = sbpf_mem_copy_on_write(current->sbpf, folio);
				if (IS_ERR_OR_NULL(folio)) {
					printk("mbpf: copy on write failed on bpf_unset_pte 0x%lx\n",
					       addr);
					return -EINVAL;
				}
			}
		} else {
			if (folio->page.sbpf_reverse->size != folio_ref_count(folio)) {
				folio = sbpf_mem_copy_on_write(current->sbpf, folio);
				if (IS_ERR_OR_NULL(folio)) {
					printk("mbpf: copy on write failed on bpf_unset_pte 0x%lx\n",
					       addr);
					return -EINVAL;
				}
			}
		}
	}

	atomic_dec(&folio->_mapcount);
	pte_clear(current->mm, addr, pte);
	tlb_remove_tlb_entry(current->sbpf->tlb, pte, addr);

	if (atomic_dec_and_test(&pmd_pgtable(*pmd)->pte_refcount)) {
		pmd_page = pmd_pgtable(*pmd);
		pmd_clear(pmd);
		tlb_remove_pmd_tlb_entry(current->sbpf->tlb, pmd, addr & PMD_MASK);
		mm_dec_nr_ptes(current->sbpf->tlb->mm);
		pte_free(current->mm, pmd_page);
		ret = SBPF_PTE_WALK_NEXT_PMD;
	}

	if (aux->folio == NULL) {
		aux->folio = folio;
		aux->start_addr = addr;
		aux->end_addr = addr + PAGE_SIZE;
		return ret;
	}

	if (aux->folio != folio) {
		ret = unset_trie_entry(aux->start_addr, aux->end_addr, aux->folio);
		folio_put_refs(aux->folio, (aux->end_addr - aux->start_addr) / PAGE_SIZE);
		if (unlikely(ret))
			return ret;

		aux->folio = folio;
		aux->start_addr = addr;
		aux->end_addr = addr + PAGE_SIZE;
	} else {
		if (likely(aux->end_addr == addr)) {
			aux->end_addr += PAGE_SIZE;
		} else { // aliases : [mapped to canon(folio) x | unmmaped ... | mapped to canon(folio) x]
			ret = unset_trie_entry(aux->start_addr, aux->end_addr, folio);
			folio_put_refs(folio,
				       (aux->end_addr - aux->start_addr) / PAGE_SIZE);
			if (unlikely(ret))
				return ret;

			// aux->folio = folio;
			aux->start_addr = addr;
			aux->end_addr = addr + PAGE_SIZE;
		}
	}

	return ret;
}

/**
 * Unset the page table entry (PTE) for a given virtual address.
 *
 * @addr: The virtual address for which the PTE needs to be unset.
 * @len: The length of the memory region to be unmapped [addr, addr + len).
 *
 * This function unsets the page table entry (PTE) for the specified virtual address.
 * It is used to remove the mapping between the virtual address and the physical page frame.
 */
static int bpf_unset_pte(unsigned long address, size_t len)
{
	struct mm_struct *mm = current->mm;
	struct unset_pte_aux aux;
	int ret = 0;

	if (len == 0)
		return 0;

	address = address & PAGE_MASK;
	if (len == PAGE_SIZE) {
		ret = walk_page_table_pte_range(mm, address, address + len,
						__unset_pte_single, NULL, true);
	} else {
		aux.folio = NULL;
		ret = walk_page_table_pte_range(mm, address, address + len, __unset_pte,
						&aux, true);
		if (aux.folio && likely(!ret)) {
			ret = unset_trie_entry(aux.start_addr, aux.end_addr, aux.folio);
			folio_put_refs(aux.folio,
				       (aux.end_addr - aux.start_addr) / PAGE_SIZE);
		}
	}

	if (unlikely(ret))
		printk("mbpf: bpf_unset_pte failed (%d) (addr : 0x%lx, len : 0x%lx)\n",
		       ret, address, len);

	return ret;
}

extern int __execute_only_pkey(struct mm_struct *mm);
static int __touch_pte(pmd_t *pmd, pte_t *pte, unsigned long addr, void *_aux)
{
	unsigned long prot = (unsigned long)_aux;
	pte_t entry;
	unsigned long pkey;

	switch (prot) {
	case BPF_SBPF_PROT_EXEC:
		pkey = __execute_only_pkey(current->mm);
		if (pkey == -1)
			return -EINVAL;
		entry = pte_set_flags(*pte, pkey << _PAGE_BIT_PKEY_BIT0);
		tlb_flush_pte_range(current->sbpf->tlb, addr, PAGE_SIZE);
		break;
	case BPF_SBPF_PROT_RDONLY:
		entry = pte_clear_flags(*pte, _PAGE_PKEY_MASK);
		entry = pte_wrprotect(entry);
		tlb_flush_pte_range(current->sbpf->tlb, addr, PAGE_SIZE);
		break;
	case BPF_SBPF_PROT_RDWR:
		entry = pte_clear_flags(*pte, _PAGE_PKEY_MASK);
		entry = pte_mkwrite(entry);
		break;
	default:
		printk("mbpf: invalid prot %lu\n", prot);
		return -EINVAL;
	}

	set_pte_at(current->mm, addr, pte, entry);

	return SBPF_PTE_WALK_NEXT_PTE;
}

// Temporary makes the address range as an read-only.
static int bpf_touch_pte(unsigned long address, size_t len, unsigned long vmf_flags,
			 unsigned long prot)
{
	struct mm_struct *mm = current->mm;
	int ret;

	if (len == 0)
		return 0;

	address = address & PAGE_MASK;

	ret = walk_page_table_pte_range(mm, address, address + len, __touch_pte,
					(void *)prot, true);
	if (unlikely(ret))
		printk("mbpf: touch page pte failed (%d) (addr : 0x%lx, len : 0x%lx)\n",
		       ret, address, len);

	return ret;
}

BPF_CALL_5(bpf_set_page_table, unsigned long, vaddr, size_t, len, unsigned long, paddr,
	   unsigned long, vmf_flags, unsigned long, prot)
{
	int ret;
	vaddr = vaddr & PAGE_MASK;

	if (!current->sbpf)
		return -EINVAL;

	sbpf_mm_lock(current->sbpf->page_fault.sbpf_mm, vaddr);
	ret = bpf_set_pte(vaddr, len, paddr, vmf_flags, prot);
	sbpf_mm_unlock(current->sbpf->page_fault.sbpf_mm, vaddr);

	return ret;
}

const struct bpf_func_proto bpf_set_page_table_proto = {
	.func = bpf_set_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};

BPF_CALL_2(bpf_unset_page_table, unsigned long, vaddr, size_t, len)
{
	int ret;
	vaddr = vaddr & PAGE_MASK;

	if (!current->sbpf)
		return -EINVAL;

	sbpf_mm_lock(current->sbpf->page_fault.sbpf_mm, vaddr);
	ret = bpf_unset_pte(vaddr, len);
	sbpf_mm_unlock(current->sbpf->page_fault.sbpf_mm, vaddr);

	return ret;
}

const struct bpf_func_proto bpf_unset_page_table_proto = {
	.func = bpf_unset_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};

/**
 * Touches the page table entry for the given address
 * @vaddr: The virtual address for which the PTE needs to be set.
 * @len: The length of the memory region to be mapped [vaddr, vaddr + len).
 * @paddr: Not used. Reserved for the future usages.
 * @vmf_flags: The flags for the virtual memory region.
 * @prot: The protection flags for the virtual memory region.
 *
 * This function touches the page table entry for the given address and sets the
 * specified flags. It ensures that the page table entry is present in the
 * page table hierarchy and updates the flags accordingly.
 */
BPF_CALL_5(bpf_touch_page_table, unsigned long, vaddr, size_t, len, unsigned long, paddr,
	   unsigned long, vmf_flags, unsigned long, prot)
{
	int ret;
	vaddr = vaddr & PAGE_MASK;

	if (!current->sbpf)
		return -EINVAL;

	sbpf_mm_lock(current->sbpf->page_fault.sbpf_mm, vaddr);
	ret = bpf_touch_pte(vaddr, len, vmf_flags, prot);
	sbpf_mm_unlock(current->sbpf->page_fault.sbpf_mm, vaddr);

	return ret;
}

const struct bpf_func_proto bpf_touch_page_table_proto = {
	.func = bpf_touch_page_table,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
};

struct sbpf_iter_pte_aux {
	bpf_callback_t callback;
	void *callback_ctx;
};

static int __iter_pte_none(pmd_t *pmd, pte_t *pte, unsigned long addr, void *aux)
{
	struct sbpf_iter_pte_aux *callback = aux;
	unsigned long pkey;
	pte_t entry;
	int ret = SBPF_PTE_WALK_NEXT_PTE;
	int callback_ret = 0;
	struct folio *folio;
	void *kaddr;

	folio = page_folio(pte_page(*pte));
	kaddr = kmap_local_page(pte_page(*pte));
	callback_ret =
		callback->callback((u64)kaddr, addr, (u64)callback->callback_ctx, 0, 0);
	kunmap_local(kaddr);

	switch (callback_ret) {
	case BPF_SBPF_ITER_TOUCH_NONE:
		ret = SBPF_PTE_WALK_NEXT_PTE;
		goto done;
	case BPF_SBPF_ITER_TOUCH_EXEC:
		pkey = __execute_only_pkey(current->mm);
		if (pkey == -1) {
			ret = -EINVAL;
			goto done;
		}
		entry = pte_set_flags(*pte, pkey << _PAGE_BIT_PKEY_BIT0);
		tlb_flush_pte_range(current->sbpf->tlb, addr, PAGE_SIZE);
		goto set;
	case BPF_SBPF_ITER_TOUCH_RDONLY:
		entry = pte_clear_flags(*pte, _PAGE_PKEY_MASK);
		entry = pte_wrprotect(entry);
		tlb_flush_pte_range(current->sbpf->tlb, addr, PAGE_SIZE);
		goto set;
	case BPF_SBPF_ITER_TOUCH_RDWR:
		entry = pte_clear_flags(*pte, _PAGE_PKEY_MASK);
		entry = pte_mkwrite(entry);
		goto set;
	case BPF_SBPF_ITER_TOUCH_STOP:
		ret = SBPF_PTE_WALK_STOP;
		goto done;
	default:
		printk("mbpf: invalid prot %d\n", ret);
		ret = -EINVAL;
		goto done;
	}

set:
	set_pte_at(current->mm, addr, pte, entry);

done:
	return SBPF_PTE_WALK_NEXT_PTE;
}

static int __iter_pte_create(pmd_t *pmd, pte_t *pte, unsigned long addr, void *aux)
{
	struct sbpf_iter_pte_aux *callback = aux;
	struct folio *folio;
	pte_t entry;
	int ret = 0;
	void *kaddr;

	if (unlikely(pte_present(*pte))) {
		folio = page_folio(pte_page(*pte));
		if (likely(!IS_ERR_OR_NULL(folio)) && !(pte_flags(*pte) & _PAGE_RW)) {
			folio = sbpf_mem_copy_on_write(current->sbpf, folio);
			if (unlikely(IS_ERR_OR_NULL(folio))) {
				printk("mbpf: copy on write failed on __iter_pte_create 0x%lx\n",
				       addr);
				return -EINVAL;
			}
			goto done;
		}

		return -EINVAL;
	}

	folio = folio_alloc(GFP_USER | GFP_ATOMIC | __GFP_ZERO, 0);
	if (unlikely(!folio))
		return -ENOMEM;

	folio_set_mbpf(folio);
	folio->page.sbpf_reverse = __sbpf_reverse_init(addr);
	if (unlikely(mem_cgroup_charge(folio, current->mm, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto err;
	}

	entry = mk_pte(&folio->page, PAGE_SHARED_EXEC);
	entry = pte_sw_mkyoung(entry);
	entry = pte_mkwrite(entry);

	atomic_inc(&folio->_mapcount);
	set_pte_at(current->mm, addr, pte, entry);
	tlb_flush_pte_range(current->sbpf->tlb, addr, PAGE_SIZE);
	atomic_inc(&pmd_pgtable(*pmd)->pte_refcount);
	sbpf_reverse_insert_range(folio->page.sbpf_reverse, addr, addr + PAGE_SIZE);

	inc_mm_counter(current->mm, MM_ANONPAGES);

done:
	// TODO. Optimization. If the callback function is NULL, we can skip the kmap_local_page.
	kaddr = kmap_local_page(folio_page(folio, 0));
	ret = callback->callback((u64)kaddr, addr, (u64)callback->callback_ctx, 0, 0);
	kunmap_local(kaddr);

err:
	return ret;
}

BPF_CALL_5(bpf_iter_pte_touch, void *, start_vaddr, u64, len, void *, callback_fn, void *,
	   callback_ctx, u64, flag)
{
	struct sbpf_iter_pte_aux aux = {
		.callback = callback_fn,
		.callback_ctx = callback_ctx,
	};
	u64 ret;

	if (start_vaddr == NULL)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	if ((len / PAGE_SIZE) > BPF_MAX_LOOPS)
		return -E2BIG;

	start_vaddr = (void *)PAGE_ALIGN_DOWN((unsigned long)start_vaddr);

	// Create a new page table entry for the given address range.
	sbpf_mm_lock(current->sbpf->page_fault.sbpf_mm, (unsigned long)start_vaddr);
	if (flag == BPF_SBPF_ITER_FLAG_CREATE) {
		ret = touch_page_table_pte_range(current->mm, (unsigned long)start_vaddr,
						 (unsigned long)start_vaddr + len,
						 __iter_pte_create, &aux);
	} else {
		ret = walk_page_table_pte_range(current->mm, (unsigned long)start_vaddr,
						(unsigned long)start_vaddr + len,
						__iter_pte_none, &aux, true);
	}
	sbpf_mm_unlock(current->sbpf->page_fault.sbpf_mm, (unsigned long)start_vaddr);

	return ret;
}

const struct bpf_func_proto bpf_iter_pte_touch_proto = {
	.func = bpf_iter_pte_touch,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_ANYTHING,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_PTR_TO_FUNC,
	.arg4_type = ARG_PTR_TO_STACK_OR_NULL,
	.arg5_type = ARG_ANYTHING,
};
