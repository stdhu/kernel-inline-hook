#include "../p_lkrg_main.h"

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#define pmd_huge(pmd) (pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT))

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
int init_kernel_text(unsigned long addr)
{   
    if(!P_SYM(p_sinittext) || !P_SYM(p_einittext)){
        return 0;
    }

	if (addr >= (unsigned long)P_SYM(p_sinittext) &&
	    addr < (unsigned long)P_SYM(p_einittext))
		return 1;
	return 0;
}

int core_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)P_SYM(p_stext) &&
	    addr < (unsigned long)P_SYM(p_etext))
		return 1;

	if (system_state < SYSTEM_RUNNING &&
	    init_kernel_text(addr))
		return 1;
	return 0;
}

int remap_write_range(void *target, void *source, int size, bool operate_on_kernel)
{
    struct page *page = NULL;
    void *new_target = NULL;

    if ((((unsigned long)target + size) ^ (unsigned long)target) & PAGE_MASK) {
        p_print_log("Try to write word across page boundary %p\n", target);
        return -EFAULT;
    }

    if (operate_on_kernel && !core_kernel_text((unsigned long)target)) {
        p_print_log("Try to write to non kernel address %p\n", target);
        return -EFAULT;
    }
    
    if (operate_on_kernel) {
        page = phys_to_page(__pa(target));
    } else {
        page = vmalloc_to_page(target);
    }
    
    if (!page) {
        p_print_log("Cannot get page of address %p\n", target);
        return -EFAULT;
    }

    new_target = vm_map_ram(&page, 1, -1,PAGE_KERNEL_EXEC);
    
    if (!new_target) {
        p_print_log("Remap address %p failed\n", target);
        return -EFAULT;
    } else {
        memcpy(new_target + ((unsigned long)target & (~ PAGE_MASK)), source, size);
        vm_unmap_ram(new_target, 1);
        flush_icache_range((unsigned long)target, (unsigned long)target + size);
        
        return 0;
    }
    return 0;
}
#else
static pte_t * get_pte(unsigned long addr)
{
    //linux page
    pgd_t *pgdp = NULL;
#if defined(CONFIG_ARM64)
    p4d_t *p4dp = NULL;
#endif
	pud_t *pudp = NULL;
	pmd_t *pmdp = NULL;
    pte_t *ptep = NULL;
    struct mm_struct init_mm;

    init_mm=*P_SYM(p_init_mm);

    pgdp = pgd_offset_k(addr);
    if (pgd_none(*pgdp)) {
		p_print_log("failed get pgdp for %p\n", (void *)addr);
		return NULL;
	}

#if defined(CONFIG_ARM64)
    p4dp = p4d_offset(pgdp,addr);
    if (p4d_none(*p4dp)) {
		p_print_log("failed get pd4 for %p\n", (void *)addr);
		return NULL;
	}
    pudp = pud_offset((p4d_t *)p4dp,addr);
#else
    pudp = pud_offset((pgd_t *)pgdp,addr);
#endif
	if (pud_none(*pudp)) {
        p_print_log("failed get pudp for %p\n", (void *)addr);
		return NULL;
	}

    pmdp = pmd_offset(pudp, addr);
	if (pmd_none(*pmdp)) {
		p_print_log("failed get pmdp for %p\n", (void *)addr);
		return NULL;
	}

#if defined(CONFIG_ARM64)
    //2MB
    if(pmd_huge(*pmdp)){
        if(!pte_valid(*(pte_t*)pmdp)){
            p_print_log("failed get pte for %p\n", (void *)addr);
            return NULL;
        }
        return (pte_t*)pmdp;
    }

    ptep = pte_offset_kernel(pmdp, addr);
	if (!pte_valid(*ptep)) {
		p_print_log("failed get pte for %p\n", (void *)addr);
		return NULL;
	}
#else
    if(pmd_large(*pmdp)){
        return (pte_t*)pmdp;
    }

    ptep = pte_offset_kernel(pmdp, addr);
#endif
    return ptep;
}

static inline void set_pte_aatt(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte)
{
	pte_t old_pte;
#if defined(CONFIG_ARM64)
	if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
		P_SYM(p_sync_icache_dcache)(pte);

	old_pte = (*ptep);

	set_pte(ptep, pte);
#else
    if (addr< TASK_SIZE && pte_valid_user(pte) && !pte_special(pte))
		P_SYM(p_sync_icache_dcache)(pte);

	old_pte = (*ptep);

	set_pte_ext(ptep, pte,0);
#endif
}

long write_ro_memory(void *addr,void *source,int size)
{
    pte_t origin_pte, pte, *ptep = NULL;
    uint32_t tmp=0;

    memcpy(&tmp,addr,4);
    ptep = get_pte((unsigned long)addr);
    if (!ptep){
        return -1;
    }
    origin_pte = (pte = *ptep);

#if defined(CONFIG_ARM64)
    pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));
	pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
#else
    pte = clear_pte_bit(pte, __pgprot(L_PTE_RDONLY));
	pte = set_pte_bit(pte, __pgprot(0));
#endif
    set_pte_aatt(P_SYM(p_init_mm), (unsigned long)addr, ptep, pte);
    
    memcpy(addr, source, size);

    set_pte_aatt(P_SYM(p_init_mm), (unsigned long)addr, ptep, origin_pte);
    
    return 0;
}
#endif
#endif

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

#if LINUX_VERSION_CODE>=KERNEL_VERSION(5, 3, 0)
static int change_allocate_page_range(pte_t *ptep,unsigned long addr, void *data)
{   
	struct page_change_data *cdata = (struct page_change_data *)data;
    pte_t pte = READ_ONCE(*ptep);
	pte = clear_pte_bit(pte,cdata->clear_mask);
    pte = set_pte_bit(pte,cdata->set_mask);
#if defined(CONFIG_ARM)
    set_pte_ext(ptep, pte, 0);
#elif defined(CONFIG_ARM64)
    set_pte(ptep,pte);
#endif
    return 0;
}
#else
static int change_allocate_page_range(pte_t *ptep, pgtable_t token, unsigned long addr, void *data)
{   
	struct page_change_data *cdata = (struct page_change_data *)data;
    pte_t pte = READ_ONCE(*ptep);
	pte = clear_pte_bit(pte,cdata->clear_mask);
    pte = set_pte_bit(pte,cdata->set_mask);
#if defined(CONFIG_ARM)
    set_pte_ext(ptep, pte, 0);
#elif defined(CONFIG_ARM64)
    set_pte(ptep,pte);
#endif
    
    return 0;
}
#endif


static int change_allocate_memory_common(unsigned long addr, int numpages, pgprot_t set_mask, pgprot_t clear_mask)
{
	unsigned long start = addr & PAGE_MASK;
	unsigned long end = PAGE_ALIGN(addr) + numpages * PAGE_SIZE;
	unsigned long size = end - start;
	struct page_change_data data;
	int ret;
	if (!size)
		return 0;

    if(!P_SYM(p_init_mm)){
        P_SYM(p_init_mm)=(struct mm_struct *)get_init_mm_address();
        if(!P_SYM(p_init_mm)) return -1;
    }

    if(!P_SYM(p_flush_tlb_kernel_range)){
        P_SYM(p_flush_tlb_kernel_range)=(void*)P_SYM(p_kallsyms_lookup_name)("flush_tlb_kernel_range");
        if(!P_SYM(p_flush_tlb_kernel_range)) return -1;
    }

    if(!P_SYM(p_apply_to_page_range)){
        P_SYM(p_apply_to_page_range)=(void*)P_SYM(p_kallsyms_lookup_name)("apply_to_page_range");
        if(!P_SYM(p_apply_to_page_range)) return -1;
    }

	data.set_mask = set_mask;
	data.clear_mask = clear_mask;
	ret = P_SYM(p_apply_to_page_range)(P_SYM(p_init_mm), start, size, change_allocate_page_range, &data);

    P_SYM(p_flush_tlb_kernel_range)(start,end);

	return ret;
}

int set_allocate_memory_x(unsigned long addr, int numpages)
{
#if defined(CONFIG_ARM)
    return change_allocate_memory_common(addr, numpages,__pgprot(0),__pgprot(L_PTE_XN));
#elif LINUX_VERSION_CODE>=KERNEL_VERSION(5, 8, 0) && defined(CONFIG_ARM64)
    return change_allocate_memory_common(addr, numpages,__pgprot(PTE_MAYBE_GP),__pgprot(PTE_PXN));
#elif LINUX_VERSION_CODE<KERNEL_VERSION(5, 8, 0) && defined(CONFIG_ARM64)
    return change_allocate_memory_common(addr, numpages,__pgprot(0),__pgprot(PTE_PXN));
#endif
}
#endif