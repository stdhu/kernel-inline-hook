#ifndef P_LKRG_MAIN_H
#define P_LKRG_MAIN_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/stop_machine.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/stacktrace.h>
#include <asm/cacheflush.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#if defined(CONFIG_X86)
#include <asm/insn.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
# define stop_machine stop_machine
#else
# define stop_machine stop_machine_run
#endif

#if !defined(CONFIG_KALLSYMS)
 #error INLINE_HOOK_ENGINE NEED CONFIG_KALLSYMS 
#endif

#define P_LKRG_SIGNATURE "[INLINE_HOOK_ENGINE] "

#define p_print_log(p_fmt, p_args...) \
({                                	   \
   printk(KERN_INFO P_LKRG_SIGNATURE p_fmt, ## p_args);           \
})

#if defined(CONFIG_X86_64)
typedef struct _p_regs{
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long bx;
	unsigned long sp;
	unsigned long bp;
	unsigned long si;
	unsigned long di;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
}hk_regs;
#elif defined(CONFIG_X86)
typedef struct _p_regs{
	unsigned long di;
	unsigned long si;
	unsigned long bp;
	unsigned long sp;
	unsigned long bx;
	unsigned long dx;
	unsigned long cx;
	unsigned long ax;
}hk_regs;
#elif defined(CONFIG_ARM64)
typedef struct _p_regs{
	unsigned long regs[31];
}hk_regs;
#elif defined(CONFIG_ARM)
typedef struct _p_rets{
	long uregs[15];
}hk_regs;
#endif

#if defined(CONFIG_X86_64)
typedef struct {
#pragma pack(push, 1)
	union {
		unsigned char _0x00_[ 0x10 ];
		atomic_t use_count;
	};
	union {
		unsigned char _0x10_[ 0x40 ];
		unsigned char orig[0];
	};
	union {
		unsigned char _0x50_[ 0x100 ]; 
		unsigned char hook[0];
	};
#pragma pack(pop)
	unsigned nbytes;
}hook_stub;
#elif defined(CONFIG_X86)
typedef struct {
#pragma pack(push, 1)
	union {
		unsigned char _0x00_[ 0x10 ];
		atomic_t use_count;
	};
	union {
		unsigned char _0x10_[ 0x30 ];
		unsigned char orig[0];
	};
	union {
		unsigned char _0x40_[ 0x50 ];
		unsigned char hook[0];
	};
#pragma pack(pop)
	unsigned nbytes;
}hook_stub;

#elif defined(CONFIG_ARM64)
typedef struct {
#pragma pack(push, 1)
	union {
		unsigned char _0x00_[ 0x10 ];
		atomic_t use_count;
	};
	union {
		unsigned char _0x10_[ 0x28 ];
		unsigned char orig[0];
	};

	unsigned long use_count_addr;

	unsigned long entry_handle;
	
	unsigned long ret_handle;

	union {
		unsigned char _0x50_[ 0x190 ];
		unsigned char hook[0];
	};
#pragma pack(pop)
	unsigned nbytes;
}hook_stub;
#elif defined(CONFIG_ARM)
typedef struct {
#pragma pack(push, 1)
	union {
		unsigned char _0x00_[ 0x10 ];
		atomic_t use_count;
	};
	union {
		unsigned char _0x10_[ 0x34 ];
		unsigned char orig[0];
	};

	unsigned int use_count_addr;

	unsigned int entry_handle;
	
	unsigned int ret_handle;

	union {
		unsigned char _0x30_[ 0xc0 ];
		unsigned char hook[0];
	};
#pragma pack(pop)
	unsigned nbytes;
}hook_stub;


#endif

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
struct p_hook_struct{
#pragma pack(push, 1)
	void	*entry_fn;
	void 	*ret_fn;	
	const char	*name;		
	char		*addr;
	unsigned long	sys_call_number;
	hook_stub * stub;
	char is_fix;
	int ori_offset;
	bool is_sys_call;
#pragma pack(pop)   
};
#else
struct p_hook_struct{
#pragma pack(push, 1)
	void	*entry_fn;
	void 	*ret_fn;
	const char	*name;
	char		*addr;
	unsigned long	sys_call_number;
	hook_stub * stub;
#pragma pack(pop)
};
#endif

typedef struct _p_lkrg_global_symbols_structure
{
	unsigned long (*p_kallsyms_lookup_name)(const char *name);
    void *(*p_module_alloc)(long size);
    int (*p_set_memory_x)(unsigned long, int);
#if defined(CONFIG_X86)
    typeof(insn_init) *p_insn_init;
	typeof(insn_get_length) *p_insn_get_length;
	void (*p_flush_tlb_all)(void);
#endif

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	unsigned long (*p_get_symbol_pos)(unsigned long, unsigned long *, unsigned long *);
	void (*p_flush_tlb_kernel_range)(unsigned long start, unsigned long end);
	int (*p_apply_to_page_range)(struct mm_struct *mm, unsigned long addr,unsigned long size, pte_fn_t fn, void *data);
	void (*p_sync_icache_dcache)(pte_t);

	void * p_stext;
	void * p_etext;
	void * p_sinittext;
	void * p_einittext;
	struct mm_struct * p_init_mm;
#endif
	unsigned long * p_sys_call_table;

}p_lkrg_global_symbols;

#if defined(CONFIG_X86)
#include "x86/p_x86_hook.h"
#elif defined(CONFIG_ARM64)
#include "arm64/p_arm64_hook.h"
#include "arm64/p_arm64_check.h"
#elif defined(CONFIG_ARM)
#include "arm32/p_arm32_hook.h"
#include "arm32/p_arm32_check.h"
#endif

#include "install/p_install.h"
#include "utils/p_memory.h"
#include "utils/p_parameter.h"

extern p_lkrg_global_symbols p_global_symbols;

#define P_SYM(p_field) p_global_symbols.p_field

#endif