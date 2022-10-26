#ifndef P_LKRG_MEMORY_H
#define P_LKRG_MEMORY_H

#if defined(CONFIG_X86_64)
#define kernel_write_enter() asm volatile (	\
	"cli\n\t"				\
	"mov %%cr0, %%rax\n\t"			\
	"and $0xfffffffffffeffff, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	::: "%rax" )

#define kernel_write_leave() asm volatile (	\
	"mov %%cr0, %%rax\n\t"			\
	"or $0x0000000000010000, %%rax\n\t"	\
	"mov %%rax, %%cr0\n\t"			\
	"sti\n\t"				\
	::: "%rax" )

#elif defined(CONFIG_X86)
#define kernel_write_enter() asm volatile (	\
	"cli\n\t"				\
	"mov %%cr0, %%eax\n\t"			\
	"and $0xfffeffff, %%eax\n\t"	\
	"mov %%eax, %%cr0\n\t"			\
	::: "%eax" )

#define kernel_write_leave() asm volatile (	\
	"mov %%cr0, %%eax\n\t"			\
	"or $0x00010000, %%eax\n\t"	\
	"mov %%eax, %%cr0\n\t"			\
	"sti\n\t"				\
	::: "%eax" )
#endif

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
long write_ro_memory(void *addr,void *source,int size);
#else
int remap_write_range(void *target, void *source, int size, bool operate_on_kernel);
#endif
int set_allocate_memory_x(unsigned long addr, int numpages);
#endif


#endif