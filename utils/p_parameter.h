#ifndef P_LKRG_PARAMETER_H
#define P_LKRG_PARAMETER_H

#define ARM64_ADD_STACK 0x110
#define ARM_ADD_STACK 0x4
#define THUMB_ADD_STACK 0x48

#ifdef CONFIG_X86
#if defined(CONFIG_X86_64)
static inline unsigned long p_inline_regs_get_arg1(hk_regs *p_regs) {
   return p_regs->di;
}

static inline unsigned long p_inline_regs_get_arg2(hk_regs *p_regs) {
   return p_regs->si;
}

static inline unsigned long p_inline_regs_get_arg3(hk_regs *p_regs){
   return p_regs->dx;
}

static inline unsigned long p_inline_regs_get_ret(hk_regs *p_regs) {
   return p_regs->ax;
}

static inline unsigned long p_inline_regs_get_fp(hk_regs *p_regs) {
   return p_regs->bp;
}

static inline unsigned long p_inline_regs_get_sp(hk_regs *p_regs) {
   return p_regs->sp;
}

static inline unsigned long p_inline_syscall_get_arg1(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg1((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg1(p_regs);
#endif
}

static inline unsigned long p_inline_syscall_get_arg2(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg2(p_regs);
#endif
}

//self hook regs
static inline void p_inline_regs_set_arg1(hk_regs *p_regs, unsigned long p_val) {
   p_regs->ax = p_val;
}

static inline void p_inline_regs_set_arg2(hk_regs *p_regs, unsigned long p_val) {
   p_regs->dx = p_val;
}

static inline void p_inline_regs_set_arg3(hk_regs *p_regs, unsigned long p_val) {
   p_regs->cx =p_val;
}

static inline void p_inline_syscall_set_arg1(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg1((hk_regs *)p_inline_regs_get_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg1(p_regs,p_val);
#endif
}

static inline void p_inline_syscall_set_arg2(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg2(p_regs,p_val);
#endif
}

#else
//self hook args
static inline unsigned long p_inline_regs_get_arg1(hk_regs *p_regs) {
   return p_regs->ax; 
}

static inline unsigned long p_inline_regs_get_arg2(hk_regs *p_regs) {
   return p_regs->dx;
}

static inline unsigned long p_inline_regs_get_arg3(hk_regs *p_regs){
   return p_regs->cx;
}

static inline unsigned long p_inline_regs_get_ret(hk_regs *p_regs) {
   return p_regs->ax;
}

static inline unsigned long p_inline_regs_get_fp(hk_regs *p_regs) {
   return p_regs->bp;
}

static inline unsigned long p_inline_regs_get_sp(hk_regs *p_regs) {
   return p_regs->sp;
}

static inline unsigned long p_inline_syscall_get_arg1(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg2(p_regs);
#endif
}

static inline unsigned long p_inline_syscall_get_arg2(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg3((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg3(p_regs);
#endif
}

//self hook regs
static inline void p_inline_regs_set_arg1(hk_regs *p_regs, unsigned long p_val) {
   p_regs->ax=p_val;  
}

static inline void p_inline_regs_set_arg2(hk_regs *p_regs, unsigned long p_val) {
   p_regs->dx=p_val;
}

static inline void p_inline_regs_set_arg3(hk_regs *p_regs, unsigned long p_val) {
   p_regs->cx=p_val;
}

static inline void p_inline_syscall_set_arg1(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg2(p_regs,p_val);
#endif
}

static inline void p_inline_syscall_set_arg2(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg3((hk_regs *)p_inline_regs_get_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg3(p_regs,p_val);
#endif
}
#endif
#endif
#elif defined(CONFIG_ARM)
//self hook args
static inline unsigned long p_inline_regs_get_arg1(hk_regs *p_regs) {
   return p_regs->ARM_r0;
}

static inline unsigned long p_inline_regs_get_arg2(hk_regs *p_regs) {
   return p_regs->ARM_r1;
}

static inline unsigned long p_inline_regs_get_arg3(hk_regs *p_regs){
   return p_regs->ARM_r2;
}

static inline unsigned long p_inline_regs_get_arg4(hk_regs *p_regs){
   return p_regs->ARM_r3;
}

static inline unsigned long p_inline_regs_get_ret(hk_regs *p_regs) {
   return p_regs->ARM_r0;
}

static inline unsigned long p_inline_regs_get_fp(hk_regs *p_regs) {
   return p_regs->ARM_fp;
}

static inline unsigned long p_inline_regs_get_sp(hk_regs *p_regs) {
#if defined( CONFIG_THUMB2_KERNEL)
   return (unsigned long)p_regs+THUMB_ADD_STACK //0x48是通过shellcode计算得来
#else
   return (unsigned long)p_regs->ARM_sp+ARM_ADD_STACK; //0x4是通过shellcode计算得来
#endif   
}

static inline unsigned long p_inline_syscall_get_arg1(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg1((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg1(p_regs);
#endif
}

static inline unsigned long p_inline_syscall_get_arg2(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg2(p_regs);
#endif
}

static inline void p_inline_regs_set_arg2(hk_regs *p_regs, unsigned long p_val) {
   p_regs->ARM_r1 = p_val;
}

static inline void p_inline_regs_set_ip(hk_regs *p_regs, unsigned long p_val) {
   p_regs->ARM_pc = p_val;
}

static inline void p_inline_syscall_set_arg1(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg1((hk_regs *)p_inline_regs_set_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg1(p_regs,p_val);
#endif
}

static inline void p_inline_syscall_set_arg2(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg2(p_regs,p_val);
#endif
}

#elif defined(CONFIG_ARM64)
//self hook args
static inline unsigned long p_inline_regs_get_arg1(hk_regs *p_regs) {
   return p_regs->regs[0];
}

static inline unsigned long p_inline_regs_get_arg2(hk_regs *p_regs) {
   return p_regs->regs[1];
}

static inline unsigned long p_inline_regs_get_arg3(hk_regs *p_regs){
   return p_regs->regs[2];
}

static inline unsigned long p_inline_regs_get_arg4(hk_regs *p_regs){
   return p_regs->regs[3];
}

static inline unsigned long p_inline_regs_get_ret(hk_regs *p_regs) {
   return p_regs->regs[0];
}

static inline unsigned long p_inline_regs_get_fp(hk_regs *p_regs) {
   return p_regs->regs[29];
}

static inline unsigned long p_inline_regs_get_sp(hk_regs *p_regs) {
   return (unsigned long)p_regs+ARM64_ADD_STACK;
}

static inline unsigned long p_inline_syscall_get_arg1(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg1((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg1(p_regs);
#endif
}

static inline unsigned long p_inline_syscall_get_arg2(hk_regs *p_regs) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   return p_inline_regs_get_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs));
#else
   return p_inline_regs_get_arg2(p_regs);
#endif
}

//self hook regs
static inline void p_inline_regs_set_arg1(hk_regs *p_regs, unsigned long p_val) {
   p_regs->regs[0]=p_val;
}

static inline void p_inline_regs_set_arg2(hk_regs *p_regs, unsigned long p_val) {
   p_regs->regs[1]=p_val;
}

static inline void p_inline_regs_set_arg3(hk_regs *p_regs, unsigned long p_val) {
   p_regs->regs[2]=p_val;
}

static inline void p_inline_syscall_set_arg1(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg1((hk_regs *)p_inline_regs_get_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg1(p_regs,p_val);
#endif
}

static inline void p_inline_syscall_set_arg2(hk_regs *p_regs,unsigned long p_val) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
   p_inline_regs_set_arg2((hk_regs *)p_inline_regs_get_arg1(p_regs),p_val);
#else
   p_inline_regs_set_arg2(p_regs,p_val);
#endif
}
#endif