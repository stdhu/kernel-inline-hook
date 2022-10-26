#ifndef P_LKRG_ARM_HOOK_H
#define P_LKRG_ARM_HOOK_H

#if defined(CONFIG_ARM)

int inline_hook_install(void *arg);

int inline_hook_uninstall(void *arg);

unsigned long get_init_mm_address(void);

#endif

#endif