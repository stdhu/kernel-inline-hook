#ifndef P_LKRG_X86_HOOK_H
#define P_LKRG_X86_HOOK_H

#if defined(CONFIG_X86)

int inline_hook_install(void *arg);

int inline_hook_uninstall(void *arg);

#endif

#endif