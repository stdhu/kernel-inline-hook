#ifndef P_LKRG_GENERIC_PERMISSION_HOOK_H
#define P_LKRG_GENERIC_PERMISSION_HOOK_H

int p_generic_permission_ret(unsigned long ret_addr,hk_regs * regs);
int p_generic_permission_entry(unsigned long ret_addr,hk_regs * regs);
int p_install_generic_permission_hook(int p_is_sys);
void p_uninstall_generic_permission_hook(void);

#endif