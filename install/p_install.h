#ifndef P_LKRG_INSTALL_HOOK_H
#define P_LKRG_INSTALL_HOOK_H

#include "../hook/p_generic_permission/p_generic_permission.h"

int inline_hook_init(void);

int p_install_hook(struct p_hook_struct * p_current_hook_struct,char* hook_state,int p_is_sys);

void p_uninstall_hook(struct p_hook_struct * p_current_hook_struct,char* hook_state);

#define GENERATE_INSTALL_FUNC(name)                                                       \
	int p_install_##name##_hook(int p_is_sys){	\
		return	p_install_hook(&p_##name##_hook,&p_##name##_hook_state,p_is_sys);	\
	}																				\
																					\
	void p_uninstall_##name##_hook(void){											\
		p_uninstall_hook(&p_##name##_hook,&p_##name##_hook_state);			\
	}		             

#endif