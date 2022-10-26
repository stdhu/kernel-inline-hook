#include "../../p_lkrg_main.h"

char p_generic_permission_hook_state = 0;

static struct p_hook_struct p_generic_permission_hook={
    .entry_fn=p_generic_permission_entry,
    .ret_fn=p_generic_permission_ret,
    .name="generic_permission",
};


int p_generic_permission_entry(unsigned long ret_addr,hk_regs * regs){
    p_print_log("p_generic_permission_entry ret_addr:%lx\n",ret_addr);
    return 0;
}

int p_generic_permission_ret(unsigned long ret_addr,hk_regs * regs){
    p_print_log("p_generic_permission_ret ret_addr:%lx\n",ret_addr);
    return 0;
}

GENERATE_INSTALL_FUNC(generic_permission)