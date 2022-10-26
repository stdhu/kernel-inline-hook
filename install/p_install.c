#include "../p_lkrg_main.h"

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
bool check_function_length_enough(void *target)
{
    unsigned long symbolsize, offset;
    unsigned long pos;
    
    pos = P_SYM(p_get_symbol_pos)((unsigned long)target, &symbolsize, &offset);
#if defined(CONFIG_ARM)
    if (pos && !offset && symbolsize >= ARM_HOOK_SIZE) {
        return true;
    } else {
        return false;
    }
#elif defined(CONFIG_ARM64)
	if (pos && !offset && symbolsize >= ARM64_HOOK_SIZE) {
        return true;
    } else {
        return false;
    }
#endif
}
#endif

static void wakeup_process(void)
{
	struct task_struct *p;
	rcu_read_lock();
	for_each_process(p) {
		wake_up_process(p);
	}
	rcu_read_unlock();
}

unsigned long * get_sys_call_table(void){
	unsigned long* p_etext = NULL;
    unsigned long* p_init_begin = NULL;

#if defined(CONFIG_ARM64)
	unsigned long** syscall_table = NULL;
    unsigned long* p_arm64_sys_close = NULL;
    unsigned long* p_arm64_sys_read = NULL;
	unsigned long i;
#elif defined(CONFIG_ARM)
	unsigned long** syscall_table = NULL;
    unsigned long* p_arm_sys_close = NULL;
    unsigned long* p_arm_sys_read = NULL;
	unsigned long i;
#elif defined(CONFIG_X86_64)
	unsigned long** syscall_table = NULL;
	unsigned long* p_x64_sys_close=NULL;
	unsigned long* p_x64_sys_read=NULL;
	unsigned long i;
#elif defined(CONFIG_X86_32)
	unsigned long** syscall_table = NULL;
	unsigned long* p_x32_sys_close=NULL;
	unsigned long* p_x32_sys_read=NULL;
	unsigned long i;
#endif

	p_etext = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("_etext");
    if(!p_etext) return NULL;
	
	p_init_begin = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__init_begin");
	if(!p_init_begin) return NULL;
	//search sys_call_table address
#if defined(CONFIG_ARM64)
	p_arm64_sys_close = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__arm64_sys_close");
	if(!p_arm64_sys_close) return NULL;

	p_arm64_sys_read = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__arm64_sys_read");
	if(!p_arm64_sys_read) return NULL;

	for(i = (unsigned long)p_etext;i < (unsigned long)p_init_begin;i += sizeof(void*)){
		syscall_table = (unsigned long**)i;
		if((syscall_table[__NR_close] == (unsigned long*)p_arm64_sys_close) && (syscall_table[__NR_read] == (unsigned long*)p_arm64_sys_read)){
            return (unsigned long *)syscall_table;
        }
	}
#elif defined(CONFIG_ARM)
	p_arm_sys_close = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("sys_close");
	if(!p_arm_sys_close) return NULL;

	p_arm_sys_read = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("sys_read");
	if(!p_arm_sys_read) return NULL;

	for(i = (unsigned long)p_etext;i < (unsigned long)p_init_begin;i += sizeof(void*)){
		syscall_table = (unsigned long**)i;
		if((syscall_table[__NR_close] == (unsigned long*)p_arm_sys_close) && (syscall_table[__NR_read] == (unsigned long*)p_arm_sys_close)){
            return (unsigned long *)syscall_table;
        }
	}
#elif defined(CONFIG_X86_64)
	p_x64_sys_close = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__x64_sys_close");
	if(!p_x64_sys_close) return NULL;

	p_x64_sys_read = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__x64_sys_read");
	if(!p_x64_sys_read) return NULL;

	for(i = (unsigned long)p_etext;i < (unsigned long)p_init_begin;i+=sizeof(void*)){
		syscall_table = (unsigned long**)i;
		if((syscall_table[__NR_close] == (unsigned long*)p_x64_sys_close) && (syscall_table[__NR_read] == (unsigned long*)p_x64_sys_read)){
            return (unsigned long *)syscall_table;
        }
	}
#elif defined(CONFIG_X86_32)
	p_x32_sys_close = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__ia32_sys_close");
	if(!p_x32_sys_close) return NULL;

	p_x32_sys_read = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("__ia32_sys_read");
	if(!p_x32_sys_read) return NULL;

	for(i = (unsigned long)p_etext;i < (unsigned long)p_init_begin;i+=sizeof(void*)){
		syscall_table = (unsigned long**)i;
		if((syscall_table[__NR_close] == (unsigned long*)p_x32_sys_close) && (syscall_table[__NR_read] == (unsigned long*)p_x32_sys_read)){
            return (unsigned long *)syscall_table;
        }
	}
#endif
	return NULL;
}

int inline_hook_init(void){

#if defined(CONFIG_X86)
	P_SYM(p_insn_init)=(void*)P_SYM(p_kallsyms_lookup_name)("insn_init");
	if(!P_SYM(p_insn_init)){
		p_print_log("insn_init addr get failed\n");
		return -1;
	}

	P_SYM(p_insn_get_length)=(void*)P_SYM(p_kallsyms_lookup_name)("insn_get_length");
	if(!P_SYM(p_insn_get_length)){
		p_print_log("insn_get_length get failed\n");
		return -1;
	}

    P_SYM(p_flush_tlb_all)=(void*)P_SYM(p_kallsyms_lookup_name)("flush_tlb_all");
	if(!P_SYM(p_flush_tlb_all)){
		p_print_log("flush_tlb_all addr get failed\n");
	}
#endif

#if defined(CONFIG_ARM64) || defined(CONFIG_ARM)
    P_SYM(p_get_symbol_pos)=(unsigned long (*)(unsigned long, unsigned long *, unsigned long *))P_SYM(p_kallsyms_lookup_name)("get_symbol_pos");
    if(!P_SYM(p_get_symbol_pos)){
        p_print_log("p_get_symbol_pos get failed\n");
        return -1;
    }

    P_SYM(p_stext)=(void*)P_SYM(p_kallsyms_lookup_name)("_stext");
    if(!P_SYM(p_stext)){
        p_print_log("p_stext get failed\n");
        return -1;
    }

    P_SYM(p_etext)=(void*)P_SYM(p_kallsyms_lookup_name)("_etext");
    if(!P_SYM(p_etext)){
        p_print_log("p_etext get failed\n");
        return -1;
    }

    P_SYM(p_sinittext)=(void*)P_SYM(p_kallsyms_lookup_name)("_sinittext");
    if(!P_SYM(p_sinittext)){
        p_print_log("p_sinittext get failed (skipping it)\n");
    }

    P_SYM(p_einittext)=(void*)P_SYM(p_kallsyms_lookup_name)("_einittext");
    if(!P_SYM(p_einittext)){
        p_print_log("p_einittext get failed (skipping it)\n");
    }

	P_SYM(p_init_mm)=(struct mm_struct *)P_SYM(p_kallsyms_lookup_name)("init_mm");
    if(!P_SYM(p_init_mm)){
        P_SYM(p_init_mm)=(struct mm_struct*)get_init_mm_address();
        if(!P_SYM(p_init_mm)){
            p_print_log("init_mm get failed\n");
			return -1;
        }
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	P_SYM(p_sync_icache_dcache)=(void (*)(pte_t))P_SYM(p_kallsyms_lookup_name)("__sync_icache_dcache");
    if(!P_SYM(p_sync_icache_dcache)){
        p_print_log("p_sync_icache_dcache get failed\n");
        return -1;
    }
#endif
#endif
	P_SYM(p_module_alloc)=(void*)P_SYM(p_kallsyms_lookup_name)("module_alloc");
	if(!P_SYM(p_module_alloc)){
		p_print_log("module_alloc addr get failed\n");
		return -1;
	}

	P_SYM(p_set_memory_x)=(void*)P_SYM(p_kallsyms_lookup_name)("set_memory_x");
	if(!P_SYM(p_set_memory_x)){
#if defined(CONFIG_X86)
		p_print_log("get set_memory_x addr failed\n");
		return -1;
#elif defined(CONFIG_ARM) || defined(CONFIG_ARM64)
		p_print_log("get set_memory_x addr (skipping it)\n");
#endif
	}

    P_SYM(p_sys_call_table)=(unsigned long *)P_SYM(p_kallsyms_lookup_name)("sys_call_table");
    if(!P_SYM(p_sys_call_table)){
		P_SYM(p_sys_call_table)=get_sys_call_table();
        if(!P_SYM(p_sys_call_table)){
            p_print_log("can not hook sys functions\n");
        }
    }

	return 0;
}

int p_install_hook(struct p_hook_struct * p_current_hook_struct,char* p_current_hook_state,int p_is_sys){
	int p_ret=-1;
	hook_stub * stub;
	int numpages;

	if((*p_current_hook_state)==true || strlen(p_current_hook_struct->name)==0) return 0;

	p_current_hook_struct->addr=(char*)P_SYM(p_kallsyms_lookup_name)(p_current_hook_struct->name);
	if(!p_current_hook_struct->addr){
		if(p_is_sys){
			unsigned long *p_sys_call_table=(unsigned long *)P_SYM(p_kallsyms_lookup_name)("sys_call_table");
			if(!p_sys_call_table){
				p_print_log("%s hook failed\n",p_current_hook_struct->name);
				return -1;
			}
			p_current_hook_struct->addr=(void *)p_sys_call_table[p_current_hook_struct->sys_call_number];
		}else{
			p_print_log("%s hook failed\n",p_current_hook_struct->name);
			return -1;
		}
	}
#if defined(CONFIG_ARM64) || defined(CONFIG_ARM)
    if(!check_function_length_enough(p_current_hook_struct->addr) || !check_target_can_hook(p_current_hook_struct->addr)){
        p_print_log("[%s] can not hook\n",p_current_hook_struct->name);
        return -1;
    }
#endif
	stub=P_SYM(p_module_alloc)(sizeof(hook_stub));
	if(!stub){
		p_print_log("%s module_alloc failed\n",p_current_hook_struct->name);
		return -1;
	}
	
	memset(stub, 0, sizeof(hook_stub));
    numpages = round_up(sizeof(hook_stub), PAGE_SIZE) / PAGE_SIZE;
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	if(P_SYM(p_set_memory_x)){
		P_SYM(p_set_memory_x)((unsigned long)stub,numpages);
	}else{
		set_allocate_memory_x((unsigned long)stub,numpages);
	}
#elif defined(CONFIG_X86)
	P_SYM(p_set_memory_x)((unsigned long)stub,numpages);
#endif

#if defined(CONFIG_X86)
	if(P_SYM(p_flush_tlb_all)){
		P_SYM(p_flush_tlb_all)();
	}
#endif
	p_current_hook_struct->stub=stub;
	p_ret=stop_machine(inline_hook_install,p_current_hook_struct,0);
	if(!p_ret){
		(*p_current_hook_state)=1;
		p_print_log("%s addr:%lx hook addr:%lx\n",p_current_hook_struct->name,(unsigned long)p_current_hook_struct->addr,(unsigned long)stub);
		p_print_log("%s hook success\n",p_current_hook_struct->name);
	}
	
	return p_ret;
}	

void p_uninstall_hook(struct p_hook_struct * p_current_hook_struct,char* hook_state){
	hook_stub * stub=p_current_hook_struct->stub;
	if((*hook_state)!=true || stub==NULL){
		return;
	}

	stop_machine(inline_hook_uninstall, p_current_hook_struct, 0);
	
	while (atomic_read(&stub->use_count) > 0) {
		wakeup_process();
		msleep_interruptible(500);
		p_print_log("waiting for %s...\n", p_current_hook_struct->name);
	}

	msleep_interruptible(300);
	vfree(stub);
	(*hook_state)=0;
	p_print_log("uninstall %s success\n",p_current_hook_struct->name);
}