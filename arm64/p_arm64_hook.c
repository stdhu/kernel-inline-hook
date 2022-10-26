#include "../p_lkrg_main.h"

#if defined(CONFIG_ARM64)
unsigned char hook_code[]={
    0xE1,0x03,0xBE,0xA9,
    0x40,0x00,0x00,0x58,
    0x00,0x00,0x1F,0xD6,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
};

unsigned char hook_ret_code[]={
    0x49,0x00,0x00,0x58,
    0x20,0x01,0x1F,0xD6,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
};

#define KHOOK_STUB_ARM64_ALL "arm64_stub64_all.inc"
#define KHOOK_STUB_ARM64 "arm64_stub64.inc"

static const char arm64_stub_all_template[] = {
#include KHOOK_STUB_ARM64_ALL
};

static const char arm64_stub_template[] = {
#include KHOOK_STUB_ARM64
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
//resolves the adrp instruction
long get_adrp_target_addr(unsigned long start_addr){
    unsigned long offset=0;
    uint8_t byte_code=0;
    unsigned long target_addr=0;


    byte_code=*(uint8_t*)(offset+start_addr);
    byte_code=(byte_code>>4) & 0xe;
    target_addr+=(unsigned long)byte_code*0x2000;
    
    byte_code=*(uint8_t*)(offset+start_addr+1);
    target_addr+=(unsigned long)byte_code*0x20000;

    byte_code=*(uint8_t*)(offset+start_addr+2);
    target_addr+=(unsigned long)byte_code*0x200000;

    byte_code=*(uint8_t*)(offset+start_addr+3);
    byte_code=(byte_code>>4) & 0xffff;
    target_addr+=((unsigned long)byte_code-9)*0x1000/2+(start_addr&(~0xfff));

    return target_addr;
}

unsigned long get_init_mm_address(void){

    unsigned long symbol_size, offset, pos;
    uint32_t instruction=0;
    unsigned long init_mm_address=0;
    unsigned long start_addr=0;
    uint8_t reg_index=0;

    start_addr=(unsigned long)P_SYM(p_kallsyms_lookup_name)("copy_init_mm");
    if(!start_addr){
        start_addr=(unsigned long)P_SYM(p_kallsyms_lookup_name)("__mmdrop");
        if(!start_addr){
            start_addr=(unsigned long)P_SYM(p_kallsyms_lookup_name)("__pte_alloc_kernel");
            if(!start_addr){
                return 0;
            }
        } 
    }

    pos = P_SYM(p_get_symbol_pos)((unsigned long)start_addr, &symbol_size, &offset);
    if(!pos || offset) return 0;
    //adrp
    while(offset<symbol_size){
        instruction=*(uint32_t*)(offset+start_addr);
        if((instruction & 0x9f000000u)==0x90000000){
            init_mm_address=get_adrp_target_addr(offset+start_addr);
            reg_index=instruction & 0xfu;
            break;
        }
        offset+=4;
    }

    if(!init_mm_address){
        return 0;
    }

    //add
    while(offset<symbol_size){
        instruction=*(uint32_t*)(offset+start_addr);
        if((instruction & 0xff000000u)==0x91000000 && (instruction & 0xfu)==reg_index){
            init_mm_address+=(((instruction>>8) & 0x00ffff) & (~0x3))/4;
            break;
        }
        offset+=4;
    }

    p_print_log("init_mm_address:%lx\n",init_mm_address);
    return init_mm_address;
}
#endif

static inline void arm64_stub_fixup(hook_stub *stub, const void *entry,const void *ret){
	stub->entry_handle=(unsigned long)entry;
    stub->ret_handle=(unsigned long)ret;
    stub->use_count_addr=(unsigned long)&stub->use_count;
}

int inline_hook_install(void *arg)
{
    struct p_hook_struct * p_current_hook_struct=NULL;
	hook_stub * stub=NULL;
    int remain=0;
    int p_ret=-1;

    p_current_hook_struct=(struct p_hook_struct*)arg;
    stub=p_current_hook_struct->stub;

    if(p_current_hook_struct->ret_fn==NULL){
		memcpy(stub,arm64_stub_template,sizeof(arm64_stub_template));
	}else{
		memcpy(stub,arm64_stub_all_template,sizeof(arm64_stub_all_template));
	}

    stub->nbytes=ARM64_HOOK_SIZE;
    arm64_stub_fixup(stub,p_current_hook_struct->entry_fn,p_current_hook_struct->ret_fn);
    *(unsigned long*)&hook_code[12]=(unsigned long)stub->hook;
    *(unsigned long*)&hook_ret_code[8]=(unsigned long)p_current_hook_struct->addr+stub->nbytes;

    memcpy(stub->orig, p_current_hook_struct->addr, stub->nbytes);
    memcpy(stub->orig+stub->nbytes,hook_ret_code,sizeof(hook_ret_code));
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    p_ret = remap_write_range(p_current_hook_struct->addr, hook_code, stub->nbytes, true);
#else
    remain=PAGE_SIZE-(((unsigned long)p_current_hook_struct->addr)%PAGE_SIZE);
    //Double Page
    if(remain<stub->nbytes){
        p_ret=write_ro_memory(p_current_hook_struct->addr,hook_code,remain);
        if(p_ret!=0) return p_ret;
        p_ret=write_ro_memory(p_current_hook_struct->addr+remain,&hook_code[remain],stub->nbytes-remain);
    }else{
        p_ret=write_ro_memory(p_current_hook_struct->addr,hook_code,stub->nbytes);
    }
#endif

    return 0;
}

int inline_hook_uninstall(void *arg)
{
    struct p_hook_struct * p_current_hook_struct=NULL;
	hook_stub * stub=NULL;
    int remain=0;
    int p_ret=-1;

    p_current_hook_struct=(struct p_hook_struct*)arg;
    stub=p_current_hook_struct->stub;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    p_ret = remap_write_range(p_current_hook_struct->addr, stub->orig, stub->nbytes, true);
#else
    remain=PAGE_SIZE-(((unsigned long)p_current_hook_struct->addr)%PAGE_SIZE);
    //Double Page
    if(remain<stub->nbytes){
        p_ret=write_ro_memory(p_current_hook_struct->addr,stub->orig,remain);
        if(p_ret!=0){
            return p_ret;
        }
        p_ret=write_ro_memory(p_current_hook_struct->addr+remain,&stub->orig[remain],stub->nbytes-remain);
    }else{
        p_ret=write_ro_memory(p_current_hook_struct->addr,stub->orig,stub->nbytes);
    }
#endif
    return 0;
}

#endif

