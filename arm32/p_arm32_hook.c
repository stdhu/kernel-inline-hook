#include "../p_lkrg_main.h"

#if defined(CONFIG_ARM)
unsigned char arm_hook_code[]={
    0x04,0xF0,0x1F,0xE5,
    0x00,0x00,0x00,0x00
};

unsigned char arm_hook_ret_code[]={
    0x04,0xF0,0x1F,0xE5,
    0x00,0x00,0x00,0x00
};

unsigned char arm_fix_parameters_limit_code[]={
    0x10,0xd0,0x4d,0xe2,
    0x3f,0x00,0x2d,0xe9,
    0x18,0x00,0x8d,0xe2,
    0x2c,0x10,0x8d,0xe2,
    0x3c,0x00,0xb1,0xe8,
    0x3c,0x00,0xa0,0xe8,
    0x3f,0x00,0xbd,0xe8
};

unsigned char thumb_fix_parameters_limit_code[]={
    0x84,0xb0,
    0x3f,0xb4,
    0x06,0xa8,
    0x0b,0xa9,
    0x3c,0xc9,
    0x3c,0xc0,
    0x3f,0xbc
};

//thumb模式
unsigned char thumb_hook_code[]={
    0x5F,0xF8,0x04,0xF0,
    0x00,0x00,0x00,0x00
};

unsigned char thumb_hook_ret_code[]={
    0x5F,0xF8,0x04,0xF0,
    0x00,0x00,0x00,0x00
};

#define KHOOK_STUB_ARM_ALL "arm32_stub_all.inc"
#define KHOOK_STUB_ARM "arm32_stub.inc"
#define hook_stubHUMB_ALL "thumb_stub_all.inc"
#define hook_stubHUMB "thumb_stub.inc"

static const char arm_stub_all_template[] = {
#include KHOOK_STUB_ARM_ALL
};

static const char arm_stub_template[] = {
#include KHOOK_STUB_ARM
};

static const char thumb_stub_all_template[]={
#include hook_stubHUMB_ALL
};

static const char thumb_stub_template[]={
#include hook_stubHUMB
};


unsigned long get_init_mm_address(void){
    unsigned long symbol_size, offset, pos;
    unsigned long start_addr;
    unsigned long target_addr;
    unsigned long init_mm_address;
    uint32_t inst_code;
    uint8_t reg_index=0;
    bool flag;

    start_addr=(unsigned long)P_SYM(p_kallsyms_lookup_name)("__mmdrop");
    if(!start_addr) return 0;

    pos = P_SYM(p_get_symbol_pos)((unsigned long)start_addr, &symbol_size, &offset);
    if(!pos || offset) return 0;

    for(target_addr=start_addr;target_addr<start_addr+symbol_size;target_addr+=INSTRUCTION_SIZE){
        inst_code=*(uint32_t*)target_addr;
        //movw
        if((inst_code & 0xfff00000)==0xe3000000){
            reg_index=(inst_code & 0x0000f000)>>12;
            init_mm_address=(inst_code & 0xff) | (inst_code & 0xf00) | ((inst_code & 0xf0000)>>4);
        }
        //movt
        if((inst_code & 0xfff00000)==0xe3400000 && init_mm_address){
            if(((inst_code & 0x0000f000)>>12)!=reg_index) continue;
            init_mm_address=((inst_code & 0xff) | (inst_code & 0xf00) | ((inst_code & 0xf0000)>>4))<<16 | init_mm_address;
            flag=true;
            break;
        }
    }

    if(!flag) return 0;

    return init_mm_address;
}

static inline void arm_stub_fixup(hook_stub *stub, const void *entry,const void *ret){
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
    bool mode;
    unsigned char* hook_addr=0;

    p_current_hook_struct=(struct p_hook_struct*)arg;
    stub=p_current_hook_struct->stub;
    mode=(unsigned long)p_current_hook_struct->addr & 1;
    hook_addr=(unsigned char*)((unsigned long)p_current_hook_struct->addr & (~1));

    if(p_current_hook_struct->ret_fn==NULL && !mode){
		memcpy(stub,arm_stub_template,sizeof(arm_stub_template));
	}else if(p_current_hook_struct->ret_fn!=NULL && !mode){
		memcpy(stub,arm_stub_all_template,sizeof(arm_stub_all_template));
	}else if(p_current_hook_struct->ret_fn==NULL && mode){
        memcpy(stub,thumb_stub_template,sizeof(thumb_stub_template));
    }else{
        memcpy(stub,thumb_stub_all_template,sizeof(thumb_stub_all_template));
    }

    stub->nbytes=ARM_HOOK_SIZE;
    //填充回调函数地址
    arm_stub_fixup(stub,p_current_hook_struct->entry_fn,p_current_hook_struct->ret_fn);
    if(p_current_hook_struct->ret_fn==NULL){
        memcpy(stub->orig, hook_addr, stub->nbytes);
    }else{
        if(!mode){
            memcpy(stub->orig,arm_fix_parameters_limit_code,sizeof(arm_fix_parameters_limit_code));
            memcpy(stub->orig+sizeof(arm_fix_parameters_limit_code), hook_addr, stub->nbytes);
        }else{
            memcpy(stub->orig,thumb_fix_parameters_limit_code,sizeof(thumb_fix_parameters_limit_code));
            memcpy(stub->orig+sizeof(thumb_fix_parameters_limit_code), hook_addr, stub->nbytes);
        }
    }

    if(!mode){
        *(unsigned long*)&arm_hook_code[4]=(unsigned long)stub->hook;
        *(unsigned long*)&arm_hook_ret_code[4]=(unsigned long)hook_addr+stub->nbytes;
        if(p_current_hook_struct->ret_fn==NULL) memcpy(stub->orig+stub->nbytes,arm_hook_ret_code,sizeof(arm_hook_ret_code));
        else memcpy(stub->orig+stub->nbytes+sizeof(arm_fix_parameters_limit_code),arm_hook_ret_code,sizeof(arm_hook_ret_code));
    }else{
        *(unsigned long*)&thumb_hook_code[4]=(unsigned long)stub->hook;
        *(unsigned long*)&thumb_hook_ret_code[4]=(unsigned long)hook_addr+stub->nbytes;
        if(p_current_hook_struct->ret_fn==NULL) memcpy(stub->orig+stub->nbytes,thumb_hook_ret_code,sizeof(thumb_hook_ret_code));
        else memcpy(stub->orig+stub->nbytes+sizeof(thumb_fix_parameters_limit_code),thumb_hook_ret_code,sizeof(thumb_hook_ret_code));
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    if(!mode){
        p_ret = remap_write_range(hook_addr, arm_hook_code, stub->nbytes, true);
    }else{
        p_ret = remap_write_range(hook_addr, thumb_hook_code, stub->nbytes, true);
    }
#else
    remain=PAGE_SIZE-(((unsigned long)hook_addr)%PAGE_SIZE);
    //Double Page
    if(remain<stub->nbytes){
        if(!mode){
            p_ret=write_ro_memory(hook_addr,arm_hook_code,remain);
            if(p_ret!=0) return p_ret;
            p_ret=write_ro_memory(hook_addr+remain,&arm_hook_code[remain],stub->nbytes-remain);
        }else{
            p_ret=write_ro_memory(hook_addr,thumb_hook_code,remain);
            if(p_ret!=0) return p_ret;
            p_ret=write_ro_memory(hook_addr+remain,&thumb_hook_code[remain],stub->nbytes-remain);
        }
    }else{
        if(!mode){
            p_ret=write_ro_memory(hook_addr,arm_hook_code,stub->nbytes);
        }else{
            p_ret=write_ro_memory(hook_addr,thumb_hook_code,stub->nbytes);
        }
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
    unsigned char* hook_addr=0;
    bool mode;

    p_current_hook_struct=(struct p_hook_struct*)arg;
    stub=p_current_hook_struct->stub;
    hook_addr=(unsigned char*)((unsigned long)p_current_hook_struct->addr & (~1));
    mode=(unsigned long)p_current_hook_struct->addr & 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    if(p_current_hook_struct->ret_fn==NULL){
        p_ret = remap_write_range((void*)hook_addr, stub->orig, stub->nbytes, true);
    }else{
        if(mode) remap_write_range((void*)hook_addr, stub->orig+sizeof(thumb_fix_parameters_limit_code), stub->nbytes, true);
        else remap_write_range((void*)hook_addr, stub->orig+sizeof(arm_fix_parameters_limit_code), stub->nbytes, true);
    }
#else
    remain=PAGE_SIZE-(((unsigned long)hook_addr)%PAGE_SIZE);
    //Double Page
    if(remain<stub->nbytes){
        if(p_current_hook_struct->ret_fn==NULL){
            p_ret=write_ro_memory(hook_addr,stub->orig,remain);
            if(p_ret!=0) return p_ret;
            p_ret=write_ro_memory(hook_addr+remain,&stub->orig[remain],stub->nbytes-remain);
        }else{
           if(mode){
                p_ret=write_ro_memory(hook_addr,stub->orig+sizeof(thumb_fix_parameters_limit_code),remain);
                if(p_ret!=0) return p_ret;
                p_ret=write_ro_memory(hook_addr+remain,&stub->orig[remain+sizeof(thumb_fix_parameters_limit_code)],stub->nbytes-remain);
           }else{
                p_ret=write_ro_memory(hook_addr,stub->orig+sizeof(arm_fix_parameters_limit_code),remain);
                if(p_ret!=0) return p_ret;
                p_ret=write_ro_memory(hook_addr+remain,&stub->orig[remain+sizeof(arm_fix_parameters_limit_code)],stub->nbytes-remain);
           }
        }
    }else{
        if(p_current_hook_struct->ret_fn==NULL){
            p_ret=write_ro_memory(hook_addr,stub->orig,stub->nbytes);
        }else{
            if(mode) write_ro_memory(hook_addr,stub->orig+sizeof(thumb_fix_parameters_limit_code),stub->nbytes);
            else write_ro_memory(hook_addr,stub->orig+sizeof(arm_fix_parameters_limit_code),stub->nbytes);
        }
    }
#endif
    return p_ret;
}

#endif