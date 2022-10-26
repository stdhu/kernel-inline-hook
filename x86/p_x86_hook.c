#include "../p_lkrg_main.h"

#if defined(CONFIG_X86)

#if defined(CONFIG_X86_64)
#define KHOOK_STUB_FILE_NAME "x86_stub64.inc"
#define KHOOK_STUB_FILE_NAME_ALL "x86_stub64_all.inc"
#elif defined(CONFIG_X86)
#define KHOOK_STUB_FILE_NAME "x86_stub.inc"
#define KHOOK_STUB_FILE_NAME_ALL "x86_stub_all.inc"
#endif

static const char hook_stubemplate[] = {
#include KHOOK_STUB_FILE_NAME
};

static const char hook_stubemplate_all[] = {
#include KHOOK_STUB_FILE_NAME_ALL
};

#if defined(CONFIG_X86_32)
unsigned char fix_parameters_limit_code[] = {
	0x83,0xEC,0x14,
	0x60,
	0x8B,0x44,0x24,0x34,
	0x89,0x44,0x24,0x20,
	0xB9,0x04,0x00,0x00,0x00,
	0x8D,0x74,0x24,0x3C,
	0x8D,0x7C,0x24,0x24,
	0xF3,0xA5,
	0x61
};
#endif

#if defined(CONFIG_X86_64)
unsigned char fix_parameters_limit_code[] = {
	0x48,0x83,0xEC,0x10,
	0x50,
	0x51,
	0x56,
	0x57,
	0x48,0x8B,0x44,0x24,0x30,
	0x48,0x89,0x44,0x24,0x20,
	0xB9,0x02,0x00,0x00,0x00,
	0x48,0x8D,0x74,0x24,0x40,
	0x48,0x8D,0x7C,0x24,0x28,
	0xF3,0x48,0xA5,
	0x5F,
	0x5E,
	0x59,
	0x58
};
#endif

static inline int get_hook_length(const void *p) {
	struct insn insn;
	int x86_64 = 0;
#ifdef CONFIG_X86_64
	x86_64 = 1;
#endif
#if defined MAX_INSN_SIZE && (MAX_INSN_SIZE == 15) /* 3.19.7+ */
	P_SYM(p_insn_init)(&insn, p, MAX_INSN_SIZE, x86_64);
#else
	P_SYM(p_insn_init)(&insn, p, x86_64);
#endif
	P_SYM(p_insn_get_length)(&insn);
	return insn.length;
}

static inline void x86_put_jmp(void *a, void *f, void *t)
{
	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (f + 5));
}

static inline void stub_fixup(unsigned char* stub, const void *entry,const void *ret){
	
	while (*(int *)stub != 0xcacacaca) stub++;
	*(unsigned long *)stub = (unsigned long)entry;

	if(ret==NULL) return;
		
	while(*(int*)stub!=0xcbcbcbcb) stub++;
	*(unsigned long*)stub=(unsigned long)ret;
		
}

#if defined(CONFIG_X86) && !defined(CONFIG_X86_64)
static inline void stub_use_count_fixup(unsigned char* stub,const void *fix_addr)
{
	while (*(int *)stub != 0xabababab) stub++;
	*(int*)stub = (int)fix_addr;

	while (*(int *)stub != 0xacacacac) stub++;
	*(int*)stub = (int)fix_addr;
}
#endif

static inline int is_fix_offset(unsigned char *opcode){
	if(opcode[0]==0xE8 || opcode[0]==0xE9){
		return 1;
	}
#ifdef CONFIG_X86_64
		//jmp [addr]
	if(opcode[0]==0xFF && opcode[1]==0x25){
		return 2;
	}
	//mov reg,[addr]
	//mov [addr],reg
	//lea reg,[addr]
	if((opcode[0]==0x48 || opcode[0]==0x4C) && (opcode[1]==0x8B || opcode[1]==0x8D) && (opcode[2]&0x5)==0x5){
		return 3;
	}
#endif
	return -1;
}

static inline void fix_hook_offset(long func_addr,unsigned long new_addr,int offset,int insn_length,int size,int pos){
	long target_addr=0;
	int new_offset=0;
	unsigned char *opcode=(unsigned char*)new_addr;
	
	target_addr=func_addr+size+offset+insn_length;
	new_offset=target_addr-(new_addr+size+insn_length);
	*(int*)&opcode[size+pos]=new_offset;
}

//fix offset
static inline void find_offset_code(struct p_hook_struct * p_current_hook_struct,unsigned long func_addr,unsigned long hook_length){
	struct insn insn;
	int x86_64 = 0;
	int size=0;
	int pos=0;
	unsigned char *opcode;

#ifdef CONFIG_X86_64
	x86_64 = 1;
#endif
	while(size<hook_length){
#if defined MAX_INSN_SIZE && (MAX_INSN_SIZE == 15) /* 3.19.7+ */
		P_SYM(p_insn_init)(&insn, (void*)(func_addr+size), MAX_INSN_SIZE, x86_64);
#else
		P_SYM(p_insn_init)(&insn, (void*)(func_addr+size), x86_64);
#endif
		P_SYM(p_insn_get_length)(&insn);
		opcode=(unsigned char*)(func_addr+size);
		if((pos=is_fix_offset(opcode))!=-1){
			p_current_hook_struct->ori_offset=*(int*)&opcode[pos];
			p_current_hook_struct->is_fix=true;
			if(p_current_hook_struct->ret_fn==NULL){
				fix_hook_offset(func_addr,(unsigned long)p_current_hook_struct->stub->orig,p_current_hook_struct->ori_offset,insn.length,size,pos);
			}else{
				fix_hook_offset(func_addr,(unsigned long)p_current_hook_struct->stub->orig+sizeof(fix_parameters_limit_code),p_current_hook_struct->ori_offset,insn.length,size,pos);
			}

			break;
		}
	
		size+=insn.length;
	}
}

static inline void reduce_hook_offset(unsigned long func_addr,unsigned long hook_addr,int ori_offset,int hook_length){
	int size=0;
	int x86_64 = 0;
	int pos=0;
	char tmp_code[20]={0};
	struct insn insn;
	unsigned char *opcode;

#ifdef CONFIG_X86_64
	x86_64 = 1;
#endif
	while(size<hook_length){
#if defined MAX_INSN_SIZE && (MAX_INSN_SIZE == 15) /* 3.19.7+ */
		P_SYM(p_insn_init)(&insn, (void*)(hook_addr+size), MAX_INSN_SIZE, x86_64);
#else
		P_SYM(p_insn_init)(&insn, (void*)(hook_addr+size), x86_64);
#endif
		P_SYM(p_insn_get_length)(&insn);
		opcode=(unsigned char*)(hook_addr+size);
		if((pos=is_fix_offset(opcode))!=-1){
			break;
		}

		size+=insn.length;
	}

	memcpy(tmp_code,(char*)hook_addr,hook_length);
	*(int*)&tmp_code[size+pos]=ori_offset;
	memcpy((char*)func_addr,tmp_code,hook_length);
}

int inline_hook_install(void *arg)
{
    struct p_hook_struct * p_current_hook_struct=(struct p_hook_struct*)arg;
	hook_stub * stub=p_current_hook_struct->stub;
	
	if(p_current_hook_struct->ret_fn==NULL){
		memcpy(stub,hook_stubemplate,sizeof(hook_stubemplate));
	}else{
		memcpy(stub,hook_stubemplate_all,sizeof(hook_stubemplate_all));
	}
	
	stub_fixup(stub->hook,p_current_hook_struct->entry_fn,p_current_hook_struct->ret_fn);
#if defined(CONFIG_X86_32)
	stub_use_count_fixup(stub->hook,&stub->use_count);
#endif

	while (stub->nbytes < 5)
		stub->nbytes += get_hook_length(p_current_hook_struct->addr + stub->nbytes);
	
	if(p_current_hook_struct->ret_fn==NULL){
		memcpy(stub->orig, p_current_hook_struct->addr, stub->nbytes);
		x86_put_jmp(stub->orig + stub->nbytes, stub->orig + stub->nbytes, p_current_hook_struct->addr + stub->nbytes);
	}else{
		memcpy(stub->orig,fix_parameters_limit_code,sizeof(fix_parameters_limit_code));
		memcpy(stub->orig + sizeof(fix_parameters_limit_code), p_current_hook_struct->addr, stub->nbytes);
		x86_put_jmp(stub->orig + stub->nbytes + sizeof(fix_parameters_limit_code), stub->orig + stub->nbytes + sizeof(fix_parameters_limit_code), p_current_hook_struct->addr + stub->nbytes);
	}

	find_offset_code(p_current_hook_struct,(unsigned long)p_current_hook_struct->addr,stub->nbytes);	
	kernel_write_enter();
	x86_put_jmp(p_current_hook_struct->addr, p_current_hook_struct->addr, stub->hook);
	kernel_write_leave();
	
	return 0;
}


int inline_hook_uninstall(void *arg)
{
    struct p_hook_struct * p_current_hook_struct=(struct p_hook_struct*)arg;
	hook_stub * stub=p_current_hook_struct->stub;

	kernel_write_enter();
	if(p_current_hook_struct->is_fix){
		if(p_current_hook_struct->ret_fn==NULL){
			reduce_hook_offset((unsigned long)p_current_hook_struct->addr,(unsigned long)stub->orig,p_current_hook_struct->ori_offset,stub->nbytes);
		}else{
			reduce_hook_offset((unsigned long)p_current_hook_struct->addr,(unsigned long)stub->orig+sizeof(fix_parameters_limit_code),p_current_hook_struct->ori_offset,stub->nbytes);
		}		
	}else{
		if(p_current_hook_struct->ret_fn==NULL){
			memcpy(p_current_hook_struct->addr,stub->orig,stub->nbytes);
		}else{
			memcpy(p_current_hook_struct->addr,stub->orig+sizeof(fix_parameters_limit_code),stub->nbytes);
		}
		
	}
	kernel_write_leave();
	return 0;
}


#endif
