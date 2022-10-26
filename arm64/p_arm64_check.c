#include "../p_lkrg_main.h"

#if defined(CONFIG_ARM64)
bool check_instruction_can_hook(uint32_t instruction)
{
    bool ret = true;

    //todo: we want to fix these instructions
    switch(instruction & 0x9f000000u) {
        case 0x10000000u:  //adr  
        case 0x90000000u:  //adrp
            ret = false;
            goto out;
    }
    switch(instruction & 0xfc000000u) {
        case 0x14000000u:  //b  
        case 0x94000000u:  //bl
            ret = false;
            goto out;
    }
    switch(instruction & 0xff000000u) {
        case 0x54000000u:  //b.c  
            ret = false;
            goto out;
    }    
    switch(instruction & 0x7e000000u) {
        case 0x34000000u:  //cbz cbnz
        case 0x36000000u:  //tbz tbnz
            ret = false;
            goto out;
    }
    switch(instruction & 0xbf000000u) {
        case 0x18000000u:  //ldr
            ret = false;
            goto out;
    }
    switch(instruction & 0x3f000000u) {
        case 0x1c000000u:  //ldrv
            ret = false;
            goto out;
    }
    switch(instruction & 0xff000000u) {
        case 0x98000000u:  //ldrsw
            ret = false;
            goto out;
    }

out:
    if (!ret) {
        p_print_log(KERN_ALERT"instruction %x cannot be hook!\n", instruction);
    }
    return ret;
}

bool check_target_can_hook(void *target)
{
    int offset = 0;
    for (; offset < ARM64_HOOK_SIZE; offset += INSTRUCTION_SIZE) {
        if (!check_instruction_can_hook(*(uint32_t *)(target + offset)))
            return false;
    }

    return true;
}
#endif