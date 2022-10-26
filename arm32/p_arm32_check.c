#include "../p_lkrg_main.h"

#if defined(CONFIG_ARM)
bool check_instruction_can_hijack(uint32_t instruction)
{
	bool ret = true;
    //todo: we want to fix these instructions
	switch (instruction & 0xfe000000u) {
		case 0xfa000000u:  // blx
		ret = false;
		goto out;
	}

	switch (instruction & 0x0f000000u) {
		case 0x0a000000u:  // b
		case 0x0b000000u:  // bl
		ret = false;
		goto out;
	}

	switch (instruction & 0xff000ffu) {
		case 0x0120001fu:  // bx
		ret = false;
		goto out;
	}

	switch (instruction & 0x0f00f010u) {
		case 0x0000f000u:  // and eor sub rsb add adc sbs rsc to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0f00f090u) {
		case 0x0000f010u:  // and eor sub rsb add adc sbs rsc to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0fe0f000u) {
		case 0x01a0f000u:  // mov to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0e5ff000u) {
		case 0x041ff000u:  // ldr to PC
		ret = false;
		goto out;
	}

	switch (instruction & 0x0ffff000u) {
		case 0x028ff000u:  // adr to PC
		case 0x024ff000u:
		ret = false;
		goto out;
	}

out:
    if (!ret) {
        printk(KERN_ALERT"instruction %x cannot be hijacked!\n", instruction);
    }
    return ret;
}

bool check_target_can_hook(void *target)
{
    int offset = 0;
    for (; offset < ARM_HOOK_SIZE; offset += INSTRUCTION_SIZE) {
        if (!check_instruction_can_hijack(*(uint32_t *)(target + offset)))
            return false;
    }
    return true;
}


#endif