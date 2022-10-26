#ifndef P_LKRG_ARM_CHECK_H
#define P_LKRG_ARM_CHECK_H

#if defined(CONFIG_ARM)

#define ARM_HOOK_SIZE 8
#define INSTRUCTION_SIZE 4

bool check_target_can_hook(void *target);

#endif

#endif