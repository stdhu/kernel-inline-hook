#ifndef P_HOOK_CHECK_H
#define P_HOOK_CHECK_H

#if defined(CONFIG_ARM64)

#define ARM64_HOOK_SIZE 20
#define INSTRUCTION_SIZE 4

bool check_target_can_hook(void *target);

#endif

#endif