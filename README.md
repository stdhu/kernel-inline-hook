# kernel-inline-hook

## Introduction

This kernel module is a linux kernel inline hook module that supports different architectures. Used to inline hook linux kernel functions. This engine can be mainly used to insert custom code before or after calling a certain kernel function for functions similar to function monitoring.

## Support Situation

1. Callback before calling -> call the original function -> callback after calling
2. Callback before calling -> call the original function

## Limits

Currently the module supports the following architectures:

1. x86 (test passed)
2. x86_64 (test passed)
3. Arm (arm mode test passed but thumb mode not tested)
4. Arm64 (test passed)
5. Currently supports functions with hook parameters of 8 or less

## Extra Features

1. You can modify the parameters that call the original function in the previous callback
2. You can get the parameter content of the original function in the previous callback function, verify it, etc.
3. You can check the return value of the original function in the post callback function, and you can also modify the return value of the original function

## Build

1. Normal build first make and then insmod to load the module
2. If you want to build a kernel module under arm architecture on a machine with x86 architecture: make ARCH=arm64 or arm CROSS_COMPILE=cross toolchain address
3. If you want to add a hook function, you need to add the corresponding .o file path in the Makefile, add the corresponding header file in install/p_install, and add the corresponding file in the hook folder and add the added function information in the global array.

## Notice

1. If the kernel version is greater than 5.7.0, you need to pass in parameters when loading the module. For example: insmod hook_engine.ko kallsyms_lookup_name_address=0xffffffc0100d4dc8
2. If there are many hook functions, the system will freeze for a while when unloading, and the unloading will be successful because it is waiting for the memory to be released.

## Example

Example of hook function structure

```c
//ordinary function
static struct p_hook_struct p_generic_permission_hook={
    .entry_fn=p_generic_permission_entry, //callback before calling
    .ret_fn=p_generic_permission_ret, //callback after calling
    .name="generic_permission", //function name
};

//system call function
static struct p_hook_struct p_generic_permission_hook={
    .entry_fn=p_generic_permission_entry, //callback before calling
    .ret_fn=p_generic_permission_ret, //callback after calling
    .name="__x64_sys_read", //function name
    .sys_call_number=__NR_read
};
```

Example of callback function

```c
//parameter1: The return address of the call to the original function
//parameter2: Register condition when calling the original function
int p_generic_permission_ret(unsigned long ret_addr,hk_regs * regs);
```

Example of hook function array information

```c
static const struct p_functions_hooks{
    const char *name;
    int (*install)(int p_isra);
    void (*uninstall)(void);
    int is_sys;
}p_functions_hooks_array[]={
    {
        "generic_permission",
        p_install_generic_permission_hook,
        p_uninstall_generic_permission_hook,
        0
    },
    {NULL,NULL,NULL,0}
};
```

## Demo

![demo](images/demo.gif)

## References

1. https://github.com/milabs/khook
2. https://github.com/zhuotong/Android_InlineHook
3. https://github.com/WeiJiLab/kernel-hook-framework

