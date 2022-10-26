KERNEL_VER = $(shell uname -r)

# the file to compile
MODULE := hook_engine
obj-m += $(MODULE).o
#$(MODULE)-objs:= p_lkrg_main.o x86/p_x86_hook.o arm64/p_arm64_check.o arm64/p_arm64_hook.o arm32/p_arm32_check.o arm32/p_arm32_hook.o hook/p_generic_permission/p_generic_perimission.o
$(MODULE)-objs += p_lkrg_main.o \
				  x86/p_x86_hook.o \
				  arm64/p_arm64_check.o \
				  arm64/p_arm64_hook.o \
				  arm32/p_arm32_check.o \
				  arm32/p_arm32_hook.o \
				  hook/p_generic_permission/p_generic_permission.o \
				  install/p_install.o \
				  utils/p_memory.o \
				 

# specify flags for the module compilation
EXTRA_CFLAGS = -g -O0

build: kernel_modules

kernel_modules:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean