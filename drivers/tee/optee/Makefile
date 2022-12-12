# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_OPTEE) += optee.o
optee-objs += core.o
optee-objs += call.o
optee-objs += rpc.o
optee-objs += supp.o
optee-objs += shm_pool.o
optee-objs += device.o
ifdef CONFIG_X86_64
optee-objs += vsmcall.o
endif
# for tracing framework to find optee_trace.h
CFLAGS_call.o := -I$(src)
