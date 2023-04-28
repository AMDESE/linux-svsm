/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

#include <svsm.h>

// Offsets of user and kernel stack for PerCpu
#define OFFSET_KERNEL_STACK	0
#define OFFSET_USER_STACK	8

#define SAVE_REGS						 \
	pushq	%rdi						;\
	pushq	%rsi						;\
	pushq	%rdx						;\
	pushq	%r8						;\
	pushq	%r9						;\
	pushq	%r10						;\
	pushq	%rcx						;\
	pushq	%r11

#define RESTORE_REGS						 \
	popq	%r11						;\
	popq	%rcx						;\
	popq	%r10						;\
	popq	%r9						;\
	popq	%r8						;\
	popq	%rdx						;\
	popq	%rsi						;\
	popq	%rdi

	.balign	4096
	.code64
GLOBAL(enter_syscall)
enter_syscall:

	# Change GS to access per-CPU variables
	swapgs

	# Save user stack, set rsp to kernel stack
	# of this CPU. 0 and 8 are the offsets
	# for per-CPU user and kernel stacks,
	# respectively
	movq	%rsp, %gs:(OFFSET_USER_STACK)
	movq	%gs:(OFFSET_KERNEL_STACK), %rsp

	# Save registers
	SAVE_REGS

	# Call the handler
	movq	%r10, %rcx
	call	*handle_syscall(%rip)

	# Don't touch rax passed this point

	# Restore registers
	RESTORE_REGS

	# Switch stack back to user
	movq	%gs:(OFFSET_USER_STACK), %rsp

	swapgs
	sysretq

end_code_user:
	.section .data

GLOBAL(handle_syscall)
	.quad	syscall_handler

GLOBAL(syscall_entry)
	.quad	enter_syscall

GLOBAL(offset_kernel)
	.quad	OFFSET_KERNEL_STACK

GLOBAL(offset_user)
	.quad	OFFSET_USER_STACK
