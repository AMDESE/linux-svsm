/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

#include "svsm.h"

	.code64
GLOBAL(code_user)
	call	*hl_user_main(%rip)

	# We shouldn't reach this point, issue a
	# terminatipm call and enter a halt loop
	movq	$0x3f100, %rsi
	jmp	terminate_64

/*
 * 64-bit termination MSR protocol termination and HLT loop
 */
terminate_64:
	movq	%rsi, %rax
	movq	$0, %rdx
	movq	$0xc0010130, %rcx
	wrmsr
	rep;	vmmcall
terminate_hlt:
	hlt
	jmp	terminate_hlt

	.data
GLOBAL(hl_user_main)
	.quad	svsm_user_main

	.section .data.padding
data_pad_start:
	.fill	4096 - ((data_pad_end - data_pad_start) % 4096), 1, 0
	.balign	4096
data_pad_end:
