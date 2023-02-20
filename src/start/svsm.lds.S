/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com> and
 *	   Carlos Bilbao <carlos.bilbao@amd.com>
 */

#include "svsm.h"

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(code_64)

SECTIONS
{
	. = SVSM_GVA_LDS;

	.text : {
	stext = .;
		*(.text.reset)
		*(.text)
		*(.text.*)
	}
	. = ALIGN(4096);
	etext = .;

	.bss : {
	sbss = .;
		*(.bss)
		*(.bss._*)
	}
	. = ALIGN(4096);
	ebss = .;

	.data : {
	sdata = .;
		*(.data)
		*(.data._*)
		*(.data.rel*)
		*(.data.guids)
	}
	edata = .;

	/DISCARD/ : {
		*(.comment)
		*(.discard)
		*(.discard.*)
		*(.dynamic)
		*(.eh_frame)
		*(.note.GNU-stack)
		*(.note.gnu.build-id)
	}

	. = ASSERT(!(SVSM_GVA_LDS & 0xfffff), "SVSM_GPA not 2MB aligned! make clean and try again...");
}
