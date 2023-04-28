/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022, 2023 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com> and
 *	   Carlos Bilbao <carlos.bilbao@amd.com>
 */

#include <svsm.h>

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

	.rodata : {
	srodata = .;
		*(.rodata*)
	}
	. = ALIGN(4096);
	erodata = .;

	.data : {
	sdata = .;
		*(.data)
		*(.data._*)
		*(.data.rel*)
		*(.data.padding)
	}
	. = ALIGN(4096);
	edata = .;

	/DISCARD/ : {
		*(.*)
	}

	. = ASSERT(!(SVSM_GVA_LDS & 0xfffff), "SVSM_GPA not 2MB aligned! make clean and try again...");
}
