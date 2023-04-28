/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com> and
 *	   Carlos Bilbao <carlos.bilbao@amd.com>
 */

#include <svsm.h>

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	. = SVSM_CPL3_GVA_LDS;

	.text : {
	stext = .;
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
		*(.comment)
		*(.debug)
		*(.debug_*)
		*(.discard)
		*(.discard.*)
		*(.dynamic)
		*(.eh_frame)
		*(.note.GNU-stack)
		*(.note.gnu.build-id)
	}
}
