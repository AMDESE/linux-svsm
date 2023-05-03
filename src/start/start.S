/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include "svsm.h"

#define CBIT(x)			(BIT(51) + x)
#define GPA(x)			(x - SVSM_GVA_OFFSET_ASM)

#define SVSM_PGD_ENTRY(x)	(CBIT(x) + 0x03)
#define SVSM_P4D_ENTRY(x)	(CBIT(x) + 0x03)
#define SVSM_PUD_ENTRY(x)	(CBIT(x) + 0x03)
#define SVSM_PMD_ENTRY(x)	(CBIT(x) + 0x83)
#define SVSM_PTE_ENTRY(x)	(CBIT(x) + 0x03)

	.code64
GLOBAL(code_64)
	cli

	xorq	%rax, %rax
	movq	%rax, %ds
	movq	%rax, %es
	movq	%rax, %fs
	movq	%rax, %ss

	/* Setup a stack */
	movq	cpu_stack(%rip), %rsp

/*
 * Jump to main high-level language code now for APs
 */
	cmpl	$0, cpu_mode(%rip)
	jne	hl

	/* Load RBX with the virtual address offset for use throughout boot */
	movq	$SVSM_GVA_OFFSET_ASM, %rbx

	/* GS is set for APs, only clear it after the AP check */
	movq	%rax, %gs

	/*
	 * SEV mitigation test to verify encryption bit position:
	 *   Use the CMP instruction, with RIP-relative addressing, to compare
	 *   the first four bytes of the CMP instruction itself (which will be
	 *   read decrypted if the encryption bit is in the proper location)
	 *   against the immediate value within the instruction itself
	 *   (instruction fetches are always decrypted by hardware).
	 */
	movq	$0x1f100, %rsi
insn:
	cmpl	$0xfff63d81, insn(%rip)
	jne	terminate_64

	/* Validate that the build load address matches the actual load address */
	movq	$0x2f100, %rsi
	leaq	code_64(%rip), %rax
	subq	%rbx, %rax
	movq	$SVSM_GPA_ASM, %rcx
	cmpq	%rax, %rcx
	jne	terminate_64

	/*
	 * Make the early GHCB shared:
	 *   - Since there is only one PGD/P4D/PUD entry, operate on just
	 *     the PMD entry that holds the early GHCB.
	 */
	leaq	ghcb(%rip), %rsi
	movq	%rsi, early_ghcb(%rip)

	/*
	 * Rescind the page validation from LAUNCH.
	 */
	movq	%rsi, %rax
	movq	$0, %rcx
	movq	$0, %rdx
	.byte 0xf2,0x0f,0x01,0xff	/* pvalidate */
	jc	terminate_64

	/*
	 * Issue the Page State Change to make shared in the RMP.
	 */
psc:
	movq	$0xc0010130, %rcx
	rdmsr
	pushq	%rax
	pushq	%rdx

	subq	%rbx, %rsi
	movq	$2, %rax
	shlq	$52, %rax
	addq	$0x14, %rax
	addq	%rsi, %rax
	movq	%rax, %rdx
	shrq	$32, %rdx
	wrmsr
	rep; vmmcall
	rdmsr
	cmpq	$0x15, %rax
	jne	terminate_64
	cmpq	$0, %rdx
	jne	terminate_64

	popq	%rdx
	popq	%rax
	wrmsr

	/*
	 * Build the PTE entries. Use the address of the early GHCB to
	 * obtain the start and end of the 2MB page in which it lives.
	 */
	leaq	ghcb(%rip), %rsi
	subq	%rbx, %rsi
	andq	$PAGE_2MB_MASK, %rsi
	addq	$PAGE_2MB_SIZE, %rsi
	movq	$SVSM_PTE_ENTRY(0), %rax
	addq	%rax, %rsi

	leaq	pte(%rip), %rax
	addq	$PAGE_SIZE, %rax

	movq	$PAGE_TABLE_ENTRY_COUNT, %rcx
set_pte:
	subq	$PAGE_SIZE, %rsi
	subq	$PAGE_TABLE_ENTRY_SIZE, %rax
	movq	%rsi, (%rax)
	loop	set_pte

	/* Make GHCB page shared */
	leaq	ghcb(%rip), %rsi
	movq	%rsi, %rax
	shrq	$PAGE_SHIFT, %rax
	andq	$PAGE_TABLE_INDEX_MASK, %rax
	shlq	$3, %rax
	leaq	pte(%rip), %rcx
	addq	%rcx, %rax
	subq	%rbx, %rsi
	addq	$0x03, %rsi
	movq	%rsi, (%rax)

	/* Replace the huge PMD entry with the new PTE */
	leaq	ghcb(%rip), %rsi
	movq	%rsi, %rax
	shrq	$PAGE_2MB_SHIFT, %rax
	andq	$PAGE_TABLE_INDEX_MASK, %rax
	shlq	$3, %rax
	leaq	pmd(%rip), %rcx
	addq	%rcx, %rax

	leaq	pte(%rip), %rdx
	subq	%rbx, %rdx
	movq	$SVSM_PTE_ENTRY(0), %rcx
	addq	%rcx, %rdx
	movq	%rdx, (%rax)

	/* Flush the TLB - no globals, so CR3 update is enough */
	mov	%cr3, %rax
	mov	%rax, %cr3

	/* Zero out the early GHCB */
	cld
	leaq	ghcb(%rip), %rdi
	movq	$PAGE_SIZE, %rcx
	xorq	%rax, %rax
	rep	stosb

	/* Zero out the BSS memory */
	cld
	leaq	sbss(%rip), %rdi
	leaq	ebss(%rip), %rcx
	subq	%rdi, %rcx
	xorq	%rax, %rax
	rep	stosb

	/* Save the start and end of the SVSM and dynamic memory */
	movq	$SVSM_GVA_ASM, %rax
	movq	%rax, svsm_begin(%rip)
	addq	$SVSM_MEM_ASM, %rax
	movq	%rax, svsm_end(%rip)

	movq	%rax, dyn_mem_end(%rip)
	leaq	SVSM_DYN_MEM_BEGIN(%rip), %rax
	movq	%rax, dyn_mem_begin(%rip)

hl:
	xorq	%rdi, %rdi
	xorq	%rsi, %rsi
	xorq	%rdx, %rdx
	xorq	%rcx, %rcx
	xorq	%r8, %r8
	xorq	%r9, %r9

	movq	hl_main(%rip), %rax
	call	*%rax

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

	.section .data
/*
 * Four zeroed stack pages with associated guard page.
 */
	.balign	4096
GLOBAL(bsp_guard_page)
	.fill	512, 8, 0
bsp_stack_start:
	.fill	8192, 8, 0
bsp_stack_end:

/*
 * 64-bit GDT.
 */
	.balign	8
GLOBAL(gdt64)
	.quad	0			/* Reserved */
kernel_cs:
	.quad	SVSM_KERNEL_CS_ATTR	/* 64-bit code segment (CPL0) */
kernel_ds:
	.quad	SVSM_KERNEL_DS_ATTR	/* 64-bit data segment (CPL0) */

tss:
	.quad	SVSM_TSS_ATTR0		/* 64-bit TSS */
	.quad	SVSM_TSS_ATTR1		/* TSS (Second half) */
GLOBAL(gdt64_end)

GLOBAL(gdt64_kernel_cs)
	.quad	SVSM_KERNEL_CS_SELECTOR

GLOBAL(gdt64_kernel_ds)
	.quad	SVSM_KERNEL_DS_SELECTOR

GLOBAL(gdt64_tss)
	.quad	SVSM_TSS_SELECTOR

GLOBAL(early_tss)
	.quad	tss

/*
 * 64-bit IDT - 256 16-byte entries
 */
	.balign 8
GLOBAL(idt64)
	.fill	2 * 256, 8, 0
GLOBAL(idt64_end)

/*
 * BSP/AP support:
 *   SMP support will update these values when starting an AP to provide
 *   information and unique values to each AP. This requires serialized
 *   AP startup.
 */
GLOBAL(cpu_mode)
	.long	0
GLOBAL(cpu_stack)
	.quad	bsp_stack_end
GLOBAL(cpu_start)
	.quad	code_64

/*
 * 64-bit identity-mapped pagetables:
 *   Maps only the size of the working memory of the SVSM.
 *   (e.g. 0x8000000000 - 0x800fffffff for 256MB)
 */
	.balign	4096
pgtables_start:
pgd:
	.fill	SVSM_PGD_INDEX, 8, 0
	.quad	SVSM_PGD_ENTRY(GPA(p4d))
	.fill	511 - SVSM_PGD_INDEX, 8, 0
p4d:
	.fill	SVSM_P4D_INDEX, 8, 0
	.quad	SVSM_P4D_ENTRY(GPA(pud))
	.fill	511 - SVSM_P4D_INDEX, 8, 0
pud:
	.fill	SVSM_PUD_INDEX, 8, 0
	.quad	SVSM_PUD_ENTRY(GPA(pmd))
	.fill	511 - SVSM_PUD_INDEX, 8, 0
pmd:
	.fill	SVSM_PMD_INDEX, 8, 0
	i = 0
	.rept	SVSM_PMD_COUNT
	.quad	SVSM_PMD_ENTRY(SVSM_GPA_ASM + i)
	i = i + SVSM_PMD_SIZE
	.endr
	.fill	511 - SVSM_PMD_INDEX - SVSM_PMD_COUNT + 1, 8, 0

/*
 * Reserve one extra page to split the 2MB private page that holds the
 * early GHCB so that a GHCB can be used for early page validation.
 */
pte:
	.fill	512, 8, 0
pgtables_end:

/*
 * Reserved an area for an early-usage GHCB, needed for fast validation
 * of memory.
 */
	.balign	4096
ghcb:
	.fill	512, 8, 0

/*
 * Main high-level language function to call
 */
GLOBAL(hl_main)
	.quad	svsm_main

/*
 * SEV related information
 */
GLOBAL(early_ghcb)
	.quad	0

GLOBAL(sev_encryption_mask)
	.quad	CBIT(0)

GLOBAL(sev_status)
	.quad	0

GLOBAL(svsm_begin)
	.quad	0

GLOBAL(svsm_end)
	.quad	0

GLOBAL(dyn_mem_begin)
	.quad	0

GLOBAL(dyn_mem_end)
	.quad	0

GLOBAL(svsm_sbss)
	.quad	sbss

GLOBAL(svsm_ebss)
	.quad	ebss

GLOBAL(svsm_sdata)
	.quad	sdata

GLOBAL(svsm_edata)
	.quad	edata

GLOBAL(guard_page)
	.quad	bsp_guard_page

GLOBAL(svsm_secrets_page)
	.quad	SVSM_SNP_SECRETS_PAGE_BASE

GLOBAL(svsm_secrets_page_size)
	.quad	SVSM_SNP_SECRETS_PAGE_SIZE

GLOBAL(svsm_cpuid_page)
	.quad	SVSM_SNP_CPUID_PAGE_BASE

GLOBAL(svsm_cpuid_page_size)
	.quad	SVSM_SNP_CPUID_PAGE_SIZE

GLOBAL(bios_vmsa_page)
	.quad	SVSM_SNP_BIOS_BSP_PAGE_BASE

/*
 * SVSM GUID Table
 */
	.section .data.guids

	/* Place the GUIDs at the end of the page */
	.balign	4096
	.fill	4096 - ((svsm_guids_end - svsm_fill_end) % 4096), 1, 0
svsm_fill_end:

/*
 * SVSM SEV SNP MetaData
 *   (similar to OVMF format, but addresses expanded to 8 bytes)
 */
svsm_snp_metadata:
	.byte	'S', 'V', 'S', 'M'					/* Signature */
	.long	svsm_snp_metadata_end - svsm_snp_metadata		/* Length */
	.long	1							/* Version */
	.long	(svsm_snp_metadata_end - svsm_snp_sections ) / 16	/* Section Count */

svsm_snp_sections:
	/* SEV SNP Secrets Page */
	.quad	GPA(SVSM_SNP_SECRETS_PAGE_BASE)
	.long	SVSM_SNP_SECRETS_PAGE_SIZE
	.long	2

	/* SEV SNP CPUID Page */
	.quad	GPA(SVSM_SNP_CPUID_PAGE_BASE)
	.long	SVSM_SNP_CPUID_PAGE_SIZE
	.long	3

	/* BIOS BSP VMSA Page */
	.quad	GPA(SVSM_SNP_BIOS_BSP_PAGE_BASE)
	.long	SVSM_SNP_BIOS_BSP_PAGE_SIZE
	.long	5
svsm_snp_metadata_end:

/*
 * SVSM GUID Envelope: 81384fea-ad48-4eb6-af4f-6ac49316df2b
 */
svsm_guids_start:

/* SVSM SEV SNP MetaData GUID: be30189b-ab44-4a97-82dd-ea813941047e */
svsm_guid_snp:
	.long	svsm_guids_end - svsm_snp_metadata			/* Offset to metadata */
	.word	svsm_guid_snp_end - svsm_guid_snp
	.byte	0x9b, 0x18, 0x30, 0xbe, 0x44, 0xab, 0x97, 0x4a
	.byte	0x82, 0xdd, 0xea, 0x81, 0x39, 0x41, 0x04, 0x7e
svsm_guid_snp_end:

/* SVSM INFO GUID: a789a612-0597-4c4b-a49f-cbb1fe9d1ddd */
svsm_guid_info:
	.quad	SVSM_GPA_ASM						/* SVSM load address */
	.quad	SVSM_MEM_ASM						/* SVSM memory footprint */
	.quad	CBIT(GPA(p4d))						/* SVSM pagetable (4-level) */
	.quad	gdt64							/* SVSM GDT */
	.word	SVSM_GDT_LIMIT						/* SVSM GDT limit */
	.quad	idt64							/* SVSM IDT */
	.word	SVSM_IDT_LIMIT						/* SVSM IDT limit */
	.word	SVSM_KERNEL_CS_SELECTOR					/* SVSM 64-bit CS slot */
	.quad	SVSM_KERNEL_CS_ATTR					/* SVSM 64-bit CS attributes */
	.quad	code_64							/* BSP start RIP */
	.quad	SVSM_EFER						/* SVSM EFER value */
	.quad	SVSM_CR0						/* SVSM CR0 value */
	.quad	SVSM_CR4						/* SVSM CR4 value */
	.word	svsm_guid_info_end - svsm_guid_info
	.byte	0x12, 0xa6, 0x89, 0xa7, 0x97, 0x05, 0x4b, 0x4c
	.byte	0xa4, 0x9f, 0xcb, 0xb1, 0xfe, 0x9d, 0x1d, 0xdd
svsm_guid_info_end:

	.word	svsm_guids_end - svsm_guids_start
	.byte	0xea, 0x4f, 0x38, 0x81, 0x48, 0xad, 0xb6, 0x4e
	.byte	0xaf, 0x4f, 0x6a, 0xc4, 0x93, 0x16, 0xdf, 0x2b
svsm_guids_end:
