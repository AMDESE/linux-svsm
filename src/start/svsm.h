/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022, 2023 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef __SVSM_H__
#define __SVSM_H__

#define GLOBAL(_name)	\
	.global _name;	\
_name:

#define BIT(x)				(1ULL << (x))

#define LOWER_8BITS(x)			((u8)((x) & 0xff))
#define LOWER_16BITS(x)			((u16)((x) & 0xffff))
#define LOWER_32BITS(x)			((u32)((x) & 0xffffffff))
#define UPPER_32BITS(x) 		((u32)(x >> 32))

#define MIN(x, y)			((x) < (y) ? (x) : (y))
#define MAX(x, y)			((x) > (y) ? (x) : (y))

#define PAGE_TABLE_ENTRY_SIZE		8
#define PAGE_TABLE_ENTRY_COUNT		512
#define PAGE_TABLE_INDEX_MASK		(PAGE_TABLE_ENTRY_COUNT - 1)

#define PAGE_SHIFT			12
#define PAGE_SIZE			BIT(PAGE_SHIFT)
#define PAGE_MASK			~(PAGE_SIZE - 1)
#define PAGE_ADDR(x)			((u64)(x) & PAGE_MASK)
#define PAGE_ALIGN(x)			(((u64)(x) + PAGE_SIZE - 1) & PAGE_MASK)
#define PAGE_ALIGNED(x)			ALIGNED((u64)(x), PAGE_SIZE)
#define PAGE_COUNT(x)			(PAGE_ALIGN(x) >> PAGE_SHIFT)
#define PA(x)				((u64)(x))
#define PFN(x)				(PA(x) >> PAGE_SHIFT)
#define PFN_TO_PA(x)			((u64)(x) << PAGE_SHIFT)

#define PAGE_2MB_SHIFT			21
#define PAGE_2MB_SIZE			BIT(PAGE_2MB_SHIFT)
#define PAGE_2MB_MASK			~(PAGE_2MB_SIZE - 1)
#define PAGE_2MB_ALIGNED(x)		ALIGNED((u64)(x), PAGE_2MB_SIZE)

#ifndef SVSM_GPA
#define SVSM_GPA			0x8000000000	/* 512 GB start */
#endif /* SVSM_GPA */

#ifndef SVSM_MEM
#define SVSM_MEM			0x10000000	/* 256 MB of memory */
#endif /* SVSM_MEM */

#define __ASM_ULL(x)			x ## ULL
#define ASM_ULL(x)			__ASM_ULL(x)

#define SVSM_GPA_ASM			ASM_ULL(SVSM_GPA)
#define SVSM_MEM_ASM			ASM_ULL(SVSM_MEM)

#define SVSM_GVA_OFFSET			0xffff800000000000
#define SVSM_GVA_OFFSET_ASM		ASM_ULL(SVSM_GVA_OFFSET)

#define SVSM_GVA_ASM			(SVSM_GPA_ASM + SVSM_GVA_OFFSET_ASM)
#define SVSM_GVA_LDS			(SVSM_GPA + SVSM_GVA_OFFSET)

#define SVSM_PAGES			(SVSM_MEM_ASM / PAGE_SIZE)

#define SVSM_EFER			0x00001d00	/* SVME, NXE, LMA, LME */
#define SVSM_CR0			0x80010033	/* PG, WP, NE, ET, MP, PE */
#define SVSM_CR4			0x00000668	/* OSXMMEXCPT, OSFXSR, MCE, PAE, DE */

#define SVSM_PGD_INDEX			((SVSM_GVA_ASM >> 48) & 511)
#define SVSM_P4D_INDEX			((SVSM_GVA_ASM >> 39) & 511)
#define SVSM_PUD_INDEX			((SVSM_GVA_ASM >> 30) & 511)
#define SVSM_PMD_INDEX			((SVSM_GVA_ASM >> 21) & 511)
#define SVSM_PTE_INDEX			((SVSM_GVA_ASM >> 12) & 511)

#define SVSM_PGD_SIZE			0x1000000000000ULL
#define SVSM_PGD_COUNT			(SVSM_MEM_ASM / SVSM_PGD_SIZE)
#define SVSM_P4D_SIZE			0x8000000000ULL
#define SVSM_P4D_COUNT			(SVSM_MEM_ASM / SVSM_P4D_SIZE)
#define SVSM_PUD_SIZE			0x40000000ULL
#define SVSM_PUD_COUNT			(SVSM_MEM_ASM / SVSM_P4D_SIZE)
#define SVSM_PMD_SIZE			0x200000ULL
#define SVSM_PMD_COUNT			(SVSM_MEM_ASM / SVSM_PMD_SIZE)

#define SVSM_GDT_LIMIT			gdt64_end - gdt64 - 1
#define SVSM_IDT_LIMIT			idt64_end - idt64 - 1

#define SVSM_KERNEL_CS_SELECTOR		(kernel_cs - gdt64)
#define SVSM_KERNEL_CS_ATTR		0x00af9a000000ffff
#define SVSM_KERNEL_DS_SELECTOR		(kernel_ds - gdt64)
#define SVSM_KERNEL_DS_ATTR		0x00cf92000000ffff
#define SVSM_USER32_CS_SELECTOR		(user32_cs - gdt64) | 0x3
#define SVSM_USER32_CS_ATTR		0x00cffa000000ffff
#define SVSM_USER_DS_SELECTOR		(user64_ds - gdt64) | 0x3
#define SVSM_USER_DS_ATTR		0x00cff2000000ffff
#define SVSM_USER_CS_SELECTOR		(user64_cs - gdt64) | 0x3
#define SVSM_USER_CS_ATTR		0x00affa000000ffff

#define SVSM_TSS_SELECTOR		(tss - gdt64)
#define SVSM_TSS_ATTR0			0x0080890000000000
#define SVSM_TSS_ATTR1			0x0000000000000000

#define SVSM_SNP_MEASURED_PAGES_BASE	edata

#define SVSM_SNP_SECRETS_PAGE_BASE	SVSM_SNP_MEASURED_PAGES_BASE
#define SVSM_SNP_SECRETS_PAGE_SIZE	4096
#define SVSM_SNP_SECRETS_PAGE_END	SVSM_SNP_SECRETS_PAGE_BASE + SVSM_SNP_SECRETS_PAGE_SIZE

#define SVSM_SNP_CPUID_PAGE_BASE	SVSM_SNP_SECRETS_PAGE_END
#define SVSM_SNP_CPUID_PAGE_SIZE	4096
#define SVSM_SNP_CPUID_PAGE_END		SVSM_SNP_CPUID_PAGE_BASE + SVSM_SNP_CPUID_PAGE_SIZE

#define SVSM_SNP_BIOS_BSP_PAGE_BASE	SVSM_SNP_CPUID_PAGE_END
#define SVSM_SNP_BIOS_BSP_PAGE_SIZE	4096
#define SVSM_SNP_BIOS_BSP_PAGE_END	SVSM_SNP_BIOS_BSP_PAGE_BASE + SVSM_SNP_BIOS_BSP_PAGE_SIZE

#define SVSM_DYN_MEM_BEGIN		SVSM_SNP_BIOS_BSP_PAGE_END

#define PVALIDATE_RET_MAX		0x0f
#define PVALIDATE_CF_SET		0x10
#define PVALIDATE_RET_RANGE_ERR		0x11

#define VMPL_R				BIT(8)
#define VMPL_W				BIT(9)
#define VMPL_X_USER			BIT(10)
#define VMPL_X_SUPER			BIT(11)
#define VMSA_PAGE			BIT(16)

#define VMPL_RWX			(VMPL_R | VMPL_W | VMPL_X_USER | VMPL_X_SUPER)
#define VMPL_VMSA			(VMPL_R | VMSA_PAGE)

#define CPUID_VENDOR_INFO		0x00000000
#define CPUID_PROCESSOR_INFO		0x00000001
#define CPUID_EXTENDED_TOPO		0x0000000b

#define SVSM_SECRETS_PAGE_OFFSET	0x140

#ifndef __ASSEMBLY__

#define ALIGN(x, y)			(((x) + (y) - 1) & ~(y - 1))
#define ALIGNED(x, y)			((x) == ALIGN((x), (y)))

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;

enum {
	RMP_4K = 0,
	RMP_2M,
};

enum {
	PVALIDATE_RESCIND = 0,
	PVALIDATE_VALIDATE,
};

enum {
	VMPL0 = 0,
	VMPL1,
	VMPL2,
	VMPL3,

	VMPL_MAX
};

struct ca {
	u8 call_pending;
	u8 mem_available;
	u8 reserved_1[6];
} __attribute__((packed));

struct vmpl_info {
	struct vmsa *vmsa;
	struct ca *ca;
};

struct sev_snp_secrets_page {
	u32 version;
	u32 flags;
	u32 fms;
	u8  reserved_1[4];

	u8  gosvw[16];

	u8  vmpck0[32];
	u8  vmpck1[32];
	u8  vmpck2[32];
	u8  vmpck3[32];

	u8  os_reserved[96];

	u8  reserved_2[64];

	/* SVSM fields start at offset 0x140 into the secrets page */
	u64 svsm_base;
	u64 svsm_size;
	u64 svsm_caa;
	u32 svsm_max_version;
	u8  svsm_guest_vmpl;
	u8  reserved_3[3];
} __attribute__((packed));

extern u64 sev_encryption_mask;
extern u64 sev_status;

extern u8 code_64[];

extern u8 stext[];
extern u8 etext[];

extern u8 sbss[];
extern u8 ebss[];

extern u8 sdata[];
extern u8 edata[];

extern u8 bsp_guard_page[];

extern u32 cpu_mode;
extern u64 cpu_stack;

extern u64 hl_main;
void svsm_ap(void);

int prints(const char *format, ...);

#endif /* __ASSEMBLY__ */

#endif
