/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022, 2023 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::BIT;
use x86_64::addr::VirtAddr;

// CPL0 and CPL3 segment bases, and SYSCALL EIP
/// 0xc0000081
pub const MSR_STAR: u32 = 0xc0000081;

// Contains kernel's RIP SYSCALL entry
/// 0xC0000082
pub const MSR_LSTAR: u32 = 0xC0000082;

// Low 32 bits are SYSCALL flag mask (clearing rFLAGS)
/// 0xC0000084
pub const MSR_SFMASK: u32 = 0xC0000084;

// Value for MSR SFMASK to disable interrupts during syscalls
/// 0x200
pub const SFMASK_INTERRUPTS_DISABLED: u64 = BIT!(9);

// GHCB standard termination constants
/// 0
pub const GHCB_REASON_CODE_SET: u64 = 0;
/// 0
pub const GHCB_TERM_GENERAL: u64 = 0;
/// 1
pub const GHCB_TERM_UNSUPPORTED_PROTOCOL: u64 = 1;
/// 2
pub const GHCB_TERM_FEATURE_SUPPORT: u64 = 2;

// SVSM termination constants
/// 15
pub const SVSM_REASON_CODE_SET: u64 = 15;
/// 0
pub const SVSM_TERM_GENERAL: u64 = 0;
/// 1
pub const SVSM_TERM_ENOMEM: u64 = 1;
/// 2
pub const SVSM_TERM_UNHANDLED_VC: u64 = 2;
/// 3
pub const SVSM_TERM_PSC_ERROR: u64 = 3;
/// 4
pub const SVSM_TERM_SET_PAGE_ERROR: u64 = 4;
/// 5
pub const SVSM_TERM_NO_GHCB: u64 = 5;
/// 6
pub const SVSM_TERM_GHCB_RESP_INVALID: u64 = 6;
/// 7
pub const SVSM_TERM_FW_CFG_ERROR: u64 = 7;
/// 8
pub const SVSM_TERM_BIOS_FORMAT: u64 = 8;
/// 9
pub const SVSM_TERM_NOT_VMPL0: u64 = 9;
/// 10
pub const SVSM_TERM_VMPL0_SEV_FEATURES: u64 = 10;
/// 11
pub const SVSM_TERM_INCORRECT_VMPL: u64 = 11;
/// 12
pub const SVSM_TERM_VMPL1_SEV_FEATURES: u64 = 12;

/// 12
pub const PAGE_SHIFT: u64 = 12;
/// BIT 12
pub const PAGE_SIZE: u64 = BIT!(PAGE_SHIFT);
/// Page Mask (the opposite of page size minus 1)
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// 21
pub const PAGE_2MB_SHIFT: u64 = 21;
/// Bit 21
pub const PAGE_2MB_SIZE: u64 = BIT!(PAGE_2MB_SHIFT);
/// Page Mask for 2MB (the opposite of 2MB page size minus 1)
pub const PAGE_2MB_MASK: u64 = !(PAGE_2MB_SIZE - 1);

// CPUID
/// 0x0
pub const CPUID_VENDOR_INFO: u32 = 0x00000000;
/// 0xb
pub const CPUID_EXTENDED_TOPO: u32 = 0x0000000b;
/// 0xd
pub const CPUID_EXTENDED_STATE: u32 = 0x0000000d;

// MSRs
/// 0xc0000101
pub const MSR_GS_BASE: u32 = 0xc0000101;
/// 0xc0010130
pub const MSR_GHCB: u32 = 0xc0010130;
/// 0xc0010131
pub const MSR_SEV_STATUS: u32 = 0xc0010131;

// PVALIDATE and RMPADJUST related
/// 0
pub const RMP_4K: u32 = 0;
/// 1
pub const RMP_2M: u32 = 1;

/// Bit 8
pub const VMPL_R: u64 = BIT!(8);
/// Bit 9
pub const VMPL_W: u64 = BIT!(9);
/// Bit 10
pub const VMPL_X_USER: u64 = BIT!(10);
/// Bit 11
pub const VMPL_X_SUPER: u64 = BIT!(11);
/// Bit 16
pub const VMSA_PAGE: u64 = BIT!(16);

/// VMPL_R | VMPL_W | VMPL_X_USER | VMPL_X_SUPER
pub const VMPL_RWX: u64 = VMPL_R | VMPL_W | VMPL_X_USER | VMPL_X_SUPER;
/// VMPL_R | VMSA_PAGE
pub const VMPL_VMSA: u64 = VMPL_R | VMSA_PAGE;

#[derive(Copy, Clone, Debug)]
/// Vmpl levels
pub enum VMPL {
    Vmpl0,
    Vmpl1,
    Vmpl2,
    Vmpl3,

    VmplMax,
}

/// 8
pub const CAA_MAP_SIZE: u64 = 8;

/// PAGE_SIZE
pub const VMSA_MAP_SIZE: u64 = PAGE_SIZE;

//
// External symbol support:
//   To better control the expected type of value in the external symbol,
//   create getter and, optionally, setter functions for accessing the
//   sysmbols.
//
macro_rules! extern_symbol_u64_ro {
    ($name: ident, $T: ty) => {
        paste::paste! {
            extern "C" {
                static $name: $T;
            }
            pub fn [<get_ $name>]() -> u64 {
                unsafe {
                    $name as u64
                }
            }
        }
    };
}

macro_rules! extern_symbol_virtaddr_ro {
    ($name: ident, $T: ty) => {
        paste::paste! {
            extern "C" {
                static $name: $T;
            }
            pub fn [<get_ $name>]() -> VirtAddr {
                unsafe {
                    VirtAddr::new($name as u64)
                }
            }
        }
    };
}

macro_rules! extern_symbol_u64_rw {
    ($name: ident, $T1: ty) => {
        paste::paste! {
            extern "C" {
                static mut $name: $T1;
            }
            pub fn [<get_ $name>]() -> u64 {
                unsafe {
                    $name as u64
                }
            }
            pub fn [<set_ $name>](value: u64) {
                unsafe {
                    $name = value;
                }
            }
        }
    };
}

extern_symbol_u64_ro!(sev_encryption_mask, u64);
extern_symbol_virtaddr_ro!(svsm_begin, u64);
extern_symbol_virtaddr_ro!(svsm_end, u64);
extern_symbol_virtaddr_ro!(svsm_sbss, u64);
extern_symbol_virtaddr_ro!(svsm_ebss, u64);
extern_symbol_virtaddr_ro!(svsm_sdata, u64);
extern_symbol_virtaddr_ro!(svsm_edata, u64);
extern_symbol_virtaddr_ro!(svsm_secrets_page, u64);
extern_symbol_virtaddr_ro!(svsm_cpuid_page, u64);
extern_symbol_u64_ro!(svsm_cpuid_page_size, u64);
extern_symbol_virtaddr_ro!(bios_vmsa_page, u64);
extern_symbol_virtaddr_ro!(guard_page, u64);
extern_symbol_virtaddr_ro!(early_ghcb, u64);
extern_symbol_virtaddr_ro!(early_tss, u64);
extern_symbol_u64_ro!(gdt64_tss, u64);
extern_symbol_u64_ro!(gdt64_kernel_cs, u64);
extern_symbol_u64_ro!(gdt64_user32_cs, u64);
extern_symbol_u64_ro!(gdt64_user64_cs, u64);
extern_symbol_u64_ro!(gdt64_user64_ds, u64);
extern_symbol_virtaddr_ro!(dyn_mem_begin, u64);
extern_symbol_virtaddr_ro!(dyn_mem_end, u64);
extern_symbol_u64_rw!(hl_main, u64);
extern_symbol_u64_rw!(cpu_mode, u64);
extern_symbol_u64_rw!(cpu_stack, u64);
extern_symbol_u64_ro!(cpu_start, u64);
