/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::sys::EFER_SVME;
use crate::globals::*;
use crate::STATIC_ASSERT;
use crate::{cmpxchg, funcs, BARRIER, BIT};

use core::mem::size_of;
use memoffset::offset_of;
use paste::paste;
use x86_64::addr::VirtAddr;
use x86_64::instructions::tlb::flush;

// Sev Features for guest
// Secure Nested Paging is active
/// Bit 0
pub const SEV_FEAT_SNP_ACTIVE: u64 = BIT!(0);

// Virtual TOM feature is enabled
/// Bit 1
pub const SEV_FEAT_VIRTUAL_TOM: u64 = BIT!(1);

// Reflect #VC is enabled
/// Bit 2
pub const SEV_FEAT_REFLECT_VC: u64 = BIT!(2);

// Restricted Injection is enabled
/// Bit 3
pub const SEV_FEAT_RESTRICTED_INJ: u64 = BIT!(3);

// Alternate Injection is enabled
/// Bit 4
pub const SEV_FEAT_ALTERNATE_INJ: u64 = BIT!(4);

// Extra debug registers are swapped
/// Bit 5
pub const SEV_FEAT_DEBUG_SWAP: u64 = BIT!(5);

// Prevent Host IBS is enabled
/// Bit 6
pub const SEV_FEAT_PREVENT_HOST_IBS: u64 = BIT!(6);

// BTB predictor isolation is enabled
/// Bit 7
pub const SEV_FEAT_SNP_BTB_ISOLATION: u64 = BIT!(7);

// VMPL SSS is enabled
/// Bit 8
pub const SEV_FEAT_VMPL_SSS: u64 = BIT!(8);

// Secure TSC feature is enabled
/// Bit 9
pub const SEV_FEAT_SECURE_TSC: u64 = BIT!(9);

// Reserved
/// Bits 10 to 13
pub const SEV_FEAT_RESERVED_1: u64 = 0b1111 << 10;

// VMSA Register Protection is enabled
/// Bit 14
pub const SEV_FEAT_VMSA_REG_PROTECTION: u64 = BIT!(14);

// Reserved
/// Bits 15 to 63
pub const SEV_FEAT_RESERVED_2: u64 = !(BIT!(15) - 1);

//
// Different VMPL levels may have distinct SEV features,
// but some of them should be enabled or not, depending on
// currently supported features and security considerations.
// This is the info on what should be checked or ignored:

// MB1 - Must be 1
// MBZ - Must be 0
// DC  - Don't care
//
// BITS                            VMPL0           VMPL1
//
//  0 - SNPAactive                 MB1             MB1
//  1 - VirtualTOM                 MBZ             MBZ
//  2 - ReflectVC                  MBZ             MBZ
//  3 - RestrictInjection          MB1             DC
//  4 - AlternateInjection         MBZ             MBZ
//  5 - DebugSwapSupport           DC              DC
//  6 - PreventHostIbs             DC              DC
//  7 - SNPBTBIsolation            DC              DC
//  8 - VMPLSSS                    DC              DC
//  9 - SecureTSC                  MBZ             MBZ
// 10 - 13  Reserved_1             MBZ             MBZ
// 14 - VmsaRegisterProtection     MBZ             MBZ
//
// 15 - 63 Reserved_2              MBZ             MBZ
//

/// These are the features that must be one for VMPL1
pub const VMPL1_REQUIRED_SEV_FEATS: u64 = SEV_FEAT_SNP_ACTIVE;

/// These are the features that must be zero for VMPL1
pub const VMPL1_UNSUPPORTED_SEV_FEATS: u64 = SEV_FEAT_VIRTUAL_TOM
    | SEV_FEAT_REFLECT_VC
    | SEV_FEAT_ALTERNATE_INJ
    | SEV_FEAT_SECURE_TSC
    | SEV_FEAT_RESERVED_1
    | SEV_FEAT_VMSA_REG_PROTECTION
    | SEV_FEAT_RESERVED_2;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct VmsaSegmentRegister {
    selector: u16,
    rtype: u16,
    limit: u32,
    base: u64,
}

/// These are the features that must be one for VMPL0
pub const VMPL0_REQUIRED_SEV_FEATS: u64 = SEV_FEAT_SNP_ACTIVE | SEV_FEAT_RESTRICTED_INJ;

/// These are the features that must be zero for VMPL0
pub const VMPL0_UNSUPPORTED_SEV_FEATS: u64 = SEV_FEAT_VIRTUAL_TOM
    | SEV_FEAT_REFLECT_VC
    | SEV_FEAT_ALTERNATE_INJ
    | SEV_FEAT_SECURE_TSC
    | SEV_FEAT_RESERVED_1
    | SEV_FEAT_VMSA_REG_PROTECTION
    | SEV_FEAT_RESERVED_2;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
/// Virtual Machine Saving Area for world switches
pub struct Vmsa {
    es: VmsaSegmentRegister,
    cs: VmsaSegmentRegister,
    ss: VmsaSegmentRegister,
    ds: VmsaSegmentRegister,
    fs: VmsaSegmentRegister,
    gs: VmsaSegmentRegister,
    gdtr: VmsaSegmentRegister,
    ldtr: VmsaSegmentRegister,
    idtr: VmsaSegmentRegister,
    tr: VmsaSegmentRegister,

    reserved1: [u8; 42],

    vmpl: u8,
    cpl: u8,

    reserved2: [u8; 4],

    efer: u64,

    reserved3: [u8; 104],

    xss: u64,
    cr4: u64,
    cr3: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,

    reserved4: [u8; 88],

    rsp: u64,

    reserved5: [u8; 24],

    rax: u64,

    reserved6: [u8; 104],

    gpat: u64,

    reserved7: [u8; 152],

    rcx: u64,
    rdx: u64,
    rbx: u64,

    reserved8: [u8; 8],

    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,

    reserved9: [u8; 48],

    sev_features: u64,

    reserved10: [u8; 8],

    guest_exitcode: u64,

    virtual_tom: u64,

    reserved11: [u8; 24],

    xcr0: u64,

    reserved12: [u8; 16],

    x87_dp: u64,
    mxcsr: u32,
    x87_ftw: u16,
    x87_fsw: u16,
    x87_fcw: u16,
    x87_fop: u16,
    x87_ds: u16,
    x87_cs: u16,
    x87_rip: u64,
    fpreg_x87: [u8; 80],
    fpreg_xmm: [u8; 256],
    fpreg_ymm: [u8; 256],

    reserved13: [u8; 2448],
}

macro_rules! vmsa_seg_fns {
    ($name: ident) => {
        paste! {
            pub fn [<$name _selector>](&self) -> u16 {
                self.$name.selector
            }
            pub fn [<set_ $name _selector>](&mut self, value: u16) {
                self.$name.selector = value;
            }
            pub fn [<$name _rtype>](&self) -> u16 {
                self.$name.rtype
            }
            pub fn [<set_ $name _rtype>](&mut self, value: u16) {
                self.$name.rtype = value;
            }
            pub fn [<$name _limit>](&self) -> u32 {
                self.$name.limit
            }
            pub fn [<set_ $name _limit>](&mut self, value: u32) {
                self.$name.limit = value;
            }
            pub fn [<$name _base>](&self) -> u64 {
                self.$name.base
            }
            pub fn [<set_ $name _base>](&mut self, value: u64) {
                self.$name.base = value;
            }
        }
    };
}

impl Vmsa {
    vmsa_seg_fns!(cs);
    vmsa_seg_fns!(ds);
    vmsa_seg_fns!(es);
    vmsa_seg_fns!(fs);
    vmsa_seg_fns!(gs);
    vmsa_seg_fns!(ss);

    vmsa_seg_fns!(gdtr);
    vmsa_seg_fns!(idtr);
    vmsa_seg_fns!(ldtr);
    vmsa_seg_fns!(tr);

    funcs!(cr0, u64);
    funcs!(cr3, u64);
    funcs!(cr4, u64);
    funcs!(dr6, u64);
    funcs!(dr7, u64);
    funcs!(efer, u64);
    funcs!(gpat, u64);
    funcs!(mxcsr, u32);
    funcs!(vmpl, u8);
    funcs!(rax, u64);
    funcs!(rbx, u64);
    funcs!(rcx, u64);
    funcs!(rdx, u64);
    funcs!(rsi, u64);
    funcs!(rdi, u64);
    funcs!(r8, u64);
    funcs!(r9, u64);
    funcs!(r10, u64);
    funcs!(r11, u64);
    funcs!(r12, u64);
    funcs!(r13, u64);
    funcs!(r14, u64);
    funcs!(r15, u64);
    funcs!(rip, u64);
    funcs!(rflags, u64);
    funcs!(sev_features, u64);
    funcs!(guest_exitcode, u64);
    funcs!(xcr0, u64);
    funcs!(xss, u64);
    funcs!(x87_fcw, u16);
    funcs!(x87_ftw, u16);

    pub fn efer_offset(&self) -> u64 {
        offset_of!(Vmsa, efer) as u64
    }
}

#[inline]
#[allow(dead_code)]
fn vmsa_size_check() {
    STATIC_ASSERT!(size_of::<Vmsa>() == PAGE_SIZE as usize);
}

unsafe fn update_vmsa_efer_svme(va: VirtAddr, svme: bool) -> bool {
    flush(va);
    BARRIER!();

    let vmsa: *mut Vmsa = va.as_mut_ptr();
    let efer_va: u64 = va.as_u64() + (*vmsa).efer_offset();

    let cur_efer: u64 = (*vmsa).efer();
    let new_efer: u64 = match svme {
        true => cur_efer | EFER_SVME,
        false => cur_efer & !EFER_SVME,
    };

    let xchg_efer: u64 = cmpxchg(cur_efer, new_efer, efer_va);
    BARRIER!();

    // If the cmpxchg() succeeds, xchg_efer will have the cur_efer value,
    // otherwise, it will have the new_efer value.
    xchg_efer == cur_efer
}

pub fn vmsa_clear_efer_svme(va: VirtAddr) -> bool {
    unsafe { update_vmsa_efer_svme(va, false) }
}

pub fn vmsa_set_efer_svme(va: VirtAddr) -> bool {
    unsafe { update_vmsa_efer_svme(va, true) }
}
