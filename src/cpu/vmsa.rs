/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::funcs;
use crate::globals::*;
use crate::STATIC_ASSERT;

use core::intrinsics::size_of;
use memoffset::offset_of;
use paste::paste;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct VmsaSegmentRegister {
    selector: u16,
    rtype: u16,
    limit: u32,
    base: u64,
}

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

    reserved10: [u8; 16],

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
