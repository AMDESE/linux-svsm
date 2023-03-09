/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::BIT;
use core::arch::asm;

/// Bit 12
pub const EFER_SVME: u64 = BIT!(12);

/// Read MSR
pub fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;

    unsafe {
        asm!("rdmsr",
             in("rcx") msr, out("rax") lo, out("rdx") hi,
             options(nostack));
    }

    ((hi as u64) << 32) | lo as u64
}

/// Write to MSR a given value
pub fn wrmsr(msr: u32, value: u64) {
    let lo: u32 = value as u32;
    let hi: u32 = (value >> 32) as u32;

    unsafe {
        asm!("wrmsr",
             in("rcx") msr, in("rax") lo, in("rdx") hi,
             options(nostack));
    }
}

/// Execute assembly pause instruction
pub fn pause() {
    unsafe {
        asm!("pause", options(nostack));
    }
}

/// Execute assembly hlt instruction (yielding)
pub fn halt() {
    unsafe {
        asm!("hlt", options(nostack));
    }
}

/// 1
pub const PVALIDATE_FAIL_INPUT: u32 = 1;
/// 6
pub const PVALIDATE_FAIL_SIZE_MISMATCH: u32 = 6;

/// 15
pub const PVALIDATE_RET_MAX: u32 = 15;
/// 16
pub const PVALIDATE_CF_SET: u32 = 16;
/// 17
pub const PVALIDATE_RET_ERR: u32 = 17;

/// Pvalidate a given memory region
pub fn pvalidate(va: u64, page_size: u32, validation: u32) -> u32 {
    let mut ret: u32;
    let mut carry: u32;

    unsafe {
        asm!(".byte 0xf2,0x0f,0x01,0xff",
             "xor rcx, rcx",
             "jnc 1f",
             "inc rcx",
             "1:",
             in("rax") va, in("rcx") page_size, in("rdx") validation,
             lateout("rax") ret, lateout("rcx") carry,
             options(nostack));
    }

    if ret > PVALIDATE_RET_MAX {
        ret = PVALIDATE_RET_ERR;
    } else if ret == 0 && carry > 0 {
        ret = PVALIDATE_CF_SET;
    }

    ret
}

/// 1
pub const RMPADJUST_FAIL_INPUT: u32 = 1;
/// 2
pub const RMPADJUST_FAIL_PERMISSION: u32 = 2;
/// 6
pub const RMPADJUST_FAIL_SIZE_MISMATCH: u32 = 6;

/// Update RMP (Reverse Map Table) with new attributes
pub fn rmpadjust(va: u64, page_size: u32, attrs: u64) -> u32 {
    let ret: u32;

    unsafe {
        asm!(".byte 0xf3,0x0f,0x01,0xfe",
             in("rax") va, in("rcx") page_size, in("rdx") attrs,
             lateout("rax") ret,
             options(nostack));
    }

    ret
}

/// Flush everything for the ASID, including Global entries
pub fn invlpgb_all() {
    let rax: u32 = BIT!(3);

    unsafe {
        asm!(".byte 0x0f,0x01,0xfe",
             in("rax") rax, in("rcx") 0, in("rdx") 0,
             options(nostack));
    }
}

pub fn tlbsync() {
    unsafe {
        asm!(".byte 0x0f,0x01,0xff", options(nostack));
    }
}

/// Compare and exchange
pub fn cmpxchg(cmpval: u64, newval: u64, va: u64) -> u64 {
    let ret: u64;

    unsafe {
        asm!("lock cmpxchg [{0}], {1}",
             in(reg) va, in(reg) newval, in("rax") cmpval,
             lateout("rax") ret,
             options(nostack));
    }

    ret
}
