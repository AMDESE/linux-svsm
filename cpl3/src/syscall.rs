/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */
//
// The file src/cpu/syscall.rs takes care of system
// call initialization. We provide here macros to
// wrap system calls requests
//
use core::arch::asm;

#[inline]
pub fn syscall0(id: u32) -> u64 {
    let ret: u64;
    // syscall modifies both rcx and r11
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               options(nostack));
    }

    ret
}

#[inline]
pub fn syscall1(id: u32, p1: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               in("rdi") p1,
               options(nostack));
    }

    ret
}

#[inline]
pub fn syscall2(id: u32, p1: u64, p2: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               in("rdi") p1,
               in("rsi") p2,
               options(nostack));
    }

    ret
}

#[inline]
pub fn syscall3(id: u32, p1: u64, p2: u64, p3: u64) -> u64 {
    let ret: u64;
    // syscall modifies both rcx and r11
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               in("rdi") p1,
               in("rsi") p2,
               in("rdx") p3,
               options(nostack));
    }

    ret
}

// In case of adding system calls with more parameters, this is the order
// in which to fill the registers:
// p4=r10, p5=r8, p6=r9
// We can't pass >6 params without using the stack
// Don't forget to include the call in system_call!() too.

///
/// System call macro. Example of usage:
/// system_call!(CALL_ID, param1)
///
#[macro_export]
macro_rules! system_call {
    ($id: expr) => {
        syscall0($id)
    };

    ($id: expr, $param_1:expr) => {
        syscall1($id, $param_1 as u64)
    };
    ($id: expr, $param_1:expr, $param_2:expr) => {
        syscall2($id, $param_1 as u64, $param_2 as u64)
    };

    ($id: expr, $param_1:expr, $param_2:expr, $param_3:expr) => {
        syscall3($id, $param_1 as u64, $param_2 as u64, $param_3 as u64)
    };
}
