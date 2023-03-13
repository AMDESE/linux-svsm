/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::prints;
use core::arch::asm;

/// Generate set/get methods for a given struct field and type
#[macro_export]
macro_rules! funcs {
    ($name: ident, $T: ty) => {
        paste::paste! {
            pub fn [<$name>](&self) -> $T {
                self.$name
            }
            pub fn [<set_ $name>](&mut self, value: $T) {
                self.$name = value;
            }
        }
    };
}

/// Generate get method for a given struct field and type
#[macro_export]
macro_rules! getter_func {
    ($name: ident, $T: ty) => {
        paste::paste! {
            pub fn [<$name>](&self) -> $T {
                self.$name
            }
        }
    };
}

/// Statically check for a condition
#[macro_export]
macro_rules! STATIC_ASSERT {
    ($x: expr) => {
        const _: () = core::assert!($x);
    };
}

/// Obtain bit for a given position
#[macro_export]
macro_rules! BIT {
    ($x: expr) => {
        (1 << ($x))
    };
}

/// Retrieve 8 least significant bits
#[macro_export]
macro_rules! LOWER_8BITS {
    ($x: expr) => {
        (($x) as u8 & 0xff)
    };
}

/// Retrieve 16 least significant bits
#[macro_export]
macro_rules! LOWER_16BITS {
    ($x: expr) => {
        (($x) as u16 & 0xffff)
    };
}

/// Retrieve 32 least significant bits
#[macro_export]
macro_rules! LOWER_32BITS {
    ($x: expr) => {
        (($x) as u32 & 0xffffffff)
    };
}

/// Retrieve 32 most significant bits
#[macro_export]
macro_rules! UPPER_32BITS {
    ($x: expr) => {
        (($x >> 32) as u32 & 0xffffffff)
    };
}

/// Align value to a given size
#[macro_export]
macro_rules! ALIGN {
    ($x: expr, $y: expr) => {
        ((($x) + ($y) - 1) & !(($y) - 1))
    };
}

/// Check if x is aligned to y
#[macro_export]
macro_rules! ALIGNED {
    ($x: expr, $y: expr) => {
        ($x == ALIGN!(($x), ($y)))
    };
}

/// Check if address is 2MB aligned
#[macro_export]
macro_rules! PAGE_2MB_ALIGNED {
    ($x: expr) => {
        ALIGNED!($x, PAGE_2MB_SIZE)
    };
}

/// Retrieve number of pages that a given value contains
#[macro_export]
macro_rules! PAGE_COUNT {
    ($x: expr) => {
        (ALIGN!(($x), PAGE_SIZE) >> PAGE_SHIFT)
    };
}

/// Make sure threads are sequentially consistent
#[macro_export]
macro_rules! BARRIER {
    () => {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst)
    };
}

pub fn memset(dst: *mut u8, val: u8, len: usize) {
    unsafe {
        core::intrinsics::write_bytes(dst, val, len);
    }
}

/// Infinite loop that updates rsi (debugging purposes)
#[inline]
pub fn loop_rsi(val: u64) {
    unsafe {
        asm!("2: jmp 2b", in("rsi") val);
    }
}

#[inline]
pub fn breakpoint() {
    prints!("\nDebug breakpoint\n");
    loop_rsi(0xdeb);
}
