/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use paste::paste;

macro_rules! cpuid_fns {
    ($name: ident, $type: ty) => {
        paste! {
            pub fn [<$name>](&self) -> $type {
                self.$name
            }
        }
    };
}

/// 64
pub const CPUID_COUNT_MAX: usize = 64;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct CpuidPageEntry {
    eax_in: u32,
    ecx_in: u32,
    xcr0_in: u64,
    xss_in: u64,

    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    reserved1: [u8; 8],
}

impl CpuidPageEntry {
    cpuid_fns!(eax_in, u32);
    cpuid_fns!(ecx_in, u32);
    cpuid_fns!(xcr0_in, u64);
    cpuid_fns!(xss_in, u64);

    cpuid_fns!(eax, u32);
    cpuid_fns!(ebx, u32);
    cpuid_fns!(ecx, u32);
    cpuid_fns!(edx, u32);
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct CpuidPage {
    count: u32,
    reserved1: [u8; 12],

    entries: [CpuidPageEntry; CPUID_COUNT_MAX],
}

impl CpuidPage {
    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn entry(&self, index: usize) -> CpuidPageEntry {
        assert!(index < CPUID_COUNT_MAX);
        assert!(index < self.count as usize);

        self.entries[index]
    }
}
