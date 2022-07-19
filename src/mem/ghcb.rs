/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::percpu::PERCPU;
use crate::cpu::percpu_count;
use crate::cpu::vc_register_ghcb;
use crate::cpu::vc_terminate;
use crate::dynam::mem_allocate_frames;
use crate::globals::*;
use crate::mem::pgtable_make_pages_shared;
use crate::mem::pgtable_pa_to_va;
use crate::BIT;
use crate::STATIC_ASSERT;

use core::intrinsics::size_of;
use core::ptr::copy_nonoverlapping;
use memoffset::offset_of;
use paste::paste;
use x86_64::structures::paging::PhysFrame;
use x86_64::VirtAddr;

/// 1
pub const GHCB_VERSION_1: u16 = 1;
/// 0
pub const GHCB_USAGE: u32 = 0;

/// 2032
pub const SHARED_BUFFER_SIZE: usize = 2032;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct Ghcb {
    reserved1: [u8; 203],
    cpl: u8,
    reserved2: [u8; 300],
    rax: u64,
    reserved3: [u8; 264],
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved4: [u8; 112],
    sw_exit_code: u64,
    sw_exit_info_1: u64,
    sw_exit_info_2: u64,
    sw_scratch: u64,
    reserved5: [u8; 56],
    xcr0: u64,
    valid_bitmap: [u8; 16],
    reserved6: [u8; 1024],
    shared_buffer: [u8; SHARED_BUFFER_SIZE],
    reserved7: [u8; 10],
    version: u16,
    usage: u32,
}

macro_rules! ghcb_fns {
    ($name: ident) => {
        paste! {
            pub fn [<$name>](&self) -> u64 {
                self.$name
            }
            pub fn [<set_ $name>](&mut self, value: u64) {
                self.$name = value;
                self.set_offset_valid(offset_of!(Ghcb, $name));
            }
            pub fn [<is_ $name _valid>](&self) -> bool {
                self.is_offset_valid(offset_of!(Ghcb, $name))
            }
        }
    };
}

impl Ghcb {
    ghcb_fns!(rax);
    ghcb_fns!(rbx);
    ghcb_fns!(rcx);
    ghcb_fns!(rdx);
    ghcb_fns!(xcr0);
    ghcb_fns!(sw_exit_code);
    ghcb_fns!(sw_exit_info_1);
    ghcb_fns!(sw_exit_info_2);
    ghcb_fns!(sw_scratch);

    pub fn shared_buffer(&mut self, data: *mut u8, len: usize) {
        assert!(len <= SHARED_BUFFER_SIZE);

        unsafe {
            copy_nonoverlapping(&self.shared_buffer as *const u8, data, len);
        }
    }

    pub fn set_shared_buffer(&mut self, data: *const u8, len: usize) {
        assert!(len <= SHARED_BUFFER_SIZE);

        unsafe {
            copy_nonoverlapping(data, &mut self.shared_buffer as *mut u8, len);
        }

        self.set_sw_scratch(&self.shared_buffer as *const u8 as u64);
    }

    pub fn version(&mut self) -> u16 {
        self.version
    }

    pub fn set_version(&mut self, version: u16) {
        self.version = version;
    }

    pub fn usage(&mut self) -> u32 {
        self.usage
    }

    pub fn set_usage(&mut self, usage: u32) {
        self.usage = usage;
    }

    pub fn clear(&mut self) {
        self.sw_exit_code = 0;
        self.valid_bitmap.iter_mut().for_each(|i| *i = 0);
    }

    fn set_offset_valid(&mut self, offset: usize) {
        let idx: usize = (offset / 8) / 8;
        let bit: usize = (offset / 8) % 8;

        self.valid_bitmap[idx] |= BIT!(bit);
    }

    fn is_offset_valid(&self, offset: usize) -> bool {
        let idx: usize = (offset / 8) / 8;
        let bit: usize = (offset / 8) % 8;

        (self.valid_bitmap[idx] & BIT!(bit)) != 0
    }
}

pub fn ghcb_init() {
    STATIC_ASSERT!(size_of::<Ghcb>() == PAGE_SIZE as usize);

    let count: usize = percpu_count();
    let frame: PhysFrame = match mem_allocate_frames(count as u64) {
        Some(f) => f,
        None => vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_ENOMEM),
    };
    let mut va: VirtAddr = pgtable_pa_to_va(frame.start_address());

    pgtable_make_pages_shared(va, count as u64 * PAGE_SIZE);
    unsafe {
        PERCPU.set_ghcb(va);
    }

    vc_register_ghcb(frame.start_address());

    for i in 1..count {
        va += PAGE_SIZE;
        unsafe {
            PERCPU.set_ghcb_for(va, i);
        }
    }
}
