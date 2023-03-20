/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use x86_64::structures::paging::PhysFrame;
use x86_64::PhysAddr;

use crate::*;

#[repr(C, packed)]
pub struct Ca {
    call_pending: u8,
    mem_available: u8,
    reserved1: [u8; 6],
}

impl Ca {
    funcs!(call_pending, u8);
    funcs!(mem_available, u8);
}

pub fn is_in_calling_area(gpa: PhysAddr) -> bool {
    let gfn: PhysFrame = PhysFrame::containing_address(gpa);
    let caa_gpa: PhysAddr = unsafe { PERCPU.caa(VMPL::Vmpl1) };
    let caa_gfn: PhysFrame = PhysFrame::containing_address(caa_gpa);
    gfn == caa_gfn
}
