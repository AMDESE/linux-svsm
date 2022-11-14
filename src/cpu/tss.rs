/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::mem::pgtable::*;
use crate::*;
use core::intrinsics::size_of;
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::SegmentSelector;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

// Index of the IST for #DF
/// 0
pub const DOUBLE_FAULT_IST: usize = 0;

// 2 stack pages and 1 guard page
/// 3
const IST_STACK_PAGES: u64 = 3;

unsafe fn create_tss() -> VirtAddr {
    let tss_va: VirtAddr = match mem_allocate(size_of::<TaskStateSegment>()) {
        Ok(f) => f,
        Err(()) => vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_ENOMEM),
    };

    let tss: *mut TaskStateSegment = tss_va.as_mut_ptr();
    let tss_template: TaskStateSegment = TaskStateSegment::new();

    // Make sure we have correct initial values
    *tss = tss_template;

    let frame: PhysFrame = match mem_allocate_frames(IST_STACK_PAGES) {
        Some(f) => f,
        None => vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_ENOMEM),
    };

    let guard_va: VirtAddr = pgtable_pa_to_va(frame.start_address());
    let stack_va: VirtAddr = pgtable_pa_to_va((frame + 1).start_address());

    // Protect guard page and make stack non executable
    pgtable_make_pages_np(guard_va, PAGE_SIZE);
    pgtable_make_pages_nx(stack_va, (IST_STACK_PAGES - 1) * PAGE_SIZE);

    let stack: VirtAddr = pgtable_pa_to_va((frame + IST_STACK_PAGES).start_address());

    (*tss).interrupt_stack_table[DOUBLE_FAULT_IST] = stack;

    tss_va
}

unsafe fn __tss_init() {
    let tss: VirtAddr = create_tss();
    let tss_base: u64 = tss.as_u64();
    let tss_limit: u64 = (size_of::<TaskStateSegment>() - 1) as u64;

    let gdt_tss0: *mut u64 = early_tss as *mut u64;
    let gdt_tss1: *mut u64 = (early_tss + 8) as *mut u64;

    // Update existing TSS entry in the GDT.

    *gdt_tss0 = (SVSM_TSS_TYPE as u64) << 40;
    *gdt_tss0 |= (tss_base & 0xff000000) << 32;
    *gdt_tss0 |= (tss_base & 0x00ffffff) << 16;
    *gdt_tss0 |= tss_limit;

    *gdt_tss1 = tss_base >> 32;

    PERCPU.set_tss(tss);

    load_tss(SegmentSelector(SVSM_TSS_SELECTOR));
}

///
/// Create new TSS for a given CPU, but don't load it.
/// Used by AP creation where the VMSA can be used to pre-set the
/// task register (TR) with the TSS values
///
pub fn tss_init_for(cpu_id: usize) -> VirtAddr {
    let tss: VirtAddr;

    unsafe {
        tss = create_tss();
        PERCPU.set_tss_for(tss, cpu_id);
    }

    tss
}

/// Create and load TSS.
/// Only used by the BSP, since APs can use tss_init_for()
pub fn tss_init() {
    unsafe {
        __tss_init();
    }
}
