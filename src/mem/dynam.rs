/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::vc_early_make_pages_private;
use crate::dyn_mem_begin;
use crate::dyn_mem_end;
use crate::globals::*;
use crate::mem::pgtable_pa_to_va;
use crate::util::locking::{LockGuard, SpinLock};

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::ptr;
use x86_64::addr::{align_down, PhysAddr};
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::structures::paging::page::Size4KiB;

#[derive(Clone, Debug)]
pub struct SvsmAllocator {
    // Heap
    top: u64,
    bot: u64,
    cur: u64,
}

impl SvsmAllocator {
    pub const fn new() -> Self {
        SvsmAllocator {
            top: 0,
            bot: 0,
            cur: 0,
        }
    }

    /// Initialize SVSM allocator, providing initial and last physical frames
    /// # Safety
    /// The begin and end frames better be within the SVSM's assigned memslot
    pub unsafe fn init(&mut self, begin: PhysFrame<Size4KiB>, end: PhysFrame<Size4KiB>) {
        self.top = end.start_address().as_u64();
        self.bot = begin.start_address().as_u64();
        self.cur = self.top;
    }

    /// Obtain available PA for a given size and alignment allocation
    pub unsafe fn allocate_mem(&mut self, size: u64, align: u64) -> u64 {
        let pa: u64 = align_down(self.cur - size, align);
        if pa < self.bot {
            return 0;
        }

        self.cur = pa;

        pa
    }

    pub unsafe fn allocate_frames(&mut self, count: u64) -> Option<PhysFrame> {
        let pa: u64 = self.allocate_mem(count * PAGE_SIZE, PAGE_SIZE);

        if pa == 0 {
            return None;
        }

        let frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(PhysAddr::new(pa));
        Some(frame)
    }

    pub unsafe fn allocate_frame(&mut self) -> Option<PhysFrame> {
        self.allocate_frames(1)
    }
}

unsafe impl GlobalAlloc for SpinLock<SvsmAllocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap: LockGuard<SvsmAllocator> = self.lock();
        let pa: u64 = heap.allocate_mem(layout.size() as u64, layout.align() as u64);
        if pa == 0 {
            return ptr::null_mut();
        }

        pa as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("Allocation failed: {:?}\n", layout)
}

#[global_allocator]
static ALLOCATOR: SpinLock<SvsmAllocator> = SpinLock::new(SvsmAllocator::new());

pub fn mem_free_frames(_frame: PhysFrame, _count: u64) {}

pub fn mem_free_frame(frame: PhysFrame) {
    mem_free_frames(frame, 1)
}

pub fn mem_allocate_frames(count: u64) -> Option<PhysFrame> {
    unsafe {
        let frame: Option<PhysFrame> = ALLOCATOR.lock().allocate_frames(count);
        match frame {
            Some(f) => {
                let dst: *mut u8 = pgtable_pa_to_va(f.start_address()).as_mut_ptr();
                core::intrinsics::write_bytes(dst, 0, (PAGE_SIZE * count) as usize);
            }
            None => return None,
        }

        frame
    }
}

pub fn mem_allocate_frame() -> Option<PhysFrame> {
    mem_allocate_frames(1)
}

/// Initialize allocator, that will use the region devoted to dynamic memory
/// allocations (Heap). Mark its pages as private.
pub fn mem_init() {
    let mem_begin: PhysFrame;
    let mem_end: PhysFrame;

    unsafe {
        mem_begin = PhysFrame::containing_address(PhysAddr::new(dyn_mem_begin));
        mem_end = PhysFrame::containing_address(PhysAddr::new(dyn_mem_end));
    }

    vc_early_make_pages_private(mem_begin, mem_end);

    unsafe {
        ALLOCATOR.lock().init(mem_begin, mem_end);
    }
}
