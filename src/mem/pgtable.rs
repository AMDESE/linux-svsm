/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::vc::*;
use crate::cpu::vc_make_page_private;
use crate::cpu::vc_make_page_shared;
use crate::cpu::vc_terminate;
use crate::globals::*;
use crate::mem::mem_allocate_frame;
use crate::util::locking::SpinLock;
use crate::*;

use lazy_static::lazy_static;
use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::structures::paging::mapper::{
    FlagUpdateError, MapToError, MapperFlush, TranslateResult, UnmapError,
};
use x86_64::structures::paging::page::Page;
use x86_64::structures::paging::page::{PageRange, Size4KiB};
use x86_64::structures::paging::*;

static OFFSET: VirtAddr = VirtAddr::zero();
static mut P4: PageTable = PageTable::new();

lazy_static! {
    static ref PGTABLE: SpinLock<OffsetPageTable<'static>> = {
        unsafe {
            let pgt: OffsetPageTable = OffsetPageTable::new(&mut P4, OFFSET);
            SpinLock::new(pgt)
        }
    };
}

#[derive(Copy, Clone, Debug)]
struct PageTableAllocator {}

impl PageTableAllocator {
    pub const fn new() -> Self {
        PageTableAllocator {}
    }
}

unsafe impl FrameAllocator<Size4KiB> for PageTableAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        mem_allocate_frame()
    }
}

impl FrameDeallocator<Size4KiB> for PageTableAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame) {
        mem_free_frame(frame)
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum PageType {
    Private,
    Shared,
}

fn remap_page(page: Page, page_type: PageType, flush: bool) {
    let flags: PageTableFlags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let mut allocator: PageTableAllocator = PageTableAllocator::new();

    unsafe {
        let mut pa: PhysAddr = PhysAddr::new(0);

        let result: Result<(PhysFrame<Size4KiB>, MapperFlush<Size4KiB>), UnmapError> =
            PGTABLE.lock().unmap(page);
        match result {
            Ok(r) => pa = r.0.start_address(),
            Err(_e) => vc_terminate_svsm_page_err(),
        }

        let map_pa: PhysAddr;
        if page_type == PageType::Private {
            map_pa = PhysAddr::new(pa.as_u64() | sev_encryption_mask);
        } else {
            map_pa = PhysAddr::new(pa.as_u64() & !sev_encryption_mask);
        }
        let frame: PhysFrame = PhysFrame::from_start_address_unchecked(map_pa);

        let result: Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>> = PGTABLE
            .lock()
            .map_to_with_table_flags(page, frame, flags, flags, &mut allocator);
        match result {
            Ok(r) => {
                if flush {
                    r.flush();
                }
            }
            Err(_e) => vc_terminate_svsm_page_err(),
        }
    }
}

/// Make pages private (updating flags)
pub fn pgtable_make_pages_private(va: VirtAddr, len: u64) {
    assert!(len != 0);

    let begin: Page = Page::containing_address(va);
    let end: Page = Page::containing_address(va + len - 1_u64);
    let page_range: PageRange = Page::range(begin, end + 1);

    for page in page_range {
        let page_pa: PhysAddr = pgtable_va_to_pa(page.start_address());
        let page_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(page_pa);

        remap_page(page, PageType::Private, true);
        vc_make_page_private(page_frame);

        unsafe {
            let dst: *mut u8 = begin.start_address().as_mut_ptr();
            core::intrinsics::write_bytes(dst, 0, PAGE_SIZE as usize);
        }
    }
}

/// Make pages shared via VC
pub fn pgtable_make_pages_shared(va: VirtAddr, len: u64) {
    assert!(len != 0);

    let begin: Page = Page::containing_address(va);
    let end: Page = Page::containing_address(va + len - 1_u64);
    let page_range: PageRange = Page::range(begin, end + 1);

    for page in page_range {
        let page_pa: PhysAddr = pgtable_va_to_pa(page.start_address());
        let page_frame: PhysFrame<Size4KiB> = PhysFrame::containing_address(page_pa);

        vc_make_page_shared(page_frame);
        remap_page(page, PageType::Shared, true);

        unsafe {
            let dst: *mut u8 = begin.start_address().as_mut_ptr();
            core::intrinsics::write_bytes(dst, 0, PAGE_SIZE as usize);
        }
    }
}

fn update_page_flags(page_range: PageRange, set: PageTableFlags, clr: PageTableFlags, flush: bool) {
    for page in page_range {
        unsafe {
            let translate: TranslateResult = PGTABLE.lock().translate(page.start_address());
            let mut flags: PageTableFlags = match translate {
                TranslateResult::Mapped {
                    frame: _,
                    offset: _,
                    flags,
                } => flags,
                TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => {
                    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_SET_PAGE_ERROR)
                }
            };

            flags &= !clr;
            flags |= set;
            let result: Result<MapperFlush<Size4KiB>, FlagUpdateError> =
                PGTABLE.lock().update_flags(page, flags);
            match result {
                Ok(r) => {
                    if flush {
                        r.flush();
                    }
                }
                Err(_e) => vc_terminate_svsm_page_err(),
            }
        }
    }
}

/// Make pages not executable
pub fn pgtable_make_pages_nx(va: VirtAddr, len: u64) {
    assert!(len != 0);

    let begin: Page = Page::containing_address(va);
    let end: Page = Page::containing_address(va + len - 1_u64);

    let set: PageTableFlags = PageTableFlags::NO_EXECUTE;
    let clr: PageTableFlags = PageTableFlags::empty();
    update_page_flags(Page::range(begin, end + 1), set, clr, true);
}

/// Make pages not present
pub fn pgtable_make_pages_np(va: VirtAddr, len: u64) {
    assert!(len != 0);

    let begin: Page = Page::containing_address(va);
    let end: Page = Page::containing_address(va + len - 1_u64);

    let set: PageTableFlags = PageTableFlags::empty();
    let clr: PageTableFlags = PageTableFlags::PRESENT;
    update_page_flags(Page::range(begin, end + 1), set, clr, true);
}

/// Obtain physical address (PA) of a page given its VA
pub fn pgtable_va_to_pa(va: VirtAddr) -> PhysAddr {
    PhysAddr::new(va.as_u64() - OFFSET.as_u64())
}

/// Obtain virtual address (VA) of a page given its PA
pub fn pgtable_pa_to_va(pa: PhysAddr) -> VirtAddr {
    VirtAddr::new(pa.as_u64() + OFFSET.as_u64())
}

#[inline]
fn page_with_addr(va: VirtAddr) -> Page<Size4KiB> {
    Page::containing_address(va)
}

#[inline]
fn page_with_addr_pa(add: u64) -> Page<Size4KiB> {
    page_with_addr(pgtable_pa_to_va(PhysAddr::new(add)))
}

unsafe fn __pgtable_init(flags: PageTableFlags, allocator: &mut PageTableAllocator) {
    let mut pa: PhysAddr = PhysAddr::new(svsm_begin);
    let pa_end: PhysAddr = PhysAddr::new(svsm_end);

    while pa < pa_end {
        let va: VirtAddr = pgtable_pa_to_va(pa);
        let private_pa: PhysAddr = PhysAddr::new(pa.as_u64() | sev_encryption_mask);

        let page: Page<Size4KiB> = page_with_addr(va);
        let frame: PhysFrame = PhysFrame::from_start_address_unchecked(private_pa);

        let result: Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>> = PGTABLE
            .lock()
            .map_to_with_table_flags(page, frame, flags, flags, allocator);
        if result.is_err() {
            vc_terminate_ghcb_general();
        }

        pa += PAGE_SIZE;
    }

    // Change the early GHCB to shared for use before a new one is created
    let va: VirtAddr = pgtable_pa_to_va(PhysAddr::new(early_ghcb));
    let page: Page<Size4KiB> = page_with_addr(va);
    remap_page(page, PageType::Shared, false);

    // Mark the BSS and DATA sections as non-executable
    let mut set: PageTableFlags = PageTableFlags::NO_EXECUTE;
    let mut clr: PageTableFlags = PageTableFlags::empty();

    let mut page_begin: Page<Size4KiB> = page_with_addr_pa(svsm_sbss);
    let mut page_end: Page<Size4KiB> = page_with_addr_pa(svsm_ebss);
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    page_begin = page_with_addr_pa(svsm_sdata);
    page_end = page_with_addr_pa(svsm_edata);
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    page_begin = page_with_addr_pa(dyn_mem_begin);
    page_end = page_with_addr_pa(dyn_mem_end);
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    // Mark the BSP stack guard page as non-present
    set = PageTableFlags::empty();
    clr = PageTableFlags::PRESENT;

    page_begin = page_with_addr_pa(guard_page);
    page_end = page_begin + 1;
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    // Use the new page table
    let cr3: PhysFrame = PhysFrame::containing_address(PhysAddr::new(
        &P4 as *const PageTable as u64 | sev_encryption_mask,
    ));
    Cr3::write(cr3, Cr3Flags::empty());
}

/// Map pages as private
pub fn pgtable_map_pages_private(pa: PhysAddr, len: u64) -> Result<VirtAddr, MapToError<Size4KiB>> {
    assert!(len != 0);

    let mut map: PhysAddr = pa.align_down(PAGE_SIZE);
    let map_end: PhysAddr = PhysAddr::new(pa.as_u64() + len - 1_u64).align_down(PAGE_SIZE) + 1_u64;

    let flags: PageTableFlags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let mut allocator: PageTableAllocator = PageTableAllocator::new();

    unsafe {
        while map < map_end {
            let va: VirtAddr = pgtable_pa_to_va(map);
            let private_pa: PhysAddr = PhysAddr::new(map.as_u64() | sev_encryption_mask);

            let page: Page<Size4KiB> = Page::containing_address(va);
            let _frame: PhysFrame = PhysFrame::from_start_address_unchecked(private_pa);

            let result: Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>> = PGTABLE
                .lock()
                .map_to_with_table_flags(page, _frame, flags, flags, &mut allocator);
            match result {
                Ok(r) => r.flush(),
                Err(e) => {
                    if !core::matches!(e, MapToError::PageAlreadyMapped(_frame)) {
                        return Err(e);
                    }
                }
            }

            map += PAGE_SIZE;
        }
    }

    Ok(pgtable_pa_to_va(pa))
}

/// Generate 4-level page table, update Cr3 accordingly
pub fn pgtable_init() {
    lazy_static::initialize(&PGTABLE);

    let flags: PageTableFlags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let mut allocator: PageTableAllocator = PageTableAllocator::new();
    unsafe {
        __pgtable_init(flags, &mut allocator);
    }
}
