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
        let pa: PhysAddr = match PGTABLE.lock().unmap(page) {
            Ok(r) => r.0.start_address(),
            Err(_e) => vc_terminate_svsm_page_err(),
        };

        let map_pa: PhysAddr;
        if page_type == PageType::Private {
            map_pa = PhysAddr::new(pa.as_u64() | get_sev_encryption_mask());
        } else {
            map_pa = PhysAddr::new(pa.as_u64() & !get_sev_encryption_mask());
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

fn __print_pte(va: VirtAddr) {
    let page: Page<Size4KiB> = page_with_addr(va);
    let translate: TranslateResult = PGTABLE.lock().translate(page.start_address());
    let (frame, flags) = match translate {
        TranslateResult::Mapped {
            frame,
            offset: _,
            flags,
        } => (frame, flags),
        TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => {
            prints!("   Page with va {:#x} is not mapped!\n", va);
            return;
        }
    };

    let bits: u64 = flags.bits();
    let frame: u64 = frame.start_address().as_u64();
    let addr: u64 = va.as_u64();

    prints!(
        "   VA {:#x} mapped to PFN {:#x} with flags {:#x}\n",
        addr,
        frame,
        bits
    );

    if flags & PageTableFlags::NO_EXECUTE != PageTableFlags::NO_EXECUTE {
        prints!("   where NO_EXECUTE is NOT set, ");
    } else {
        prints!("   where NO_EXECUTE is set, ");
    }

    if flags & PageTableFlags::USER_ACCESSIBLE != PageTableFlags::USER_ACCESSIBLE {
        prints!("USER_ACCESSIBLE is NOT set, ");
    } else {
        prints!("USER_ACCESSIBLE is set, ");
    }

    if flags & PageTableFlags::PRESENT != PageTableFlags::PRESENT {
        prints!("PRESENT is NOT set, ");
    } else {
        prints!("PRESENT is set, ");
    }

    if flags & PageTableFlags::WRITABLE != PageTableFlags::WRITABLE {
        prints!("WRITABLE is NOT set.\n");
    } else {
        prints!("WRITABLE is set.\n");
    }
}

/// Print flags of a page given its VA
#[inline]
pub fn pgtable_print_pte_va(va: VirtAddr) {
    __print_pte(va)
}

/// Print flags of a page given its PA
#[inline]
pub fn pgtable_print_pte_pa(pa: PhysAddr) {
    __print_pte(pgtable_pa_to_va(pa))
}

/// Make pages private
///
/// This sets the encryption bit of the page and does not change the
/// underlying data to match. If the page was previously a shared page,
/// the data will appear to the user as ciphertext now.
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
    }
}

/// Make pages shared
///
/// This clears the encryption bit of the page and does not change the
/// underlying data to match. If the page was previously a private page,
/// the data will appear to the user as ciphertext now.
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
    }
}

/// Update flags for a given range of pages
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

/// Make pages accessible from user space
pub fn pgtable_make_pages_user(va: VirtAddr, len: u64) {
    assert!(len != 0);

    let begin: Page = Page::containing_address(va);
    let end: Page = Page::containing_address(va + len - 1_u64);

    let set: PageTableFlags = PageTableFlags::USER_ACCESSIBLE;
    let clr: PageTableFlags = PageTableFlags::empty();
    update_page_flags(Page::range(begin, end + 1), set, clr, true);
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

/// Determine if a current mapping matches the specified frame and flags values
///
/// When comparing the specified flags, the ACCESSED and DIRTY are ignored.
fn page_mapping_matches(va: VirtAddr, mframe: PhysFrame, mflags: PageTableFlags) -> bool {
    let ignore: PageTableFlags = PageTableFlags::ACCESSED | PageTableFlags::DIRTY;

    let use_mapping: bool = match PGTABLE.lock().translate(va) {
        TranslateResult::Mapped {
            frame,
            offset: _,
            flags,
        } => {
            mframe.start_address() == frame.start_address()
                && (mflags & !ignore) == (flags & !ignore)
        }
        TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => false,
    };

    use_mapping
}

unsafe fn __map_pages(
    pa: PhysAddr,
    len: u64,
    page_type: PageType,
) -> Result<VirtAddr, MapToError<Size4KiB>> {
    assert!(len != 0);

    let mut map: PhysAddr = pa.align_down(PAGE_SIZE);
    let map_end: PhysAddr = PhysAddr::new(pa.as_u64() + len - 1_u64).align_down(PAGE_SIZE) + 1_u64;

    let entry_flags: PageTableFlags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let table_flags: PageTableFlags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let mut allocator: PageTableAllocator = PageTableAllocator::new();

    let pa_mod: u64 = match page_type {
        PageType::Shared => 0,
        PageType::Private => get_sev_encryption_mask(),
    };

    while map < map_end {
        let va: VirtAddr = pgtable_pa_to_va(map);
        let private_pa: PhysAddr = PhysAddr::new(map.as_u64() | pa_mod);

        let page: Page<Size4KiB> = Page::containing_address(va);
        let frame: PhysFrame = PhysFrame::from_start_address_unchecked(private_pa);

        let result: Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>> = PGTABLE
            .lock()
            .map_to_with_table_flags(page, frame, entry_flags, table_flags, &mut allocator);
        match result {
            Ok(r) => r.flush(),
            Err(e) => match e {
                MapToError::PageAlreadyMapped(_) => {
                    if !page_mapping_matches(va, frame, entry_flags) {
                        if !pgtable_unmap_pages(va, PAGE_SIZE) {
                            vc_terminate_svsm_page_err();
                        }

                        continue;
                    }
                }
                _ => {
                    return Err(e);
                }
            },
        }

        map += PAGE_SIZE;
    }

    Ok(pgtable_pa_to_va(pa))
}

unsafe fn __pgtable_init(flags: PageTableFlags, allocator: &mut PageTableAllocator) {
    let mut va: VirtAddr = get_svsm_begin();
    let va_end: VirtAddr = get_svsm_end();

    while va < va_end {
        let pa: PhysAddr = pgtable_va_to_pa(va);
        let private_pa: PhysAddr = PhysAddr::new(pa.as_u64() | get_sev_encryption_mask());

        let page: Page<Size4KiB> = page_with_addr(va);
        let frame: PhysFrame = PhysFrame::from_start_address_unchecked(private_pa);

        let result: Result<MapperFlush<Size4KiB>, MapToError<Size4KiB>> = PGTABLE
            .lock()
            .map_to_with_table_flags(page, frame, flags, flags, allocator);
        if result.is_err() {
            vc_terminate_ghcb_general();
        }

        va += PAGE_SIZE;
    }

    // Change the early GHCB to shared for use before a new one is created
    let va: VirtAddr = get_early_ghcb();
    let page: Page<Size4KiB> = page_with_addr(va);
    remap_page(page, PageType::Shared, false);

    // Mark the BSS and DATA sections as non-executable
    let mut set: PageTableFlags = PageTableFlags::NO_EXECUTE;
    let mut clr: PageTableFlags = PageTableFlags::empty();

    let mut page_begin: Page<Size4KiB> = page_with_addr(get_svsm_sbss());
    let mut page_end: Page<Size4KiB> = page_with_addr(get_svsm_ebss());
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    page_begin = page_with_addr(get_svsm_sdata());
    page_end = page_with_addr(get_svsm_edata());
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    page_begin = page_with_addr(get_dyn_mem_begin());
    page_end = page_with_addr(get_dyn_mem_end());
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    // Mark the BSP stack guard page as non-present
    set = PageTableFlags::empty();
    clr = PageTableFlags::PRESENT;

    page_begin = page_with_addr(get_guard_page());
    page_end = page_begin + 1;
    update_page_flags(Page::range(page_begin, page_end), set, clr, false);

    // Use the new page table
    let cr3: PhysFrame = PhysFrame::containing_address(PhysAddr::new(
        &P4 as *const PageTable as u64 | get_sev_encryption_mask(),
    ));
    Cr3::write(cr3, Cr3Flags::empty());
}

/// Unmap pages
pub fn pgtable_unmap_pages(va: VirtAddr, len: u64) -> bool {
    assert!(len != 0);

    let mut map: VirtAddr = va.align_down(PAGE_SIZE);
    let map_end: VirtAddr = VirtAddr::new(va.as_u64() + len - 1_u64).align_down(PAGE_SIZE) + 1_u64;

    while map < map_end {
        let page: Page<Size4KiB> = Page::containing_address(map);

        let result: Result<(PhysFrame<Size4KiB>, MapperFlush<Size4KiB>), UnmapError> =
            PGTABLE.lock().unmap(page);
        match result {
            Ok((_f, r)) => r.flush(),
            Err(e) => {
                let v: u64 = map.as_u64();
                prints!("pgtable_unmap_pages error: {:#x} => {:?}\n", v, e);

                return false;
            }
        }

        map += PAGE_SIZE;
    }

    true
}

/// Map pages as private
///
/// If a previous mapping exists and does not conform to the new mapping, the
/// previous mapping is replaced by the new mapping.
pub fn pgtable_map_pages_private(pa: PhysAddr, len: u64) -> Result<VirtAddr, MapToError<Size4KiB>> {
    unsafe { __map_pages(pa, len, PageType::Private) }
}

/// Map pages as shared
pub fn pgtable_map_pages_shared(pa: PhysAddr, len: u64) -> Result<VirtAddr, MapToError<Size4KiB>> {
    unsafe { __map_pages(pa, len, PageType::Shared) }
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
