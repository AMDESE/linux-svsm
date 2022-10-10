/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2022 SUSE LLC
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

use crate::cpu::vc_early_make_pages_private;
use crate::dyn_mem_begin;
use crate::dyn_mem_end;
use crate::globals::*;
use crate::mem::{pgtable_pa_to_va, pgtable_va_to_pa};
use crate::util::locking::SpinLock;
use crate::STATIC_ASSERT;
use core::alloc::{GlobalAlloc, Layout};
use core::mem::size_of;
use core::ptr;
use x86_64::addr::{align_up, PhysAddr, VirtAddr};
use x86_64::structures::paging::frame::PhysFrame;

struct PageStorageType(u64);

#[allow(dead_code)]
// The maximum configurable value for MAX_ORDER, equal to supported physical address bits
// In practice anythin more than 10 does not make a lot of sense. Setting 10
// will allow to allocate up to 2MiB of contiguous memory.
/// 52
pub const REAL_MAX_ORDER: usize = 52;

// Maximum allocation size is (2^MAX_ORDER)*PAGE_SIZE
// Currently 128 KiB
/// 6
pub const MAX_ORDER: usize = 6;

impl PageStorageType {
    pub const fn new(t: u64) -> Self {
        PageStorageType(t)
    }

    fn encode_order(&self, order: usize) -> PageStorageType {
        PageStorageType(self.0 | ((order as u64) & PAGE_ORDER_MASK) << PAGE_TYPE_SHIFT)
    }

    fn encode_next(&self, next_page: usize) -> PageStorageType {
        PageStorageType(self.0 | (next_page as u64) << PAGE_FREE_NEXT_SHIFT)
    }

    fn encode_slab(slab: VirtAddr) -> Self {
        PageStorageType(PAGE_TYPE_SLABPAGE | slab.as_u64() & PAGE_TYPE_SLABPAGE_MASK)
    }
}

/// 4
const PAGE_TYPE_SHIFT: u64 = 4;
/// 0xf
const PAGE_TYPE_MASK: u64 = (1u64 << PAGE_TYPE_SHIFT) - 1;
/// 0
const PAGE_TYPE_FREE: u64 = 0;
/// 12
const PAGE_FREE_NEXT_SHIFT: u64 = 12;
/// 0xffff_ffff_ffff_f000
const PAGE_FREE_NEXT_MASK: u64 = !((1u64 << PAGE_FREE_NEXT_SHIFT) - 1);

/// 1
const PAGE_TYPE_ALLOCATED: u64 = 1;
/// 0xff
const PAGE_ORDER_MASK: u64 = (1u64 << (PAGE_FREE_NEXT_SHIFT - PAGE_TYPE_SHIFT)) - 1;

// SLAB pages are always order-0
/// 2
const PAGE_TYPE_SLABPAGE: u64 = 2;
/// 0xffff_ffff_ffff_fff0
const PAGE_TYPE_SLABPAGE_MASK: u64 = !PAGE_TYPE_MASK;

/// 3
const PAGE_TYPE_COMPOUND: u64 = 3;
/// 0xf
const PAGE_TYPE_RESERVED: u64 = (1u64 << PAGE_TYPE_SHIFT) - 1;

struct FreeInfo {
    next_page: usize,
    order: usize,
}

impl FreeInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_FREE)
            .encode_order(self.order)
            .encode_next(self.next_page)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        let next: usize = ((mem.0 & PAGE_FREE_NEXT_MASK) >> PAGE_FREE_NEXT_SHIFT) as usize;
        let order: usize = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        FreeInfo {
            next_page: next,
            order: order,
        }
    }
}

struct AllocatedInfo {
    order: usize,
}

impl AllocatedInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_ALLOCATED).encode_order(self.order)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        let order: usize = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK)
            .try_into()
            .unwrap();
        AllocatedInfo { order: order }
    }
}

struct SlabPageInfo {
    slab: VirtAddr,
}

impl SlabPageInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::encode_slab(self.slab)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        SlabPageInfo {
            slab: VirtAddr::new(mem.0 & PAGE_TYPE_SLABPAGE_MASK),
        }
    }
}

struct CompoundInfo {
    order: usize,
}

impl CompoundInfo {
    pub fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_COMPOUND).encode_order(self.order)
    }

    pub fn decode(mem: PageStorageType) -> Self {
        let order: usize = ((mem.0 >> PAGE_TYPE_SHIFT) & PAGE_ORDER_MASK) as usize;
        CompoundInfo { order: order }
    }
}

struct ReservedInfo {}

impl ReservedInfo {
    fn encode(&self) -> PageStorageType {
        PageStorageType::new(PAGE_TYPE_RESERVED)
    }

    pub fn decode(_mem: PageStorageType) -> Self {
        ReservedInfo {}
    }
}

enum SvsmPageInfo {
    Free(FreeInfo),
    Allocated(AllocatedInfo),
    SlabPage(SlabPageInfo),
    CompoundPage(CompoundInfo),
    Reserved(ReservedInfo),
}

impl SvsmPageInfo {
    pub fn to_mem(&self) -> PageStorageType {
        match self {
            SvsmPageInfo::Free(fi) => fi.encode(),
            SvsmPageInfo::Allocated(ai) => ai.encode(),
            SvsmPageInfo::SlabPage(si) => si.encode(),
            SvsmPageInfo::CompoundPage(ci) => ci.encode(),
            SvsmPageInfo::Reserved(ri) => ri.encode(),
        }
    }

    pub fn from_mem(mem: PageStorageType) -> Self {
        let page_type: u64 = mem.0 & PAGE_TYPE_MASK;

        if page_type == PAGE_TYPE_FREE {
            SvsmPageInfo::Free(FreeInfo::decode(mem))
        } else if page_type == PAGE_TYPE_ALLOCATED {
            SvsmPageInfo::Allocated(AllocatedInfo::decode(mem))
        } else if page_type == PAGE_TYPE_SLABPAGE {
            SvsmPageInfo::SlabPage(SlabPageInfo::decode(mem))
        } else if page_type == PAGE_TYPE_COMPOUND {
            SvsmPageInfo::CompoundPage(CompoundInfo::decode(mem))
        } else if page_type == PAGE_TYPE_RESERVED {
            SvsmPageInfo::Reserved(ReservedInfo::decode(mem))
        } else {
            panic!("Unknown Page Type {}", page_type);
        }
    }
}

/// Data structure representing a region of allocatable memory
///
/// The memory region must be physically and virtually contiguous and
/// implements a buddy algorithm for page allocations.
///
/// All allocations have a power-of-two size and are naturally aligned
/// (virtually). For allocations to be naturally aligned physically the virtual
/// and physical start addresses must be aligned at MAX_ORDER allocation size.
///
/// The buddy allocator takes some memory for itself to store per-page page
/// meta-data, which is currently 8 bytes per PAGE_SIZE page.
struct MemoryRegion {
    /// Physical start address
    start_phys: PhysAddr,
    /// Virtual start address
    start_virt: VirtAddr,
    /// Total number of PAGE_SIZE
    page_count: usize,
    /// Total number of pages in the region per ORDER
    nr_pages: [usize; MAX_ORDER],
    /// Next free page per ORDER
    next_page: [usize; MAX_ORDER],
    /// Number of free pages per ORDER
    free_pages: [usize; MAX_ORDER],
}

impl MemoryRegion {
    pub const fn new() -> Self {
        MemoryRegion {
            start_phys: PhysAddr::new(0),
            start_virt: VirtAddr::new_truncate(0),
            page_count: 0,
            nr_pages: [0; MAX_ORDER],
            next_page: [0; MAX_ORDER],
            free_pages: [0; MAX_ORDER],
        }
    }

    fn page_info_virt_addr(&self, pfn: usize) -> VirtAddr {
        let size: usize = size_of::<PageStorageType>();
        let virt: VirtAddr = self.start_virt;
        virt + ((pfn as usize) * size)
    }

    fn check_pfn(&self, pfn: usize) {
        if pfn >= self.page_count {
            panic!("Invalid Page Number {}", pfn);
        }
    }

    fn check_virt_addr(&self, vaddr: VirtAddr) -> bool {
        let start: VirtAddr = self.start_virt;
        let end: VirtAddr = self.start_virt + (self.page_count * PAGE_SIZE as usize);

        vaddr >= start && vaddr < end
    }

    fn write_page_info(&self, pfn: usize, pi: SvsmPageInfo) {
        self.check_pfn(pfn);

        let info: PageStorageType = pi.to_mem();
        unsafe {
            let ptr: *mut PageStorageType =
                self.page_info_virt_addr(pfn).as_u64() as *mut PageStorageType;
            (*ptr) = info;
        }
    }

    fn read_page_info(&self, pfn: usize) -> SvsmPageInfo {
        self.check_pfn(pfn);

        let virt: VirtAddr = self.page_info_virt_addr(pfn);
        let info: PageStorageType = PageStorageType(unsafe { *(virt.as_u64() as *const u64) });

        SvsmPageInfo::from_mem(info)
    }

    pub fn get_page_info(&self, vaddr: VirtAddr) -> Result<SvsmPageInfo, ()> {
        if vaddr.as_u64() == 0 || !self.check_virt_addr(vaddr) {
            return Err(());
        }

        let pfn: usize = ((vaddr - self.start_virt) / PAGE_SIZE) as usize;

        Ok(self.read_page_info(pfn))
    }

    fn get_next_page(&mut self, order: usize) -> Result<usize, ()> {
        let pfn: usize = self.next_page[order];

        if pfn == 0 {
            return Err(());
        }

        let pg: SvsmPageInfo = self.read_page_info(pfn);

        let new_next: usize = match pg {
            SvsmPageInfo::Free(fi) => fi.next_page,
            _ => panic!("Unexpected page type in MemoryRegion::get_next_page()"),
        };

        self.next_page[order] = new_next;

        self.free_pages[order] -= 1;

        Ok(pfn)
    }

    fn init_compound_page(&mut self, pfn: usize, order: usize, next_pfn: usize) {
        let nr_pages: usize = 1 << order;

        let head: SvsmPageInfo = SvsmPageInfo::Free(FreeInfo {
            next_page: next_pfn,
            order: order,
        });
        self.write_page_info(pfn, head);

        for i in 1..nr_pages {
            let compound: SvsmPageInfo = SvsmPageInfo::CompoundPage(CompoundInfo { order: order });
            self.write_page_info(pfn + i, compound);
        }
    }

    fn split_page(&mut self, pfn: usize, order: usize) -> Result<(), ()> {
        if order < 1 || order >= MAX_ORDER {
            return Err(());
        }

        let new_order: usize = order - 1;
        let pfn1: usize = pfn;
        let pfn2: usize = pfn + (1usize << new_order);

        let next_pfn: usize = self.next_page[new_order];
        self.init_compound_page(pfn1, new_order, pfn2);
        self.init_compound_page(pfn2, new_order, next_pfn);
        self.next_page[new_order] = pfn1;

        // Do the accounting
        self.nr_pages[order] -= 1;
        self.nr_pages[new_order] += 2;
        self.free_pages[new_order] += 2;

        Ok(())
    }

    fn refill_page_list(&mut self, order: usize) -> Result<(), ()> {
        if self.next_page[order] != 0 {
            return Ok(());
        }

        if order >= MAX_ORDER - 1 {
            return Err(());
        }

        self.refill_page_list(order + 1)?;

        let pfn: usize = self.get_next_page(order + 1)?;

        self.split_page(pfn, order + 1)
    }

    pub fn allocate_pages(&mut self, order: usize) -> Result<VirtAddr, ()> {
        if order >= MAX_ORDER {
            return Err(());
        }
        self.refill_page_list(order)?;
        if let Ok(pfn) = self.get_next_page(order) {
            let pg: SvsmPageInfo = SvsmPageInfo::Allocated(AllocatedInfo { order: order });
            self.write_page_info(pfn, pg);
            let vaddr: VirtAddr = self.start_virt + (pfn * PAGE_SIZE as usize);
            return Ok(vaddr);
        } else {
            return Err(());
        }
    }

    pub fn allocate_page(&mut self) -> Result<VirtAddr, ()> {
        self.allocate_pages(0)
    }

    pub fn allocate_slab_page(&mut self, slab: VirtAddr) -> Result<VirtAddr, ()> {
        self.refill_page_list(0)?;
        if let Ok(pfn) = self.get_next_page(0) {
            assert!(slab.as_u64() & PAGE_TYPE_MASK == 0);
            let pg: SvsmPageInfo = SvsmPageInfo::SlabPage(SlabPageInfo { slab: slab });
            self.write_page_info(pfn, pg);
            let vaddr: VirtAddr = self.start_virt + (pfn * PAGE_SIZE as usize);
            return Ok(vaddr);
        } else {
            return Err(());
        }
    }

    fn order_mask(order: usize) -> u64 {
        !((PAGE_SIZE << order) - 1)
    }

    fn pfn_to_virt(&self, pfn: usize) -> VirtAddr {
        self.start_virt + (pfn * PAGE_SIZE as usize)
    }

    fn virt_to_pfn(&self, vaddr: VirtAddr) -> usize {
        ((vaddr - self.start_virt) / PAGE_SIZE) as usize
    }

    fn compound_neighbor(&self, pfn: usize, order: usize) -> Result<usize, ()> {
        if order >= MAX_ORDER - 1 {
            return Err(());
        }

        let vaddr: VirtAddr =
            VirtAddr::new(self.pfn_to_virt(pfn).as_u64() & MemoryRegion::order_mask(order));
        let neigh: VirtAddr = VirtAddr::new(vaddr.as_u64() ^ (PAGE_SIZE << order));

        if vaddr < self.start_virt || neigh < self.start_virt {
            return Err(());
        }

        let pfn: usize = self.virt_to_pfn(neigh);
        if pfn >= self.page_count {
            return Err(());
        }

        Ok(pfn)
    }

    fn merge_pages(&mut self, pfn1: usize, pfn2: usize, order: usize) -> Result<usize, ()> {
        if order >= MAX_ORDER - 1 {
            return Err(());
        }

        let nr_pages: usize = (1 << order) + 1;
        let pfn: usize = if pfn1 < pfn2 { pfn1 } else { pfn2 };

        // Write new compound head
        let pg: SvsmPageInfo = SvsmPageInfo::Allocated(AllocatedInfo { order: order + 1 });
        self.write_page_info(pfn, pg);

        // Write compound pages
        for i in 1..nr_pages {
            let pg: SvsmPageInfo = SvsmPageInfo::CompoundPage(CompoundInfo { order: order + 1 });
            self.write_page_info(pfn + i, pg);
        }

        // Do the accounting - none of the pages is free yet, so free_pages is
        // not updated here.
        self.nr_pages[order] -= 2;
        self.nr_pages[order + 1] += 1;

        Ok(pfn)
    }

    fn next_free_pfn(&self, pfn: usize, order: usize) -> usize {
        let page: SvsmPageInfo = self.read_page_info(pfn);
        match page {
            SvsmPageInfo::Free(fi) => fi.next_page,
            _ => {
                panic!("Unexpected page type in free-list for order {}", order);
            }
        }
    }

    fn allocate_pfn(&mut self, pfn: usize, order: usize) -> Result<(), ()> {
        let first_pfn: usize = self.next_page[order];

        // Handle special cases first
        if first_pfn == 0 {
            // No pages for that order
            return Err(());
        } else if first_pfn == pfn {
            // Requested pfn is first in list
            self.get_next_page(order).unwrap();
            return Ok(());
        }

        // Now walk the list
        let mut old_pfn: usize = first_pfn;
        loop {
            let current_pfn: usize = self.next_free_pfn(old_pfn, order);
            if current_pfn == 0 {
                break;
            } else if current_pfn == pfn {
                let next_pfn: usize = self.next_free_pfn(current_pfn, order);
                let pg: SvsmPageInfo = SvsmPageInfo::Free(FreeInfo {
                    next_page: next_pfn,
                    order: order,
                });
                self.write_page_info(old_pfn, pg);

                let pg: SvsmPageInfo = SvsmPageInfo::Allocated(AllocatedInfo { order: order });
                self.write_page_info(current_pfn, pg);

                self.free_pages[order] -= 1;

                return Ok(());
            }

            old_pfn = current_pfn;
        }

        return Err(());
    }

    fn free_page_raw(&mut self, pfn: usize, order: usize) {
        let old_next: usize = self.next_page[order];
        let pg: SvsmPageInfo = SvsmPageInfo::Free(FreeInfo {
            next_page: old_next,
            order: order,
        });

        self.write_page_info(pfn, pg);
        self.next_page[order] = pfn;

        self.free_pages[order] += 1;
    }

    fn try_to_merge_page(&mut self, pfn: usize, order: usize) -> Result<usize, ()> {
        let neighbor_pfn: usize = self.compound_neighbor(pfn, order)?;
        let neighbor_page: SvsmPageInfo = self.read_page_info(neighbor_pfn);

        if let SvsmPageInfo::Free(fi) = neighbor_page {
            if fi.order != order {
                return Err(());
            }

            self.allocate_pfn(neighbor_pfn, order)?;

            let new_pfn: usize = self.merge_pages(pfn, neighbor_pfn, order)?;

            Ok(new_pfn)
        } else {
            Err(())
        }
    }

    fn free_page_order(&mut self, pfn: usize, order: usize) {
        match self.try_to_merge_page(pfn, order) {
            Err(_e) => {
                self.free_page_raw(pfn, order);
            }
            Ok(new_pfn) => {
                self.free_page_order(new_pfn, order + 1);
            }
        }
    }

    pub fn free_page(&mut self, vaddr: VirtAddr) {
        let res = self.get_page_info(vaddr);

        if let Err(_e) = res {
            return;
        }

        let pfn: usize = ((vaddr - self.start_virt) / PAGE_SIZE) as usize;

        match res.unwrap() {
            SvsmPageInfo::Allocated(ai) => {
                self.free_page_order(pfn, ai.order);
            }
            SvsmPageInfo::SlabPage(_si) => {
                self.free_page_order(pfn, 0);
            }
            _ => {
                panic!("Unexpected page type in MemoryRegion::free_page()");
            }
        }
    }

    pub fn init_memory(&mut self) {
        let item_size: usize = size_of::<PageStorageType>();
        let size: u64 = (self.page_count * item_size) as u64;
        let meta_pages: usize = (align_up(size, PAGE_SIZE) / PAGE_SIZE) as usize;

        /* Mark page storage as reserved */
        for i in 0..meta_pages {
            let pg: SvsmPageInfo = SvsmPageInfo::Reserved(ReservedInfo {});
            self.write_page_info(i, pg);
        }

        self.nr_pages[0] = self.page_count - meta_pages;

        /* Mark all pages as allocated */
        for i in meta_pages..self.page_count {
            let pg: SvsmPageInfo = SvsmPageInfo::Allocated(AllocatedInfo { order: 0 });
            self.write_page_info(i, pg);
        }

        /* Now free all pages */
        for i in meta_pages..self.page_count {
            self.free_page_order(i, 0);
        }
    }
}

static ROOT_MEM: SpinLock<MemoryRegion> = SpinLock::new(MemoryRegion::new());

pub fn allocate_page() -> Result<VirtAddr, ()> {
    ROOT_MEM.lock().allocate_page()
}

pub fn allocate_pages(order: usize) -> Result<VirtAddr, ()> {
    ROOT_MEM.lock().allocate_pages(order)
}

pub fn allocate_slab_page(slab: VirtAddr) -> Result<VirtAddr, ()> {
    ROOT_MEM.lock().allocate_slab_page(slab)
}

pub fn free_page(vaddr: VirtAddr) {
    ROOT_MEM.lock().free_page(vaddr)
}

pub fn mem_free_frames(frame: PhysFrame, _count: u64) {
    let vaddr: VirtAddr = pgtable_pa_to_va(frame.start_address());
    free_page(vaddr);
}

pub fn mem_free_frame(frame: PhysFrame) {
    mem_free_frames(frame, 1);
}

pub fn mem_allocate_frames(count: u64) -> Option<PhysFrame> {
    let order: usize = SvsmAllocator::get_order((count * PAGE_SIZE) as usize);
    let result = ROOT_MEM.lock().allocate_pages(order);

    let frame = match result {
        Ok(vaddr) => Some(PhysFrame::from_start_address(pgtable_va_to_pa(vaddr)).unwrap()),
        Err(_e) => None,
    };

    if let Some(f) = frame {
        let vaddr: VirtAddr = pgtable_pa_to_va(f.start_address());
        unsafe {
            let dst: *mut u8 = vaddr.as_mut_ptr();
            core::intrinsics::write_bytes(dst, 0, (PAGE_SIZE << order) as usize);
        }
    }

    frame
}

pub fn mem_allocate_frame() -> Option<PhysFrame> {
    mem_allocate_frames(1)
}

struct SlabPage {
    vaddr: VirtAddr,
    capacity: u16,
    free: u16,
    item_size: u16,
    used_bitmap: [u64; 2],
    next_page: VirtAddr,
}

impl SlabPage {
    pub const fn new() -> Self {
        SlabPage {
            vaddr: VirtAddr::new_truncate(0),
            capacity: 0,
            free: 0,
            item_size: 0,
            used_bitmap: [0; 2],
            next_page: VirtAddr::new_truncate(0),
        }
    }

    pub fn init(&mut self, slab: VirtAddr, mut item_size: u16) -> Result<(), ()> {
        if self.item_size != 0 {
            return Ok(());
        }

        assert!(item_size <= (PAGE_SIZE / 2) as u16);
        assert!(self.vaddr.as_u64() == 0);

        if item_size < 32 {
            item_size = 32;
        }

        if let Ok(vaddr) = allocate_slab_page(slab) {
            self.vaddr = vaddr;
            self.item_size = item_size;
            self.capacity = (PAGE_SIZE as u16) / item_size;
            self.free = self.capacity;
        } else {
            return Err(());
        }

        Ok(())
    }

    pub fn destroy(&mut self) {
        if self.vaddr.as_u64() == 0 {
            return;
        }

        free_page(self.vaddr);
    }

    pub fn get_capacity(&self) -> u16 {
        self.capacity
    }

    pub fn get_free(&self) -> u16 {
        self.free
    }

    pub fn get_next_page(&self) -> VirtAddr {
        self.next_page
    }

    pub fn set_next_page(&mut self, next_page: VirtAddr) {
        self.next_page = next_page;
    }

    pub fn allocate(&mut self) -> Result<VirtAddr, ()> {
        if self.free == 0 {
            return Err(());
        }

        for i in 0..self.capacity {
            let idx: usize = (i / 64).into();
            let mask: u64 = 1u64 << (i % 64);

            if self.used_bitmap[idx] & mask == 0 {
                self.used_bitmap[idx] |= mask;
                self.free -= 1;
                let offset: u64 = (self.item_size * i).into();
                return Ok(self.vaddr + offset);
            }
        }

        Err(())
    }

    pub fn free(&mut self, vaddr: VirtAddr) -> Result<(), ()> {
        if vaddr < self.vaddr || vaddr >= self.vaddr + PAGE_SIZE {
            return Err(());
        }

        assert!(self.item_size > 0);

        let item_size: u64 = self.item_size.into();
        let offset: u64 = vaddr - self.vaddr;
        let i: u64 = offset / item_size;
        let idx: usize = (i / 64) as usize;
        let mask: u64 = 1u64 << (i % 64);

        self.used_bitmap[idx] &= !mask;
        self.free += 1;

        Ok(())
    }
}

#[repr(align(16))]
struct Slab {
    item_size: u16,
    capacity: u32,
    free: u32,
    pages: u32,
    full_pages: u32,
    free_pages: u32,
    page: SlabPage,
}

impl Slab {
    pub const fn new(item_size: u16) -> Self {
        Slab {
            item_size: item_size,
            capacity: 0,
            free: 0,
            pages: 0,
            full_pages: 0,
            free_pages: 0,
            page: SlabPage::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), ()> {
        let slab_vaddr: VirtAddr = VirtAddr::new((self as *mut Slab) as u64);
        if let Err(_e) = self.page.init(slab_vaddr, self.item_size) {
            return Err(());
        }

        self.capacity = self.page.get_capacity() as u32;
        self.free = self.capacity;
        self.pages = 1;
        self.full_pages = 0;
        self.free_pages = 1;

        Ok(())
    }

    unsafe fn grow_slab(&mut self) -> Result<(), ()> {
        if self.capacity == 0 {
            if let Err(_e) = self.init() {
                return Err(());
            }
            return Ok(());
        }

        let page_vaddr: VirtAddr = SLAB_PAGE_SLAB.lock().allocate().unwrap();
        let slab_page: *mut SlabPage = page_vaddr.as_u64() as *mut SlabPage;
        let slab_vaddr: VirtAddr = VirtAddr::new((self as *mut Slab) as u64);

        *slab_page = SlabPage::new();
        if let Err(_e) = (*slab_page).init(slab_vaddr, self.item_size) {
            SLAB_PAGE_SLAB.lock().deallocate(page_vaddr);
            return Err(());
        }

        let old_next_page: VirtAddr = self.page.get_next_page();
        (*slab_page).set_next_page(old_next_page);
        self.page.set_next_page(page_vaddr);

        let new_capacity: u32 = (*slab_page).get_capacity().into();
        self.pages += 1;
        self.free_pages += 1;
        self.capacity += new_capacity;
        self.free += new_capacity;

        Ok(())
    }

    unsafe fn shrink_slab(&mut self) {
        let mut last_page: *mut SlabPage = &mut self.page;
        let mut page_vaddr: VirtAddr = self.page.get_next_page();

        loop {
            if page_vaddr.as_u64() == 0 {
                break;
            }

            let slab_page: *mut SlabPage = page_vaddr.as_u64() as *mut SlabPage;
            let capacity: u16 = (*slab_page).get_capacity();
            let free: u16 = (*slab_page).get_free();

            if free == capacity {
                let capacity: u32 = (*slab_page).get_capacity().into();
                self.pages -= 1;
                self.free_pages -= 1;
                self.capacity -= capacity;
                self.free -= capacity;

                (*last_page).set_next_page((*slab_page).get_next_page());
                (*slab_page).destroy();
                SLAB_PAGE_SLAB.lock().deallocate(page_vaddr);
                return;
            }

            last_page = slab_page;
            page_vaddr = (*slab_page).get_next_page();
        }
    }

    pub fn adjust_slab_size(&mut self) -> Result<(), ()> {
        if self.capacity == 0 {
            return unsafe { self.grow_slab() };
        }

        let free: u64 = ((self.free as u64) * 100) / (self.capacity as u64);

        if free < 25 && self.free_pages < 2 {
            unsafe {
                return self.grow_slab();
            }
        } else if self.free_pages > 1 && free >= 50 {
            unsafe {
                self.shrink_slab();
            }
        }

        Ok(())
    }

    pub fn allocate(&mut self) -> Result<VirtAddr, ()> {
        if let Err(_e) = self.adjust_slab_size() {
            return Err(());
        }

        let mut page: *mut SlabPage = &mut self.page;

        unsafe {
            loop {
                let free: u16 = (*page).get_free();

                if let Ok(vaddr) = (*page).allocate() {
                    let capacity: u16 = (*page).get_capacity();
                    self.free -= 1;

                    if free == capacity {
                        self.free_pages -= 1;
                    } else if free == 1 {
                        self.full_pages += 1;
                    }

                    return Ok(vaddr);
                }

                let next_page: VirtAddr = (*page).get_next_page();

                if next_page.as_u64() == 0 {
                    break;
                }

                page = next_page.as_u64() as *mut SlabPage;
            }
        }

        Err(())
    }

    pub fn deallocate(&mut self, vaddr: VirtAddr) {
        let mut page: *mut SlabPage = &mut self.page;

        unsafe {
            loop {
                let free: u16 = (*page).get_free();

                if let Ok(_o) = (*page).free(vaddr) {
                    let capacity: u16 = (*page).get_capacity();
                    self.free += 1;

                    if free == 0 {
                        self.full_pages -= 1;
                    } else if free + 1 == capacity {
                        self.free_pages += 1;
                    }

                    self.adjust_slab_size()
                        .expect("Failed to adjust slab size in deallocation path");

                    return;
                }

                let next_page: VirtAddr = (*page).get_next_page();

                if next_page.as_u64() == 0 {
                    break;
                }

                page = next_page.as_u64() as *mut SlabPage;
            }
        }

        panic!(
            "Address {:#016x} does not belong to this Slab",
            vaddr.as_u64()
        );
    }
}

static SLAB_PAGE_SLAB: SpinLock<Slab> = SpinLock::new(Slab::new(size_of::<SlabPage>() as u16));

pub struct SvsmAllocator {
    slab_size_32: SpinLock<Slab>,
    slab_size_64: SpinLock<Slab>,
    slab_size_128: SpinLock<Slab>,
    slab_size_256: SpinLock<Slab>,
    slab_size_512: SpinLock<Slab>,
    slab_size_1024: SpinLock<Slab>,
    slab_size_2048: SpinLock<Slab>,
}

impl SvsmAllocator {
    pub const fn new() -> Self {
        SvsmAllocator {
            slab_size_32: SpinLock::new(Slab::new(32)),
            slab_size_64: SpinLock::new(Slab::new(64)),
            slab_size_128: SpinLock::new(Slab::new(128)),
            slab_size_256: SpinLock::new(Slab::new(256)),
            slab_size_512: SpinLock::new(Slab::new(512)),
            slab_size_1024: SpinLock::new(Slab::new(1024)),
            slab_size_2048: SpinLock::new(Slab::new(2048)),
        }
    }

    fn get_order(size: usize) -> usize {
        assert!(size > 0);
        let mut val: usize = (size - 1) >> PAGE_SHIFT;
        let mut order: usize = 0;

        loop {
            if val == 0 {
                break;
            }

            order += 1;
            val >>= 1;
        }

        order
    }
}

unsafe impl GlobalAlloc for SvsmAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret: Result<VirtAddr, ()>;
        let size: usize = layout.size();

        SLAB_PAGE_SLAB
            .lock()
            .adjust_slab_size()
            .expect("Failed to adjust Slab size");

        if size <= 32 {
            ret = self.slab_size_32.lock().allocate();
        } else if size <= 64 {
            ret = self.slab_size_64.lock().allocate();
        } else if size <= 128 {
            ret = self.slab_size_128.lock().allocate();
        } else if size <= 256 {
            ret = self.slab_size_256.lock().allocate();
        } else if size <= 512 {
            ret = self.slab_size_512.lock().allocate();
        } else if size <= 1024 {
            ret = self.slab_size_1024.lock().allocate();
        } else if size <= 2048 {
            ret = self.slab_size_2048.lock().allocate();
        } else if size <= 4096 {
            ret = allocate_page();
        } else {
            let order: usize = SvsmAllocator::get_order(size);
            if order >= MAX_ORDER {
                return ptr::null_mut();
            }
            ret = allocate_pages(order);
        }

        if let Err(_e) = ret {
            return ptr::null_mut();
        }

        ret.unwrap().as_u64() as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let virt_addr: VirtAddr = VirtAddr::new(ptr as u64);

        let result: Result<SvsmPageInfo, ()> = ROOT_MEM.lock().get_page_info(virt_addr);

        if let Err(_e) = result {
            panic!("Freeing unknown memory");
        }

        let info: SvsmPageInfo = result.unwrap();

        match info {
            SvsmPageInfo::Allocated(_ai) => {
                free_page(virt_addr);
            }
            SvsmPageInfo::SlabPage(si) => {
                let slab: *mut Slab = si.slab.as_u64() as *mut Slab;

                (*slab).deallocate(virt_addr);
            }
            _ => {
                panic!("Freeing memory on unsupported page type");
            }
        }
    }
}

#[global_allocator]
pub static mut ALLOCATOR: SvsmAllocator = SvsmAllocator::new();

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("Allocation failed: {:?}\n", layout)
}

fn root_mem_init(pstart: PhysAddr, vstart: VirtAddr, page_count: usize) {
    {
        let mut region = ROOT_MEM.lock();
        region.start_phys = pstart;
        region.start_virt = vstart;
        region.page_count = page_count;
        region.init_memory();
        // drop lock here so SLAB initialization does not deadlock
    }

    if let Err(_e) = SLAB_PAGE_SLAB.lock().init() {
        panic!("Failed to initialize SLAB_PAGE_SLAB");
    }
}

unsafe fn __mem_init() {
    let mem_begin: PhysFrame = PhysFrame::containing_address(PhysAddr::new(dyn_mem_begin));
    let mem_end: PhysFrame = PhysFrame::containing_address(PhysAddr::new(dyn_mem_end));

    vc_early_make_pages_private(mem_begin, mem_end);

    let pstart: PhysAddr = PhysAddr::new(dyn_mem_begin);
    let pend: PhysAddr = PhysAddr::new(dyn_mem_end);
    let vstart: VirtAddr = pgtable_pa_to_va(pstart);
    let page_count: usize = ((pend.as_u64() - pstart.as_u64()) / PAGE_SIZE) as usize;

    root_mem_init(pstart, vstart, page_count);
}

/// Initialized the runtime memory allocator
///
/// The mem_init() function sets up the root memory region data structures so
/// that memory can be allocated and released. It will set up the page
/// meta-data information and the free-lists for every supported allocation order
/// of the buddy allocator.
/// It will also setup the SLAB allocator for allocations up to 2 KiB.
pub fn mem_init() {
    STATIC_ASSERT!(MAX_ORDER < REAL_MAX_ORDER);

    unsafe {
        __mem_init();
    }
}
