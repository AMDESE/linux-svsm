/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::pause;
use crate::cpu::vc::vc_terminate_svsm_fwcfg;
use crate::cpu::*;
use crate::globals::*;
use crate::mem::dynam::mem_allocate_frame;
use crate::mem::pgtable::*;
use crate::util::locking::{LockGuard, SpinLock};
use crate::*;

use alloc::vec::Vec;
use core::intrinsics::size_of;
use core::ptr::copy_nonoverlapping;
use lazy_static::lazy_static;
use memchr::memchr;
use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::structures::paging::PhysFrame;

/// 0x510
const FW_CFG_SELECTOR: u16 = 0x510;
/// 0x511
const FW_CFG_DATA: u16 = 0x511;
/// 0x514
const FW_CFG_DMA_HI: u16 = 0x514;
/// 0x518
const FW_CFG_DMA_LO: u16 = 0x518;

/// 0x0000
const FW_CFG_SIGNATURE: u16 = 0x0000;
/// 0x554d4551
const FW_SIGNATURE: u32 = 0x554d4551;

/// 0x0001
const FW_CFG_ID: u16 = 0x0001;
//const FW_FEATURE_TRADITIONAL: u32 = BIT!(0);
/// Bit 1
const FW_FEATURE_DMA: u32 = BIT!(1);

/// 0x0019
const FW_CFG_FILE_DIR: u16 = 0x0019;

/// Bit 0
const FW_CFG_DMA_ERROR: u32 = BIT!(0);
/// Bit 1
const FW_CFG_DMA_READ: u32 = BIT!(1);
//const FW_CFG_DMA_SKIP: u32 = BIT!(2);
/// Bit 3
const FW_CFG_DMA_SELECT: u32 = BIT!(3);
//const FW_CFG_DMA_WRITE: u32 = BIT!(4);
const FW_CFG_DMA_CLEAR_SELECTOR: u32 = !((0xffff << 16) | FW_CFG_DMA_SELECT);

/// etc/bios_gpa
const FW_CFG_BIOS_GPA: &str = "etc/bios_gpa";
/// etc/bios_size
const FW_CFG_BIOS_SIZE: &str = "etc/bios_size";

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct FwCfgDmaDesc {
    control: u32,
    length: u32,
    address: u64,
}

/// PAGE_SIZE minus size of FwCfgDmaDesc
const DMA_DATA_SIZE: usize = PAGE_SIZE as usize - size_of::<FwCfgDmaDesc>();

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct FwCfgDma {
    desc: FwCfgDmaDesc,
    data: [u8; DMA_DATA_SIZE],
}

#[allow(dead_code)]
impl FwCfgDma {
    funcs!(desc, FwCfgDmaDesc);
    funcs!(data, [u8; DMA_DATA_SIZE]);
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct FwCfgFile {
    size: u32,
    select: u16,
    reserved: u16,
    name: [u8; 56],
}

#[allow(dead_code)]
impl FwCfgFile {
    pub const fn new() -> Self {
        FwCfgFile {
            size: 0,
            select: 0,
            reserved: 0,
            name: [0; 56],
        }
    }
    funcs!(size, u32);
    funcs!(select, u16);
    funcs!(name, [u8; 56]);
}

static mut FILE_COUNT: usize = 0;

lazy_static! {
    static ref FW_CFG_DMA: SpinLock<&'static mut FwCfgDma> = {
        let frame: PhysFrame = match mem_allocate_frame() {
            Some(f) => f,
            None => vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_ENOMEM),
        };
        let va: VirtAddr = pgtable_pa_to_va(frame.start_address());

        pgtable_make_pages_shared(va, PAGE_SIZE);

        let dma: &mut FwCfgDma;
        unsafe {
            dma = &mut *va.as_mut_ptr() as &mut FwCfgDma;
        }

        SpinLock::new(dma)
    };
    static ref FW_CFG_FILES: SpinLock<Vec<FwCfgFile>> = {
        let mut files: Vec<FwCfgFile>;

        unsafe {
            files = Vec::with_capacity(FILE_COUNT);
            for _i in 0..FILE_COUNT {
                let f: FwCfgFile = FwCfgFile::new();
                files.push(f);
            }
        }

        SpinLock::new(files)
    };
}

fn read32_data_be() -> u32 {
    let mut value: u32 = (vc_inb(FW_CFG_DATA) as u32) << 24;

    value |= (vc_inb(FW_CFG_DATA) as u32) << 16;
    value |= (vc_inb(FW_CFG_DATA) as u32) << 8;
    value |= vc_inb(FW_CFG_DATA) as u32;

    value
}

fn read32_data_le() -> u32 {
    let mut value: u32 = vc_inb(FW_CFG_DATA) as u32;

    value |= (vc_inb(FW_CFG_DATA) as u32) << 8;
    value |= (vc_inb(FW_CFG_DATA) as u32) << 16;
    value |= (vc_inb(FW_CFG_DATA) as u32) << 24;

    value
}

fn read64_data_le() -> u64 {
    let mut value: u64 = vc_inb(FW_CFG_DATA) as u64;

    value |= (vc_inb(FW_CFG_DATA) as u64) << 8;
    value |= (vc_inb(FW_CFG_DATA) as u64) << 16;
    value |= (vc_inb(FW_CFG_DATA) as u64) << 24;
    value |= (vc_inb(FW_CFG_DATA) as u64) << 32;
    value |= (vc_inb(FW_CFG_DATA) as u64) << 40;
    value |= (vc_inb(FW_CFG_DATA) as u64) << 48;
    value |= (vc_inb(FW_CFG_DATA) as u64) << 56;

    value
}

fn perform_dma(dma: &mut FwCfgDma, data: *const u8, control: u32, size: usize) {
    assert!(size <= DMA_DATA_SIZE);

    dma.desc.control = u32::swap_bytes(control);
    dma.desc.length = u32::swap_bytes(size as u32);
    dma.desc.address = u64::swap_bytes(&dma.data as *const u8 as u64);

    let lo: u32 = LOWER_32BITS!(dma as *mut FwCfgDma as u64) as u32;
    let hi: u32 = UPPER_32BITS!(dma as *mut FwCfgDma as u64) as u32;
    vc_outl(FW_CFG_DMA_HI, u32::swap_bytes(hi));
    vc_outl(FW_CFG_DMA_LO, u32::swap_bytes(lo));

    let mut c: u32;
    loop {
        c = u32::swap_bytes(dma.desc.control);
        if (c & !FW_CFG_DMA_ERROR) == 0 {
            break;
        }
        pause();
    }

    if (c & FW_CFG_DMA_ERROR) != 0 {
        vc_terminate_svsm_fwcfg();
    }

    unsafe {
        let p: *mut u8 = data as *mut u8;
        copy_nonoverlapping(&dma.data as *const u8, p, size);
    }
}

#[inline]
fn select_cfg_item(item: u16) {
    vc_outw(FW_CFG_SELECTOR, item);
}

fn find_file_selector(fname: &str) -> Option<u16> {
    let files: LockGuard<Vec<FwCfgFile>> = FW_CFG_FILES.lock();

    for f in files.iter() {
        let nul: usize = match memchr(0, &f.name) {
            Some(n) => n,
            None => vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_FW_CFG_ERROR),
        };
        let n: &str = match core::str::from_utf8(&f.name[0..nul]) {
            Ok(n) => n,
            Err(_e) => vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_FW_CFG_ERROR),
        };

        if n.eq(fname) {
            return Some(f.select);
        }
    }

    return None;
}

/// Privately map BIOS
pub fn fwcfg_map_bios() -> Option<(VirtAddr, u64)> {
    let bios_pa: u64;
    let bios_size: u64;

    let selector: u16 = match find_file_selector(FW_CFG_BIOS_GPA) {
        Some(f) => f,
        None => return None,
    };
    select_cfg_item(selector);
    bios_pa = read64_data_le();

    let selector: u16 = match find_file_selector(FW_CFG_BIOS_SIZE) {
        Some(f) => f,
        None => return None,
    };
    select_cfg_item(selector);
    bios_size = read64_data_le();

    // Check for possible buffer overflow
    match bios_pa.checked_add(bios_size) {
        Some(_v) => (),
        None => return None,
    };

    let bios_va: VirtAddr = match pgtable_map_pages_private(PhysAddr::new(bios_pa), bios_size) {
        Ok(b) => b,
        Err(_e) => return None,
    };

    Some((bios_va, bios_size))
}

/// Perform DMA to read firmware configuration files
pub fn fwcfg_init() {
    STATIC_ASSERT!(size_of::<FwCfgDma>() == PAGE_SIZE as usize);

    lazy_static::initialize(&FW_CFG_DMA);

    /* Validate the signature */
    select_cfg_item(FW_CFG_SIGNATURE);
    let signature: u32 = read32_data_le();
    if signature != FW_SIGNATURE {
        vc_terminate_svsm_fwcfg();
    }

    /* Validate DMA support */
    select_cfg_item(FW_CFG_ID);
    let features: u32 = read32_data_le();
    if (features & FW_FEATURE_DMA) == 0 {
        vc_terminate_svsm_fwcfg();
    }

    select_cfg_item(FW_CFG_FILE_DIR);
    let file_count: u32 = read32_data_be();
    if file_count == 0 {
        vc_terminate_svsm_fwcfg();
    }

    unsafe {
        FILE_COUNT = file_count as usize;
    }

    lazy_static::initialize(&FW_CFG_FILES);

    unsafe {
        let f: FwCfgFile = FwCfgFile {
            size: 0,
            select: 0,
            reserved: 0,
            name: [0; 56],
        };

        let mut files: LockGuard<Vec<FwCfgFile>> = FW_CFG_FILES.lock();

        let size: usize = size_of::<FwCfgFile>();
        let mut control = FW_CFG_DMA_READ;
        let mut dma: LockGuard<&'static mut FwCfgDma> = FW_CFG_DMA.lock();
        for i in 0..FILE_COUNT {
            let bytes: *const u8 = &f as *const FwCfgFile as *const u8;
            perform_dma(&mut dma, bytes, control, size);

            files[i].size = u32::swap_bytes(f.size);
            files[i].select = u16::swap_bytes(f.select);
            files[i].name = f.name;

            /* Stay on the same item */
            control &= FW_CFG_DMA_CLEAR_SELECTOR;
        }

        prints!("> All {FILE_COUNT} firmware config files read.\n");
    }
}
