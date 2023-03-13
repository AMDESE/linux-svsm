/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::smp_prepare_bios_vmpl;
use crate::cpu::smp_run_bios_vmpl;
use crate::cpu::vc::*;
use crate::*;

use core::cmp::min;
use core::mem::size_of;
use core::ptr::copy_nonoverlapping;
use uuid::Bytes;
use uuid::Uuid;
use x86_64::{PhysAddr, VirtAddr};

/// 2
const BIOS_TABLE_LEN_FIELD: u64 = 2;
/// 32
const BIOS_TABLE_END: u64 = 32;
/// 16
const GUID_SIZE: u64 = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct GuidTable {
    begin: u64,
    end: u64,
    len: u16,
}

#[allow(dead_code)]
impl GuidTable {
    pub const fn new() -> Self {
        GuidTable {
            begin: 0,
            end: 0,
            len: 0,
        }
    }
    funcs!(begin, u64);
    funcs!(end, u64);
    funcs!(len, u16);
}

struct BiosInfo {
    va: u64,
    size: u64,

    guid_table: GuidTable,
}

#[allow(dead_code)]
impl BiosInfo {
    pub const fn new(va: VirtAddr, size: u64) -> Self {
        let g: GuidTable = GuidTable::new();

        BiosInfo {
            va: va.as_u64(),
            size: size,
            guid_table: g,
        }
    }
    funcs!(va, u64);
    funcs!(size, u64);
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct SnpMetaData {
    signature: u32,
    len: u32,
    version: u32,
    section_count: u32,
}

#[allow(dead_code)]
impl SnpMetaData {
    funcs!(signature, u32);
    funcs!(len, u32);
    funcs!(version, u32);
    funcs!(section_count, u32);
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct SnpSection {
    address: u32,
    size: u32,
    stype: u32,
}

#[allow(dead_code)]
impl SnpSection {
    funcs!(address, u32);
    funcs!(size, u32);
    funcs!(stype, u32);

    pub fn address_u64(&self) -> u64 {
        self.address as u64
    }
    pub fn size_u64(&self) -> u64 {
        self.size as u64
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct SnpSecrets {
    version: u32,
    flags: u32,
    fms: u32,
    reserved1: [u8; 4],

    gosvw: [u8; 16],

    vmpck0: [u8; 32],
    vmpck1: [u8; 32],
    vmpck2: [u8; 32],
    vmpck3: [u8; 32],

    os_reserved: [u8; 96],

    reserved2: [u8; 64],

    // SVSM fields start at offset 0x140 into the secrets page
    svsm_base: u64,
    svsm_size: u64,
    svsm_caa: u64,
    svsm_max_version: u32,
    svsm_guest_vmpl: u8,
    reserved3: [u8; 3],
}

#[allow(dead_code)]
impl SnpSecrets {
    pub fn clear_vmpck0(&mut self) {
        self.vmpck0.iter_mut().for_each(|e| *e = 0);
    }

    funcs!(svsm_base, u64);
    funcs!(svsm_size, u64);
    funcs!(svsm_caa, u64);
    funcs!(svsm_max_version, u32);
    funcs!(svsm_guest_vmpl, u8);
}

/// 96b582de-1fb2-45f7-baea-a366c55a082d
const OVMF_TABLE_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
/// dc886566-984a-4798-A75e-5585a7bf67cc
const OVMF_SNP_ENTRY_GUID: &str = "dc886566-984a-4798-A75e-5585a7bf67cc";

/// 0x56455341 ("ASEV" in little endian integer)
const SNP_METADATA_SIGNATURE: u32 = 0x56455341; /* "A", "S", "E", "V" in little endian integer */

//const SNP_SECT_MEM:      u32 = 1;
/// 2
const SNP_SECT_SECRETS: u32 = 2;
/// 3
const SNP_SECT_CPUID: u32 = 3;
/// 4
const SNP_SECT_SVSM_CAA: u32 = 4;
//const SNP_SECT_BSP_VMSA: u32 = 5;

unsafe fn __find_bios_guid_entry(
    bios_info: &mut BiosInfo,
    target_guid: Uuid,
    avail_len: &mut u64,
    p: &mut u64,
) -> Option<u64> {
    /* Search is in reverse order */
    while *p > bios_info.guid_table.begin() {
        let len: u64 = *((*p - GUID_SIZE - BIOS_TABLE_LEN_FIELD) as *const u16) as u64;
        if (len < (GUID_SIZE + BIOS_TABLE_LEN_FIELD)) || (len > *avail_len) {
            return None;
        }

        let bytes: *const Bytes = (*p - GUID_SIZE) as *const Bytes;
        let entry_guid: Uuid = Uuid::from_bytes_le(*bytes);
        if entry_guid == target_guid {
            return Some(*p - len as u64);
        }

        *avail_len -= len;
        *p -= len;
    }

    return None;
}

fn find_bios_guid_entry(bios_info: &mut BiosInfo, guid: &str) -> Option<u64> {
    let mut avail_len: u64 = bios_info.guid_table.len() as u64;
    let mut p: u64 = bios_info.guid_table.end();

    let target_guid: Uuid = match Uuid::parse_str(guid) {
        Ok(g) => g,
        Err(_e) => vc_terminate_svsm_bios(),
    };

    unsafe { __find_bios_guid_entry(bios_info, target_guid, &mut avail_len, &mut p) }
}

unsafe fn __find_snp_section(bios_info: &mut BiosInfo, stype: u32, p: u64) -> Option<SnpSection> {
    let offset: u64 = *(p as *const u32) as u64;
    if offset > bios_info.size() {
        return None;
    }

    let metadata: *const SnpMetaData =
        (bios_info.va() + bios_info.size() - offset) as *const SnpMetaData;
    if (*metadata).signature() != SNP_METADATA_SIGNATURE {
        return None;
    }

    let defined_len: u64 = (*metadata).len() as u64;
    let expected_len: u64 = (*metadata).section_count() as u64 * size_of::<SnpSection>() as u64;
    if defined_len < expected_len {
        return None;
    }

    let mut section: *const SnpSection =
        (metadata as u64 + size_of::<SnpMetaData>() as u64) as *const SnpSection;
    for _i in 0..(*metadata).section_count() {
        if (*section).stype() == stype {
            return Some(*section);
        }

        section = (section as u64 + size_of::<SnpSection>() as u64) as *const SnpSection;
    }

    return None;
}

fn find_snp_section(bios_info: &mut BiosInfo, stype: u32) -> Option<SnpSection> {
    let p: u64 = match find_bios_guid_entry(bios_info, OVMF_SNP_ENTRY_GUID) {
        Some(p) => p,
        None => vc_terminate_svsm_bios(),
    };

    unsafe { __find_snp_section(bios_info, stype, p) }
}

unsafe fn advertise_svsm_presence(bios_info: &mut BiosInfo, caa: PhysAddr) -> bool {
    let section: SnpSection = match find_snp_section(bios_info, SNP_SECT_SECRETS) {
        Some(p) => p,
        None => return false,
    };

    if (section.size() as usize) < size_of::<SnpSecrets>() {
        return false;
    }

    let bios_secrets_pa: PhysAddr = PhysAddr::new(section.address_u64());
    let mut bios_secrets_map: MapGuard =
        match MapGuard::new_private(bios_secrets_pa, section.size_u64()) {
            Ok(m) => m,
            Err(_e) => return false,
        };
    let svsm_secrets_va: VirtAddr = get_svsm_secrets_page();

    // Copy the Secrets page to the BIOS Secrets page location
    let bios_secrets: &mut SnpSecrets = bios_secrets_map.as_object_mut();
    let svsm_secrets: *const SnpSecrets = svsm_secrets_va.as_ptr();
    *bios_secrets = *svsm_secrets;

    // Clear the VMPCK0 key
    bios_secrets.clear_vmpck0();

    // Advertise the SVSM
    bios_secrets.set_svsm_base(pgtable_va_to_pa(get_svsm_begin()).as_u64());
    bios_secrets.set_svsm_size(get_svsm_end().as_u64() - get_svsm_begin().as_u64());
    bios_secrets.set_svsm_caa(caa.as_u64());
    bios_secrets.set_svsm_max_version(1);
    bios_secrets.set_svsm_guest_vmpl(1);

    let section: SnpSection = match find_snp_section(bios_info, SNP_SECT_CPUID) {
        Some(p) => p,
        None => return false,
    };

    let bios_cpuid_pa: PhysAddr = PhysAddr::new(section.address_u64());

    let bios_cpuid_va: VirtAddr = match pgtable_map_pages_private(bios_cpuid_pa, section.size_u64())
    {
        Ok(v) => v,
        Err(_e) => return false,
    };
    let svsm_cpuid_va: VirtAddr = get_svsm_cpuid_page();

    // Copy the CPUID page to the BIOS Secrets page location
    let bios_cpuid: *mut u8 = bios_cpuid_va.as_mut_ptr();
    let svsm_cpuid: *const u8 = svsm_cpuid_va.as_ptr();
    let size: u64 = min(section.size_u64(), get_svsm_cpuid_page_size());
    copy_nonoverlapping(svsm_cpuid, bios_cpuid, size as usize);

    pgtable_unmap_pages(bios_cpuid_va, section.size_u64());

    true
}

fn locate_bios_ca_page(bios_info: &mut BiosInfo) -> Option<PhysAddr> {
    let section: SnpSection = match find_snp_section(bios_info, SNP_SECT_SVSM_CAA) {
        Some(p) => p,
        None => return None,
    };

    if (section.size() as usize) < size_of::<u32>() {
        return None;
    }

    return Some(PhysAddr::new(section.address_u64()));
}

fn parse_bios_guid_table(bios_info: &mut BiosInfo) -> bool {
    if bios_info.size() < (BIOS_TABLE_END + GUID_SIZE + BIOS_TABLE_LEN_FIELD) {
        return false;
    }

    let ovmf_guid: Uuid = match Uuid::parse_str(OVMF_TABLE_GUID) {
        Ok(g) => g,
        Err(_e) => return false,
    };

    unsafe {
        let bios: *const u8 = (bios_info.va() + bios_info.size() - BIOS_TABLE_END) as *const u8;
        let bytes: *const Bytes = (bios as u64 - GUID_SIZE) as *const Bytes;

        let guid: Uuid = Uuid::from_bytes_le(*bytes);
        if guid != ovmf_guid {
            return false;
        }

        let len: *const u16 = (bios as u64 - GUID_SIZE - BIOS_TABLE_LEN_FIELD) as *const u16;
        if (*len as u64) > bios_info.size() {
            return false;
        }

        bios_info.guid_table.set_begin(bios as u64 - *len as u64);
        bios_info.guid_table.set_end(len as u64);
        bios_info.guid_table.set_len(*len);
    }

    true
}

/// Locate BIOS, prepare it, advertise SVSM presence and run BIOS
pub fn start_bios() {
    let (bios_va, bios_size) = match fwcfg_map_bios() {
        Some(t) => t,
        None => vc_terminate_svsm_fwcfg(),
    };

    let mut bios_info: BiosInfo = BiosInfo::new(bios_va, bios_size);
    if !parse_bios_guid_table(&mut bios_info) {
        vc_terminate_svsm_bios();
    }

    let caa: PhysAddr = match locate_bios_ca_page(&mut bios_info) {
        Some(p) => p,
        None => vc_terminate_svsm_bios(),
    };

    unsafe {
        if !advertise_svsm_presence(&mut bios_info, caa) {
            vc_terminate_svsm_bios();
        }
    }

    if !smp_prepare_bios_vmpl(caa) {
        vc_terminate_svsm_general();
    }

    pgtable_unmap_pages(bios_va, bios_size);

    if !smp_run_bios_vmpl() {
        vc_terminate_svsm_general();
    }
}
