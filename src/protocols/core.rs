/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::protocols::error_codes::*;
use crate::vmsa_list::VMSA_LIST;
use crate::*;

use core::mem::size_of;
use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::structures::paging::frame::PhysFrame;

/// 0
const SVSM_CORE_REMAP_CA: u32 = 0;
/// 1
const SVSM_CORE_PVALIDATE: u32 = 1;
/// 2
const SVSM_CORE_CREATE_VCPU: u32 = 2;
/// 3
const SVSM_CORE_DELETE_VCPU: u32 = 3;
//const SVSM_CORE_DEPOSIT_MEM:    u32 = 4;
//const SVSM_CORE_WITHDRAW_MEM:   u32 = 5;
/// 6
const SVSM_CORE_QUERY_PROTOCOL: u32 = 6;
/// 7
const SVSM_CORE_CONFIGURE_VTOM: u32 = 7;

#[derive(Clone, Copy, Debug)]
struct VersionInfo {
    min: u32,
    max: u32,
}

#[allow(dead_code)]
impl VersionInfo {
    funcs!(min, u32);
    funcs!(max, u32);
}

static PROTOCOL_INFO: [VersionInfo; 1] = [VersionInfo { min: 1, max: 1 }];

#[allow(dead_code)]
enum ProtocolId {
    ProtocolId0,

    MaxProtocolId,
}

//
// PvalidateEntry format:
//   entry[1:0]   - Page size
//   entry[2]     - Action
//   entry[3]     - Ignore CF
//   entry[11:4]  - Reserved
//   entry[63:12] - GFN
//
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct PvalidateEntry {
    operation: u64,
}

macro_rules! PVALIDATE_ENTRY_PAGE_SIZE {
    ($x: expr) => {
        (*$x).operation & 3
    };
}

macro_rules! PVALIDATE_ENTRY_ACTION {
    ($x: expr) => {
        ((*$x).operation >> 2) & 1
    };
}

macro_rules! PVALIDATE_ENTRY_IGNORE_CF {
    ($x: expr) => {
        ((*$x).operation >> 3) & 1
    };
}

macro_rules! PVALIDATE_ENTRY_GFN {
    ($x: expr) => {
        (*$x).operation & !0xfff
    };
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct PvalidateRequest {
    entries: u16,
    next: u16,
    reserved: u32,
}

#[allow(dead_code)]
impl PvalidateRequest {
    funcs!(entries, u16);
    funcs!(next, u16);
}

unsafe fn address_valid(gfn: PhysFrame, page_size: u32) -> bool {
    let mut gpa: PhysAddr = gfn.start_address();

    if page_size > 1 {
        return false;
    }

    if page_size == 1 && !gpa.is_aligned(PAGE_2MB_SIZE) {
        return false;
    }

    let mut gpa_end: PhysAddr = gpa;
    if page_size == 0 {
        gpa_end += PAGE_SIZE;
    } else {
        gpa_end += PAGE_2MB_SIZE;
    }

    let svsm_begin_gpa: PhysAddr = pgtable_va_to_pa(get_svsm_begin());
    let svsm_end_gpa: PhysAddr = pgtable_va_to_pa(get_svsm_end());
    if gpa < svsm_end_gpa && gpa_end > svsm_begin_gpa {
        return false;
    }

    // Check VMSAs
    while gpa < gpa_end {
        if VMSA_LIST.contains(gpa) {
            return false;
        }

        gpa += PAGE_SIZE;
    }

    true
}

#[inline]
unsafe fn configure_vtom(vmsa: *mut Vmsa) {
    (*vmsa).set_rax(SVSM_ERR_INVALID_REQUEST);
}

#[inline]
unsafe fn query_vtom(vmsa: *mut Vmsa) {
    (*vmsa).set_rax(SVSM_SUCCESS);
    (*vmsa).set_rcx(0);
}

unsafe fn handle_configure_vtom_request(vmsa: *mut Vmsa) {
    if (*vmsa).rcx() == 1 {
        query_vtom(vmsa);
    } else {
        configure_vtom(vmsa);
    }
}

unsafe fn grant_vmpl_access(va: VirtAddr, page_size: u32, vmpl: u8) -> u32 {
    assert!(vmpl != 0);

    let vmin: u64 = VMPL::Vmpl1 as u64;
    let vmax: u64 = (vmpl + 1) as u64;

    for i in vmin..vmax {
        let ret: u32 = rmpadjust(va.as_u64(), page_size, VMPL_RWX | i);
        if ret != 0 {
            return ret;
        }
    }

    return 0;
}

unsafe fn revoke_vmpl_access(va: VirtAddr, page_size: u32) -> u32 {
    let vmin: u64 = VMPL::Vmpl1 as u64;
    let vmax: u64 = VMPL::VmplMax as u64;

    for i in vmin..vmax {
        let ret: u32 = rmpadjust(va.as_u64(), page_size, i);
        if ret != 0 {
            return ret;
        }
    }

    return 0;
}

unsafe fn handle_delete_vcpu_request(vmsa: *mut Vmsa) {
    (*vmsa).set_rax(SVSM_ERR_INVALID_PARAMETER);

    let gpa: PhysAddr = PhysAddr::new((*vmsa).rcx());
    if !gpa.is_aligned(PAGE_SIZE) {
        return;
    }

    if !VMSA_LIST.contains(gpa) {
        return;
    }

    let apic_id: u32 = match VMSA_LIST.get_apic_id(gpa) {
        Some(i) => i,
        None => return,
    };

    let cpu_id: usize = match smp_get_cpu_id(apic_id) {
        Some(c) => c,
        None => return,
    };

    let va: VirtAddr = match pgtable_map_pages_private(gpa, VMSA_MAP_SIZE) {
        Ok(v) => v,
        Err(_e) => return,
    };

    // EFER.SVME must be set to zero
    (*vmsa).set_rax(SVSM_ERR_PROTOCOL_FAIL_INUSE);

    //
    // Set EFER.SVME to 0 to ensure the VMSA is not in-use and can't be used
    // by the hypervisor to run the vCPU while it is being deleted.
    //
    if !vmsa_clear_efer_svme(va) {
        pgtable_unmap_pages(va, VMSA_MAP_SIZE);
        return;
    }

    // Turn the page into a non-VMSA page
    grant_vmpl_access(va, RMP_4K, VMPL::Vmpl1 as u8);

    pgtable_unmap_pages(va, VMSA_MAP_SIZE);

    if PERCPU.vmsa_for(VMPL::Vmpl1, cpu_id) == gpa {
        PERCPU.set_vmsa_for(PhysAddr::zero(), VMPL::Vmpl1, cpu_id);
        PERCPU.set_caa_for(PhysAddr::zero(), VMPL::Vmpl1, cpu_id);
    }
    if !VMSA_LIST.remove(gpa) {
        return;
    }

    (*vmsa).set_rax(SVSM_SUCCESS);
}

unsafe fn handle_create_vcpu_request(vmsa: *mut Vmsa) {
    (*vmsa).set_rax(SVSM_ERR_INVALID_PARAMETER);

    let create_vmsa_gpa: PhysAddr = PhysAddr::new((*vmsa).rcx());
    let create_ca_gpa: PhysAddr = PhysAddr::new((*vmsa).rdx());
    let apic_id: u32 = LOWER_32BITS!((*vmsa).r8()) as u32;

    if !create_vmsa_gpa.is_aligned(PAGE_SIZE) || !create_ca_gpa.is_aligned(PAGE_SIZE) {
        return;
    }

    if !address_valid(PhysFrame::containing_address(create_vmsa_gpa), 0)
        || !address_valid(PhysFrame::containing_address(create_ca_gpa), 0)
    {
        return;
    }

    let create_vmsa_va: VirtAddr = match pgtable_map_pages_private(create_vmsa_gpa, VMSA_MAP_SIZE) {
        Ok(v) => v,
        Err(_e) => return,
    };
    let create_vmsa: *mut Vmsa = create_vmsa_va.as_mut_ptr();

    let vmpl: VMPL = VMPL::Vmpl1;
    'main: loop {
        // Revoke access to all non-zero VMPL levels to prevent tampering
        // before checking the fields within the new VMSA.
        let ret: u32 = revoke_vmpl_access(create_vmsa_va, RMP_4K);
        if ret != 0 {
            break;
        }

        BARRIER!();

        // Only VMPL1 is currently supported
        if (*create_vmsa).vmpl() != 1 {
            break;
        }

        // EFER.SVME must be one
        if ((*create_vmsa).efer() & EFER_SVME) == 0 {
            break;
        }

        // Restrict the VMSA page to, at most, read-only for non-VMPL0. This
        // is to prevent a guest from altering the VMPL level within the VMSA.
        let vmin: u64 = VMPL::Vmpl1 as u64;
        let vmax: u64 = vmpl as u64 + 1;

        for i in vmin..vmax {
            let ret: u32 = rmpadjust(create_vmsa_va.as_u64(), RMP_4K, VMPL_R | i);
            if ret != 0 {
                break 'main;
            }
        }

        // Turn the page into a VMSA page
        let ret: u32 = rmpadjust(create_vmsa_va.as_u64(), RMP_4K, VMPL_VMSA | vmpl as u64);
        if ret != 0 {
            break;
        }

        VMSA_LIST.push(create_vmsa_gpa, apic_id);

        let cpu_id: usize = match smp_get_cpu_id(apic_id) {
            Some(c) => c,
            None => break,
        };

        PERCPU.set_vmsa_for(create_vmsa_gpa, vmpl, cpu_id);
        PERCPU.set_caa_for(create_ca_gpa, vmpl, cpu_id);

        pgtable_unmap_pages(create_vmsa_va, VMSA_MAP_SIZE);

        // Since the VA of the VMSA page is not known to the SVSM, a global ASID
        // flush must be done.
        invlpgb_all();
        tlbsync();
        (*vmsa).set_rax(SVSM_SUCCESS);

        return;
    }

    // Error path when break from loop vs return from loop
    //

    // On error turn the page (back) into a non-VMSA page
    grant_vmpl_access(create_vmsa_va, RMP_4K, vmpl as u8);

    pgtable_unmap_pages(create_vmsa_va, VMSA_MAP_SIZE);

    // Since the VA of the VMSA page is not known to the SVSM, a global ASID
    // flush must be done.
    invlpgb_all();
    tlbsync();
}

unsafe fn handle_pvalidate(vmsa: *mut Vmsa, entry: *const PvalidateEntry) -> (bool, bool) {
    let mut flush: bool = false;
    let gpa: PhysAddr = PhysAddr::new(PVALIDATE_ENTRY_GFN!(entry));
    let action: u32 = PVALIDATE_ENTRY_ACTION!(entry) as u32;
    let page_size: u32 = PVALIDATE_ENTRY_PAGE_SIZE!(entry) as u32;
    let ignore_cf: u32 = PVALIDATE_ENTRY_IGNORE_CF!(entry) as u32;

    let gfn: PhysFrame = PhysFrame::containing_address(gpa);
    if !address_valid(gfn, page_size) {
        (*vmsa).set_rax(SVSM_ERR_INVALID_ADDRESS);
        return (false, false);
    }

    (*vmsa).set_rax(SVSM_ERR_INVALID_PARAMETER);

    let len: u64;
    if page_size == 0 {
        len = PAGE_SIZE;
    } else {
        len = PAGE_2MB_SIZE;
    }

    let va: VirtAddr = match pgtable_map_pages_private(gpa, len) {
        Ok(v) => v,
        Err(_e) => return (false, false),
    };

    if action == 0 {
        flush = true;

        let ret: u32 = revoke_vmpl_access(va, page_size);
        if ret != 0 {
            (*vmsa).set_rax(SVSM_ERR_PROTOCOL_BASE + ret as u64);
            return (false, flush);
        }
    }

    let ret: u32 = pvalidate(va.as_u64(), page_size, action);
    if ret != 0 && (ret != PVALIDATE_CF_SET || ignore_cf == 0) {
        (*vmsa).set_rax(SVSM_ERR_PROTOCOL_BASE + ret as u64);
        return (false, flush);
    }

    if action != 0 {
        let ret: u32 = grant_vmpl_access(va, page_size, VMPL::Vmpl1 as u8);
        if ret != 0 {
            (*vmsa).set_rax(SVSM_ERR_PROTOCOL_BASE + ret as u64);
            return (false, flush);
        }
    }

    pgtable_unmap_pages(va, len);

    (*vmsa).set_rax(SVSM_SUCCESS);
    (true, flush)
}

unsafe fn handle_pvalidate_request(vmsa: *mut Vmsa) {
    (*vmsa).set_rax(SVSM_ERR_INVALID_PARAMETER);

    let gpa: PhysAddr = PhysAddr::new((*vmsa).rcx());

    if !gpa.is_aligned(8_u64) {
        return;
    }

    let va: VirtAddr = match pgtable_map_pages_private(gpa, CAA_MAP_SIZE) {
        Ok(v) => v,
        Err(_e) => return,
    };

    let request: *mut PvalidateRequest = va.as_mut_ptr();
    if (*request).entries() == 0 || (*request).entries() < (*request).next() {
        return;
    }

    // Request data cannot cross a 4K boundary
    let va_end: VirtAddr = va
        + size_of::<PvalidateRequest>()
        + ((*request).entries() as usize * size_of::<PvalidateEntry>())
        - 1_u64;

    if va.align_down(PAGE_SIZE) != va_end.align_down(PAGE_SIZE) {
        return;
    }

    let mut flush: bool = false;
    let mut e_va: VirtAddr = va + size_of::<PvalidateRequest>();
    while (*request).next() < (*request).entries() {
        let entry: *const PvalidateEntry = e_va.as_ptr();

        let (success, should_flush) = handle_pvalidate(vmsa, entry);
        if should_flush {
            flush = true;
        }
        if !success {
            break;
        }

        e_va += size_of::<PvalidateEntry>();
        (*request).set_next((*request).next() + 1);
    }

    //
    // If the PVALIDATE structure is not part of the CA, ensure it is unmapped.
    //
    if gpa.align_down(PAGE_SIZE) != PERCPU.caa(VMPL::Vmpl1).align_down(PAGE_SIZE) {
        pgtable_unmap_pages(va, CAA_MAP_SIZE);
    }

    //
    // Since the VA of the pages is not known to the SVSM, a global ASID
    // flush must be done if any permissions were reduced.
    //
    if flush {
        invlpgb_all();
        tlbsync();
    }
}

unsafe fn handle_remap_ca_request(vmsa: *mut Vmsa) {
    (*vmsa).set_rax(SVSM_ERR_INVALID_PARAMETER);

    let caa: PhysAddr = PhysAddr::new((*vmsa).rcx());

    if !caa.is_aligned(PAGE_SIZE) {
        return;
    }

    if !address_valid(PhysFrame::containing_address(caa), 0) {
        return;
    }

    let vmpl: VMPL = match (*vmsa).vmpl() {
        1 => VMPL::Vmpl1,
        2 => VMPL::Vmpl2,
        3 => VMPL::Vmpl3,
        _ => return,
    };

    PERCPU.set_caa(caa, vmpl);

    (*vmsa).set_rax(SVSM_SUCCESS);
}

unsafe fn handle_query_protocol_request(vmsa: *mut Vmsa) {
    let protocol: usize = UPPER_32BITS!((*vmsa).rcx()) as usize;
    let version: u32 = LOWER_32BITS!((*vmsa).rcx()) as u32;

    (*vmsa).set_rax(SVSM_SUCCESS);
    (*vmsa).set_rcx(0);

    if protocol > ProtocolId::MaxProtocolId as usize {
        return;
    }

    if PROTOCOL_INFO[protocol].min == 0 {
        return;
    }

    if version < PROTOCOL_INFO[protocol].min || version > PROTOCOL_INFO[protocol].max {
        return;
    }

    let info: u64 = (PROTOCOL_INFO[protocol].max as u64) << 32 | PROTOCOL_INFO[protocol].min as u64;
    (*vmsa).set_rcx(info);
}

pub unsafe fn core_handle_request(callid: u32, vmsa: *mut Vmsa) {
    match callid {
        SVSM_CORE_QUERY_PROTOCOL => handle_query_protocol_request(vmsa),
        SVSM_CORE_REMAP_CA => handle_remap_ca_request(vmsa),
        SVSM_CORE_PVALIDATE => handle_pvalidate_request(vmsa),
        SVSM_CORE_CREATE_VCPU => handle_create_vcpu_request(vmsa),
        SVSM_CORE_DELETE_VCPU => handle_delete_vcpu_request(vmsa),
        SVSM_CORE_CONFIGURE_VTOM => handle_configure_vtom_request(vmsa),

        _ => (*vmsa).set_rax(SVSM_ERR_UNSUPPORTED_CALLID),
    };
}
