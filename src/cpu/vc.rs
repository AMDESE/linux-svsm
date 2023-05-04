/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::percpu::PERCPU;
use crate::cpu::pvalidate;
use crate::cpu::sys::PVALIDATE_FAIL_SIZE_MISMATCH;
use crate::cpu::vmsa::Vmsa;
use crate::cpu::*;
use crate::funcs;
use crate::globals::*;
use crate::mem::ghcb::Ghcb;
use crate::mem::ghcb::*;
use crate::mem::*;
use crate::psp::guest_request_cmd::{SnpGuestRequestCmd, SNP_GUEST_REQ_INVALID_LEN};
use crate::util::util::memset;
use crate::*;

use alloc::vec::Vec;
use core::arch::asm;
use core::mem::size_of;
use x86_64::addr::PhysAddr;
use x86_64::addr::VirtAddr;
use x86_64::structures::idt::*;
use x86_64::structures::paging::frame::PhysFrame;

use core::cmp::max;
use core::cmp::min;

use crate::cpu::cpuid::CpuidPage;
use crate::cpu::cpuid::CpuidPageEntry;
use crate::cpu::cpuid::CPUID_COUNT_MAX;

use x86_64::registers::control::Cr4;
use x86_64::registers::control::Cr4Flags;
use x86_64::registers::xcontrol::XCr0;

/// 2
const GHCB_PROTOCOL_MIN: u64 = 2;
/// 2
const GHCB_PROTOCOL_MAX: u64 = 2;

/// Bits zero, one and four
const GHCB_SVSM_FEATURES: u64 = BIT!(0) | BIT!(1) | BIT!(4);

/// 0xfff
const GHCB_MSR_INFO_MASK: u64 = 0xfff;

macro_rules! GHCB_MSR_INFO {
    ($x: expr) => {
        $x & GHCB_MSR_INFO_MASK
    };
}

macro_rules! GHCB_MSR_DATA {
    ($x: expr) => {
        $x & !GHCB_MSR_INFO_MASK
    };
}

// MSR protocol: SEV Information
/// 0x2
const GHCB_MSR_SEV_INFO_REQ: u64 = 0x002;
/// 0x1
const GHCB_MSR_SEV_INFO_RES: u64 = 0x001;
macro_rules! GHCB_MSR_PROTOCOL_MIN {
    ($x: expr) => {
        (($x) >> 32) & 0xffff
    };
}
macro_rules! GHCB_MSR_PROTOCOL_MAX {
    ($x: expr) => {
        (($x) >> 48) & 0xffff
    };
}

// MSR protocol: GHCB registration
/// 0x12
const GHCB_MSR_REGISTER_GHCB_REQ: u64 = 0x12;
macro_rules! GHCB_MSR_REGISTER_GHCB {
    ($x: expr) => {
        (($x) | GHCB_MSR_REGISTER_GHCB_REQ)
    };
}
/// 0x13
const GHCB_MSR_REGISTER_GHCB_RES: u64 = 0x13;

// MSR protocol: Hypervisor feature support
/// 0x80
const GHCB_MSR_HV_FEATURE_REQ: u64 = 0x080;
/// 0x81
const GHCB_MSR_HV_FEATURE_RES: u64 = 0x081;
macro_rules! GHCB_MSR_HV_FEATURES {
    ($x: expr) => {
        (GHCB_MSR_DATA!($x) >> 12)
    };
}

// MSR protocol: Termination request
/// 0x100
const GHCB_MSR_TERMINATE_REQ: u64 = 0x100;

/// 0
const RESCIND: u32 = 0;
/// 1
const VALIDATE: u32 = 1;

// VMGEXIT exit codes
/// 0x72
const GHCB_NAE_CPUID: u64 = 0x72;
/// 0x7b
const GHCB_NAE_IOIO: u64 = 0x7b;
/// 0x80000010
const GHCB_NAE_PSC: u64 = 0x80000010;
/// 0x80000011
const GHCB_NAE_SNP_GUEST_REQUEST: u64 = 0x80000011;
/// 0x80000012
const GHCB_NAE_SNP_EXT_GUEST_REQUEST: u64 = 0x80000012;
/// 0x80000013
const GHCB_NAE_SNP_AP_CREATION: u64 = 0x80000013;
/// 1
const SNP_AP_CREATE_IMMEDIATE: u64 = 1;
/// 0x80000017
const GHCB_NAE_GET_APIC_IDS: u64 = 0x80000017;
/// 0x80000018
const GHCB_NAE_RUN_VMPL: u64 = 0x80000018;

macro_rules! GHCB_NAE_SNP_AP_CREATION_REQ {
    ($op: expr, $vmpl: expr, $apic: expr) => {
        (($op) | ((($vmpl) as u64) << 16) | ((($apic) as u64) << 32))
    };
}

// GHCB IN/OUT instruction constants
/// Bit 9
const IOIO_ADDR_64: u64 = BIT!(9);
/// Bit 6
const IOIO_SIZE_32: u64 = BIT!(6);
/// Bit 5
const IOIO_SIZE_16: u64 = BIT!(5);
/// Bit 4
const IOIO_SIZE_8: u64 = BIT!(4);
/// Bit 0
const IOIO_TYPE_IN: u64 = BIT!(0);

static mut HV_FEATURES: u64 = 0;

fn vc_vmgexit() {
    unsafe {
        asm!("rep vmmcall");
    }
}

/// Terminate execution of SVSM
pub fn vc_terminate(reason_set: u64, reason_code: u64) -> ! {
    let mut value: u64;

    value = GHCB_MSR_TERMINATE_REQ;
    value |= reason_set << 12;
    value |= reason_code << 16;

    wrmsr(MSR_GHCB, value);
    vc_vmgexit();

    loop {
        halt()
    }
}

/// Terminate SVSM with generic SVSM reason
#[inline]
pub fn vc_terminate_svsm_general() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_GENERAL);
}

/// Terminate SVSM due to lack of memory
#[inline]
pub fn vc_terminate_svsm_enomem() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_ENOMEM);
}

/// Terminate SVSM due to firmware configuration error
#[inline]
pub fn vc_terminate_svsm_fwcfg() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_FW_CFG_ERROR);
}

/// Terminate SVSM due to invalid GHCB response
#[inline]
pub fn vc_terminate_svsm_resp_invalid() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_GHCB_RESP_INVALID);
}

/// Terminate SVSM due to a page-related error
#[inline]
pub fn vc_terminate_svsm_page_err() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_SET_PAGE_ERROR);
}

/// Terminate SVSM due to a PSC-related error
#[inline]
pub fn vc_terminate_svsm_psc() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_PSC_ERROR);
}

/// Terminate SVSM due to a BIOS-format related error
#[inline]
pub fn vc_terminate_svsm_bios() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_BIOS_FORMAT);
}

/// Terminate SVSM due to an unhandled #VC exception
#[inline]
pub fn vc_terminate_unhandled_vc() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_UNHANDLED_VC);
}

/// Terminate SVSM with generic GHCB reason
#[inline]
pub fn vc_terminate_ghcb_general() -> ! {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_GENERAL);
}

/// Terminate SVSM due to unsupported GHCB protocol
#[inline]
pub fn vc_terminate_ghcb_unsupported_protocol() -> ! {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_UNSUPPORTED_PROTOCOL);
}

/// Terminate SVSM due to error related with feature support
#[inline]
pub fn vc_terminate_ghcb_feature() -> ! {
    vc_terminate(GHCB_REASON_CODE_SET, GHCB_TERM_FEATURE_SUPPORT);
}

/// Terminate SVSM due to incorrect SEV features for VMPL1
#[inline]
pub fn vc_terminate_vmpl1_sev_features() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_VMPL1_SEV_FEATURES);
}

/// Terminate SVSM due to incorrect SEV features for VMPL0
#[inline]
pub fn vc_terminate_vmpl0_sev_features() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_VMPL0_SEV_FEATURES);
}

/// Terminate SVSM due to incorrect VMPL level on VMSA
#[inline]
pub fn vc_terminate_svsm_incorrect_vmpl() -> ! {
    vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_INCORRECT_VMPL);
}

fn vc_msr_protocol(request: u64) -> u64 {
    let response: u64;

    // Save the current GHCB MSR value
    let value: u64 = rdmsr(MSR_GHCB);

    // Perform the MSR protocol
    wrmsr(MSR_GHCB, request);
    vc_vmgexit();
    response = rdmsr(MSR_GHCB);

    // Restore the GHCB MSR value
    wrmsr(MSR_GHCB, value);

    response
}

pub extern "x86-interrupt" fn vc_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    let rip: u64 = stack_frame.instruction_pointer.as_u64();

    prints!(
        "Unhandled #VC exception: {:#?}\n{:#?}\nRIP={rip}\n",
        error_code,
        stack_frame
    );
    vc_terminate_unhandled_vc();
}

fn vc_establish_protocol() {
    let mut response: u64;

    // Request SEV information
    response = vc_msr_protocol(GHCB_MSR_SEV_INFO_REQ);

    // Validate the GHCB protocol version
    if GHCB_MSR_INFO!(response) != GHCB_MSR_SEV_INFO_RES {
        vc_terminate_ghcb_general();
    }

    if GHCB_MSR_PROTOCOL_MIN!(response) > GHCB_PROTOCOL_MAX
        || GHCB_MSR_PROTOCOL_MAX!(response) < GHCB_PROTOCOL_MIN
    {
        vc_terminate_ghcb_unsupported_protocol();
    }

    // Request hypervisor feature support
    response = vc_msr_protocol(GHCB_MSR_HV_FEATURE_REQ);

    // Validate required SVSM feature(s)
    if GHCB_MSR_INFO!(response) != GHCB_MSR_HV_FEATURE_RES {
        vc_terminate_ghcb_general();
    }

    if (GHCB_MSR_HV_FEATURES!(response) & GHCB_SVSM_FEATURES) != GHCB_SVSM_FEATURES {
        vc_terminate_ghcb_feature();
    }

    unsafe {
        HV_FEATURES = GHCB_MSR_HV_FEATURES!(response);
    }
}

fn vc_get_ghcb() -> *mut Ghcb {
    unsafe {
        let va: VirtAddr = PERCPU.ghcb();
        let ghcb: *mut Ghcb = va.as_mut_ptr();

        ghcb
    }
}

unsafe fn vc_perform_vmgexit(ghcb: *mut Ghcb, code: u64, info1: u64, info2: u64) {
    (*ghcb).set_version(GHCB_VERSION_1);
    (*ghcb).set_usage(GHCB_USAGE);

    (*ghcb).set_sw_exit_code(code);
    (*ghcb).set_sw_exit_info_1(info1);
    (*ghcb).set_sw_exit_info_2(info2);

    vc_vmgexit();

    if !(*ghcb).is_sw_exit_info_1_valid() {
        vc_terminate_svsm_resp_invalid();
    }

    let info1: u64 = (*ghcb).sw_exit_info_1();
    if LOWER_32BITS!(info1) != 0 {
        vc_terminate_ghcb_general();
    }
}

/// Each vCPU has two VMSAs: One for VMPL0 (for SVSM) and one for VMPL1 (for
/// the guest).
///
/// The SVSM will use this function to invoke a GHCB NAE event to go back to
/// the guest after handling a request.
///
/// The guest will use the same GHCB NAE event to request something of the SVSM.
///
pub fn vc_run_vmpl(vmpl: VMPL) {
    let ghcb: *mut Ghcb = vc_get_ghcb();

    unsafe {
        vc_perform_vmgexit(ghcb, GHCB_NAE_RUN_VMPL, vmpl as u64, 0);

        (*ghcb).clear();
    }
}

pub fn vc_ap_create(vmsa_va: VirtAddr, apic_id: u32) {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let vmsa: *const Vmsa = vmsa_va.as_u64() as *const Vmsa;

    unsafe {
        let info1: u64 =
            GHCB_NAE_SNP_AP_CREATION_REQ!(SNP_AP_CREATE_IMMEDIATE, (*vmsa).vmpl(), apic_id);
        let info2: u64 = pgtable_va_to_pa(vmsa_va).as_u64();

        (*ghcb).set_rax((*vmsa).sev_features());

        vc_perform_vmgexit(ghcb, GHCB_NAE_SNP_AP_CREATION, info1, info2);

        (*ghcb).clear();
    }
}

pub fn vc_snp_guest_request(
    extended: bool,
    psp_rc: &mut u64,
    cmd: &mut SnpGuestRequestCmd,
) -> Result<(), ()> {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let info1: u64 = pgtable_va_to_pa((*cmd).req_shared_page()).as_u64();
    let info2: u64 = pgtable_va_to_pa((*cmd).resp_shared_page()).as_u64();

    let exit_code: u64 = if extended {
        GHCB_NAE_SNP_EXT_GUEST_REQUEST
    } else {
        GHCB_NAE_SNP_GUEST_REQUEST
    };

    unsafe {
        if extended {
            let data_gpa: u64 = pgtable_va_to_pa((*cmd).data_gva()).as_u64();
            (*ghcb).set_rax(data_gpa);
            (*ghcb).set_rbx((*cmd).data_npages() as u64);
        }

        vc_perform_vmgexit(ghcb, exit_code, info1, info2);

        if !(*ghcb).is_sw_exit_info_2_valid() {
            return Err(());
        }

        *psp_rc = (*ghcb).sw_exit_info_2();

        // The number of expected pages are returned in RBX
        if extended && *psp_rc == SNP_GUEST_REQ_INVALID_LEN {
            (*cmd).set_data_npages((*ghcb).rbx() as usize);
        }

        (*ghcb).clear();
    }

    Ok(())
}

pub fn vc_get_apic_ids(bsp_apic_id: u32) -> Vec<u32> {
    let mut apic_ids: Vec<u32>;
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let pages: u64;

    unsafe {
        (*ghcb).set_rax(0);

        vc_perform_vmgexit(ghcb, GHCB_NAE_GET_APIC_IDS, 0, 0);

        if !(*ghcb).is_rax_valid() {
            vc_terminate_svsm_resp_invalid();
        }

        pages = (*ghcb).rax();

        (*ghcb).clear();
    }

    let frame: PhysFrame = match mem_allocate_frames(pages) {
        Some(f) => f,
        None => vc_terminate_svsm_enomem(),
    };
    let pa: PhysAddr = frame.start_address();
    let va: VirtAddr = pgtable_pa_to_va(pa);

    pgtable_make_pages_shared(va, pages * PAGE_SIZE);
    memset(va.as_mut_ptr(), 0, (pages * PAGE_SIZE) as usize);

    unsafe {
        (*ghcb).set_rax(pages);

        vc_perform_vmgexit(ghcb, GHCB_NAE_GET_APIC_IDS, pa.as_u64(), 0);

        if !(*ghcb).is_rax_valid() {
            vc_terminate_svsm_resp_invalid();
        }

        if (*ghcb).rax() != pages {
            vc_terminate_svsm_resp_invalid();
        }

        (*ghcb).clear();

        let count: *const u32 = va.as_u64() as *const u32;

        if *count == 0 || *count > 4096 {
            vc_terminate_svsm_resp_invalid();
        }

        apic_ids = Vec::with_capacity(*count as usize);

        // BSP is always CPU 0
        apic_ids.push(bsp_apic_id);
        for i in 0..*count {
            let id: *const u32 = (va.as_u64() + 4 + (i as u64 * 4)) as *const u32;
            if *id != bsp_apic_id {
                apic_ids.push(*id);
            }
        }

        // Ensure the BSP APIC ID was present
        assert_eq!(apic_ids.len(), *count as usize);
    }

    pgtable_make_pages_private(va, pages * PAGE_SIZE);
    mem_free_frames(frame, pages);

    apic_ids
}

fn cpuid_calc_xsave_size(features: u64, compact: bool) -> u32 {
    let mut features_found: u64 = 0;
    let mut xsave_size: u32 = 0;

    unsafe {
        let cpuid_page: *mut CpuidPage = get_svsm_cpuid_page().as_mut_ptr() as *mut CpuidPage;

        let count: usize = min(CPUID_COUNT_MAX, (*cpuid_page).count() as usize);
        for i in 0..count {
            let cpuid_entry: CpuidPageEntry = (*cpuid_page).entry(i);

            if cpuid_entry.eax_in() != 0x0000000d {
                continue;
            }

            if cpuid_entry.ecx_in() <= 1 || cpuid_entry.ecx_in() >= 64 {
                continue;
            }

            let feature = BIT!(cpuid_entry.ecx_in());

            // Must be a feature that is being requested
            if (features & feature) == 0 {
                continue;
            }

            // Don't process duplicate entries
            if (features_found & feature) != 0 {
                continue;
            }

            features_found |= feature;

            if compact {
                xsave_size += cpuid_entry.eax();
            } else {
                xsave_size = max(xsave_size, cpuid_entry.eax() + cpuid_entry.ebx());
            }
        }

        if features_found != (features & !3) {
            xsave_size = 0;
        }
    }

    xsave_size
}

fn cpuid_find_entry(leaf: u32, subleaf: u32) -> Option<CpuidPageEntry> {
    let subleaf_used: bool = cpuid_is_subleaf_used(leaf);

    unsafe {
        let cpuid_page: *mut CpuidPage = get_svsm_cpuid_page().as_mut_ptr() as *mut CpuidPage;

        let count: usize = min(CPUID_COUNT_MAX, (*cpuid_page).count() as usize);
        for i in 0..count {
            let cpuid_entry: CpuidPageEntry = (*cpuid_page).entry(i);
            if leaf == cpuid_entry.eax_in() {
                if !subleaf_used || subleaf == cpuid_entry.ecx_in() {
                    return Some(cpuid_entry);
                }
            }
        }
    }

    return None;
}

fn cpuid_is_subleaf_used(leaf: u32) -> bool {
    match leaf {
        0x00000007 => true,
        0x0000000b => true,
        0x0000000d => true,
        0x0000000f => true,
        0x00000010 => true,
        0x8000001d => true,
        0x80000020 => true,

        _ => false,
    }
}

fn vc_cpuid_vmgexit(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    unsafe {
        (*ghcb).set_rax(leaf as u64);
        (*ghcb).set_rcx(subleaf as u64);
        if leaf == CPUID_EXTENDED_STATE {
            if Cr4::read().contains(Cr4Flags::OSXSAVE) {
                (*ghcb).set_xcr0(XCr0::read_raw());
            } else {
                (*ghcb).set_xcr0(1);
            }
        }

        vc_perform_vmgexit(ghcb, GHCB_NAE_CPUID, 0, 0);

        if !(*ghcb).is_rax_valid()
            || !(*ghcb).is_rbx_valid()
            || !(*ghcb).is_rcx_valid()
            || !(*ghcb).is_rdx_valid()
        {
            vc_terminate_svsm_resp_invalid();
        }

        eax = (*ghcb).rax() as u32;
        ebx = (*ghcb).rbx() as u32;
        ecx = (*ghcb).rcx() as u32;
        edx = (*ghcb).rdx() as u32;

        (*ghcb).clear();
    }

    (eax, ebx, ecx, edx)
}

pub fn vc_cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let cpuid_entry: CpuidPageEntry = match cpuid_find_entry(leaf, subleaf) {
        Some(e) => e,
        None => return (0, 0, 0, 0),
    };

    let mut eax: u32 = cpuid_entry.eax();
    let mut ebx: u32 = cpuid_entry.ebx();
    let mut ecx: u32 = cpuid_entry.ecx();
    let mut edx: u32 = cpuid_entry.edx();

    match leaf {
        0x00000001 => {
            let (_, b, _, _) = vc_cpuid_vmgexit(leaf, subleaf);

            // Use hypervisor supplied APIC ID
            ebx &= 0x00ffffff;
            ebx |= b & 0xff000000;

            // Set CPUID_ECX[OSXSAVE] to CR4[OSXSAVE]
            if Cr4::read().contains(Cr4Flags::OSXSAVE) {
                ecx |= BIT!(27);
            } else {
                ecx &= !BIT!(27);
            }
        }
        0x00000007 => {
            // Set CPUID_ECX[OSPKE] to CR4[PKE]
            if Cr4::read().contains(Cr4Flags::PROTECTION_KEY_USER) {
                ecx |= BIT!(4);
            } else {
                ecx &= !BIT!(4);
            }
        }
        0x0000000b => {
            let (_, _, _, d) = vc_cpuid_vmgexit(leaf, subleaf);

            // Use hypervisor supplied extended APIC ID
            edx = d;
        }
        0x0000000d => {
            if subleaf == 0 || subleaf == 1 {
                let compact: bool;
                let xcr0: u64;
                let xss: u64;

                if Cr4::read().contains(Cr4Flags::OSXSAVE) {
                    xcr0 = XCr0::read_raw();
                } else {
                    xcr0 = 1;
                }

                if subleaf == 1 {
                    compact = true;

                    if (eax & BIT!(3)) != 0 {
                        xss = rdmsr(0x00000da0);
                    } else {
                        xss = 0;
                    }
                } else {
                    compact = false;

                    xss = 0;
                }

                ebx = cpuid_calc_xsave_size(xcr0 | xss, compact);
            }
        }
        0x8000001e => {
            let (a, b, c, _) = vc_cpuid_vmgexit(leaf, subleaf);

            // Use hypervisor supplied extended APIC ID
            eax = a;

            // Use hypervisor supplied topology information
            ebx = b;
            ecx = c;
        }
        _ => {}
    }

    (eax, ebx, ecx, edx)
}

pub fn vc_outl(port: u16, value: u32) {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let mut ioio: u64 = (port as u64) << 16;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_32;

    unsafe {
        (*ghcb).set_rax(value as u64);

        vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

        (*ghcb).clear();
    }
}

pub fn vc_inl(port: u16) -> u32 {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let mut ioio: u64 = (port as u64) << 16;
    let value: u32;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_32;
    ioio |= IOIO_TYPE_IN;

    unsafe {
        (*ghcb).set_rax(0);

        vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

        if !(*ghcb).is_rax_valid() {
            vc_terminate_svsm_resp_invalid();
        }

        value = LOWER_32BITS!((*ghcb).rax()) as u32;

        (*ghcb).clear();
    }

    value
}

pub fn vc_outw(port: u16, value: u16) {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let mut ioio: u64 = (port as u64) << 16;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_16;

    unsafe {
        (*ghcb).set_rax(value as u64);

        vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

        (*ghcb).clear();
    }
}

pub fn vc_inw(port: u16) -> u16 {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let mut ioio: u64 = (port as u64) << 16;
    let value: u16;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_16;
    ioio |= IOIO_TYPE_IN;

    unsafe {
        (*ghcb).set_rax(0);

        vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

        if !(*ghcb).is_rax_valid() {
            vc_terminate_svsm_resp_invalid();
        }

        value = LOWER_16BITS!((*ghcb).rax()) as u16;

        (*ghcb).clear();
    }

    value
}

pub fn vc_outb(port: u16, value: u8) {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let mut ioio: u64 = (port as u64) << 16;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_8;

    unsafe {
        (*ghcb).set_rax(value as u64);

        vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

        (*ghcb).clear();
    }
}

pub fn vc_inb(port: u16) -> u8 {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    let mut ioio: u64 = (port as u64) << 16;
    let value: u8;

    ioio |= IOIO_ADDR_64;
    ioio |= IOIO_SIZE_8;
    ioio |= IOIO_TYPE_IN;

    unsafe {
        (*ghcb).set_rax(0);

        vc_perform_vmgexit(ghcb, GHCB_NAE_IOIO, ioio, 0);

        if !(*ghcb).is_rax_valid() {
            vc_terminate_svsm_resp_invalid();
        }

        value = LOWER_8BITS!((*ghcb).rax()) as u8;

        (*ghcb).clear();
    }

    value
}

pub fn vc_register_ghcb(pa: PhysAddr) {
    // Perform GHCB registration
    let response: u64 = vc_msr_protocol(GHCB_MSR_REGISTER_GHCB!(pa.as_u64()));

    // Validate the response
    if GHCB_MSR_INFO!(response) != GHCB_MSR_REGISTER_GHCB_RES {
        vc_terminate_svsm_general();
    }

    if GHCB_MSR_DATA!(response) != pa.as_u64() {
        vc_terminate_svsm_general();
    }

    wrmsr(MSR_GHCB, pa.as_u64());
}

const PSC_SHARED: u64 = 2 << 52;
const PSC_PRIVATE: u64 = 1 << 52;
const PSC_ENTRIES: usize = (SHARED_BUFFER_SIZE - size_of::<PscOpHeader>()) / 8;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct PscOpHeader {
    pub cur_entry: u16,
    pub end_entry: u16,
    pub reserved: u32,
}

#[allow(dead_code)]
impl PscOpHeader {
    pub const fn new() -> Self {
        PscOpHeader {
            cur_entry: 0,
            end_entry: 0,
            reserved: 0,
        }
    }
    funcs!(cur_entry, u16);
    funcs!(end_entry, u16);
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct PscOpData {
    pub data: u64,
}

#[allow(dead_code)]
impl PscOpData {
    pub const fn new() -> Self {
        PscOpData { data: 0 }
    }
    funcs!(data, u64);
}

#[repr(C, packed)]
struct PscOp {
    pub header: PscOpHeader,
    pub entries: [PscOpData; PSC_ENTRIES],
}

#[allow(dead_code)]
impl PscOp {
    pub const fn new() -> Self {
        let h: PscOpHeader = PscOpHeader::new();
        let d: PscOpData = PscOpData::new();

        PscOp {
            header: h,
            entries: [d; PSC_ENTRIES],
        }
    }
    funcs!(header, PscOpHeader);
    funcs!(entries, [PscOpData; PSC_ENTRIES]);
}

macro_rules! GHCB_2MB_PSC_ENTRY {
    ($x: expr, $y: expr) => {
        ((($x) | ($y) | (1 << 56)) as u64)
    };
}

macro_rules! GHCB_4KB_PSC_ENTRY {
    ($x: expr, $y: expr) => {
        ((($x) | ($y)) as u64)
    };
}

macro_rules! GHCB_PSC_GPA {
    ($x: expr) => {
        ((($x) & ((1 << 52) - 1)) as u64)
    };
}

macro_rules! GHCB_PSC_SIZE {
    ($x: expr) => {
        (((($x) >> 56) & 1) as u32)
    };
}

fn pvalidate_psc_entries(op: &mut PscOp, pvalidate_op: u32) {
    let first_entry: usize = op.header.cur_entry as usize;
    let last_entry: usize = op.header.end_entry as usize + 1;

    for i in first_entry..last_entry {
        let gpa: u64 = GHCB_PSC_GPA!(op.entries[i].data);
        let size: u32 = GHCB_PSC_SIZE!(op.entries[i].data);

        let mut va: VirtAddr = pgtable_pa_to_va(PhysAddr::new(gpa));
        let mut ret: u32 = pvalidate(va.as_u64(), size, pvalidate_op);
        if ret == PVALIDATE_FAIL_SIZE_MISMATCH && size > 0 {
            let va_end = va + PAGE_2MB_SIZE;

            while va < va_end {
                ret = pvalidate(va.as_u64(), 0, pvalidate_op);
                if ret != 0 {
                    break;
                }

                va += PAGE_SIZE;
            }
        }

        if ret != 0 {
            vc_terminate_svsm_psc();
        }
    }
}

fn build_psc_entries(op: &mut PscOp, begin: PhysAddr, end: PhysAddr, page_op: u64) -> PhysAddr {
    let mut pa: PhysAddr = begin;
    let mut i: usize = 0;

    while pa < end && i < PSC_ENTRIES {
        if pa.is_aligned(PAGE_2MB_SIZE) && (end - pa) >= PAGE_2MB_SIZE {
            op.entries[i].data = GHCB_2MB_PSC_ENTRY!(pa.as_u64(), page_op);
            pa += PAGE_2MB_SIZE;
        } else {
            op.entries[i].data = GHCB_4KB_PSC_ENTRY!(pa.as_u64(), page_op);
            pa += PAGE_SIZE;
        }
        op.header.end_entry = i as u16;

        i += 1;
    }

    return pa;
}

fn perform_page_state_change(ghcb: *mut Ghcb, begin: PhysFrame, end: PhysFrame, page_op: u64) {
    let mut op: PscOp = PscOp::new();

    let mut pa: PhysAddr = begin.start_address();
    let pa_end: PhysAddr = end.start_address();

    while pa < pa_end {
        op.header.cur_entry = 0;
        pa = build_psc_entries(&mut op, pa, pa_end, page_op);

        let last_entry: u16 = op.header.end_entry;

        if page_op == PSC_SHARED {
            pvalidate_psc_entries(&mut op, RESCIND);
        }

        let size: usize =
            size_of::<PscOpHeader>() + size_of::<PscOpData>() * (last_entry as usize + 1);
        unsafe {
            let set_bytes: *const u8 = &op as *const PscOp as *const u8;
            let get_bytes: *mut u8 = &mut op as *mut PscOp as *mut u8;

            (*ghcb).clear();

            (*ghcb).set_shared_buffer(set_bytes, size);

            while op.header.cur_entry <= last_entry {
                vc_perform_vmgexit(ghcb, GHCB_NAE_PSC, 0, 0);
                if !(*ghcb).is_sw_exit_info_2_valid() || (*ghcb).sw_exit_info_2() != 0 {
                    vc_terminate_svsm_psc();
                }

                (*ghcb).shared_buffer(get_bytes, size);
            }
        }

        if page_op == PSC_PRIVATE {
            op.header.cur_entry = 0;
            op.header.end_entry = last_entry;
            pvalidate_psc_entries(&mut op, VALIDATE);
        }
    }
}

pub fn vc_make_pages_shared(begin: PhysFrame, end: PhysFrame) {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    perform_page_state_change(ghcb, begin, end, PSC_SHARED)
}

pub fn vc_make_page_shared(frame: PhysFrame) {
    vc_make_pages_shared(frame, frame + 1)
}

pub fn vc_make_pages_private(begin: PhysFrame, end: PhysFrame) {
    let ghcb: *mut Ghcb = vc_get_ghcb();
    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE)
}

pub fn vc_make_page_private(frame: PhysFrame) {
    vc_make_pages_private(frame, frame + 1)
}

pub fn vc_early_make_pages_private(begin: PhysFrame, end: PhysFrame) {
    let ghcb: *mut Ghcb = get_early_ghcb().as_mut_ptr() as *mut Ghcb;

    perform_page_state_change(ghcb, begin, end, PSC_PRIVATE);
}

pub fn vc_init() {
    let ghcb_pa: PhysAddr = pgtable_va_to_pa(get_early_ghcb());

    vc_establish_protocol();
    vc_register_ghcb(ghcb_pa);
}
