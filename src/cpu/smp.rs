/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::percpu::PERCPU;
use crate::cpu::vc::*;
use crate::cpu::vmsa::*;
use crate::cpu::*;
use crate::globals::*;
use crate::mem::*;
use crate::svsm_request::*;
use crate::*;

use core::intrinsics::size_of;
use x86_64::addr::{PhysAddr, VirtAddr};
use x86_64::instructions::tables::{sgdt, sidt};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::structures::DescriptorTablePointer;

/// Bit 4
const SEGMENT_TYPE_SUPERVISOR: u16 = BIT!(4);
/// Bit 7
const SEGMENT_TYPE_PRESENT: u16 = BIT!(7);
/// Bit 9
const SEGMENT_TYPE_LONGMODE: u16 = BIT!(9);

/// 0x029a
const SVSM_CS_TYPE: u16 =
    0x0a | SEGMENT_TYPE_PRESENT | SEGMENT_TYPE_SUPERVISOR | SEGMENT_TYPE_LONGMODE;
/// 0xffffffff
const SVSM_CS_LIMIT: u32 = 0xffffffff;
/// 0
const SVSM_CS_BASE: u64 = 0;

/// 0x0089
pub const SVSM_TSS_TYPE: u16 = 0x9 | SEGMENT_TYPE_PRESENT;

/// 0x80010033
const SVSM_CR0: u64 = 0x80010033; /* PG, WP, NE, ET, MP, PE */
/// 0x668
const SVSM_CR4: u64 = 0x668; /* OSXMMEXCPT, OSFXSR, MCE, PAE, DE */
/// 0xffff0ff0
const SVSM_DR6: u64 = 0xffff0ff0;
/// 0x400
const SVSM_DR7: u64 = 0x400;
/// 0x1d00
const SVSM_EFER: u64 = 0x1d00; /* SVME, NXE, LMA, LME */
/// 0x0007040600070406
const SVSM_GPAT: u64 = 0x0007040600070406;
/// 0x1
const SVSM_XCR0: u64 = 0x1;
/// 0x1f80
const SVSM_MXCSR: u32 = 0x1f80;
/// 0x2
const SVSM_RFLAGS: u64 = 0x2;
/// 0x5555
const SVSM_X87_FTW: u16 = 0x5555;
/// 0x40
const SVSM_X87_FCW: u16 = 0x40;

/// 5
const SVSM_STACK_PAGES: u64 = 5; /* 4 stack pages and one guard page */

static mut AP_SYNC: u8 = 0;
/// 1
const AP_STARTING: u8 = 1;
/// 2
const AP_STARTED: u8 = 2;

/// Function executed for each AP when booted
pub extern "C" fn ap_entry() -> ! {
    unsafe {
        vc_register_ghcb(pgtable_va_to_pa(PERCPU.ghcb()));
        BARRIER!();
        AP_SYNC = AP_STARTED;
    }

    halt();
    svsm_request_loop();

    loop {
        halt()
    }
}

fn alloc_vmsa() -> PhysFrame {
    // Allocate one frame
    let mut frame: PhysFrame = match mem_allocate_frames(1) {
        Some(f) => f,
        None => vc_terminate_svsm_enomem(),
    };

    // VMSA pages must not be 2MB aligned, check for that
    if frame.start_address().is_aligned(PAGE_2MB_SIZE) {
        // Free aligned frame
        mem_free_frame(frame);

        // Allocate two frames and ...
        frame = match mem_allocate_frames(2) {
            Some(f) => f,
            None => vc_terminate_svsm_enomem(),
        };

        // ... chose a frame which is not 2MB aligned
        if frame.start_address().is_aligned(PAGE_2MB_SIZE) {
            frame += 1;
        }
    }

    return frame;
}

unsafe fn __create_bios_vmsa(vmsa_va: VirtAddr) {
    let bsp_page_va: VirtAddr = pgtable_pa_to_va(PhysAddr::new(bios_vmsa_page));

    let vmsa: *mut Vmsa = vmsa_va.as_mut_ptr();
    let bsp_page: *const Vmsa = bsp_page_va.as_ptr();

    // Copy the measured BIOS BSP VMSA page
    *vmsa = *bsp_page;

    if (*vmsa).vmpl() != VMPL::Vmpl1 as u8 {
        vc_terminate_svsm_incorrect_vmpl();
    }

    // Check the SEV-SNP VMSA SEV features to make sure guest will
    // execute with supported SEV features. It is better to not fix
    // the SEV features ourselves, since this could indicate an issue
    // on the hypervisor side.

    if (*vmsa).sev_features() & VMPL1_REQUIRED_SEV_FEATS != VMPL1_REQUIRED_SEV_FEATS {
        vc_terminate_vmpl1_sev_features();
    }

    if (*vmsa).sev_features() & VMPL1_UNSUPPORTED_SEV_FEATS != 0 {
        vc_terminate_vmpl1_sev_features();
    }
}

fn create_bios_vmsa() -> VirtAddr {
    let frame: PhysFrame = alloc_vmsa();
    let vmsa_va: VirtAddr = pgtable_pa_to_va(frame.start_address());

    unsafe { __create_bios_vmsa(vmsa_va) }

    vmsa_va
}

/// Create stack for an AP
fn create_svsm_stack() -> VirtAddr {
    let frame: PhysFrame = match mem_allocate_frames(SVSM_STACK_PAGES) {
        Some(f) => f,
        None => vc_terminate_svsm_enomem(),
    };

    let guard_va: VirtAddr = pgtable_pa_to_va(frame.start_address());
    let stack_va: VirtAddr = pgtable_pa_to_va((frame + 1).start_address());

    pgtable_make_pages_np(guard_va, PAGE_SIZE);
    pgtable_make_pages_nx(stack_va, (SVSM_STACK_PAGES - 1) * PAGE_SIZE);

    let stack: VirtAddr = pgtable_pa_to_va((frame + SVSM_STACK_PAGES).start_address());

    stack
}

/// Create VMSA (execution context information) for an AP
fn create_svsm_vmsa(for_id: usize) -> VirtAddr {
    let frame: PhysFrame = alloc_vmsa();
    let vmsa_va: VirtAddr = pgtable_pa_to_va(frame.start_address());
    let vmsa: *mut Vmsa = vmsa_va.as_mut_ptr();

    let gdtr: DescriptorTablePointer = sgdt();
    let idtr: DescriptorTablePointer = sidt();
    let gs: VirtAddr = percpu_address(for_id);
    let tss: VirtAddr = tss_init_for(for_id);

    unsafe {
        (*vmsa).set_cs_selector(gdt64_kernel_cs as u16);
        (*vmsa).set_cs_rtype(SVSM_CS_TYPE);
        (*vmsa).set_cs_limit(SVSM_CS_LIMIT);
        (*vmsa).set_cs_base(SVSM_CS_BASE);

        (*vmsa).set_tr_selector(gdt64_tss as u16);
        (*vmsa).set_tr_rtype(SVSM_TSS_TYPE);
        (*vmsa).set_tr_limit(size_of::<TaskStateSegment>() as u32 - 1);
        (*vmsa).set_tr_base(tss.as_u64());

        (*vmsa).set_gs_base(gs.as_u64());

        (*vmsa).set_rip(cpu_start);

        (*vmsa).set_gdtr_limit(gdtr.limit as u32);
        (*vmsa).set_gdtr_base(gdtr.base.as_u64());

        (*vmsa).set_idtr_limit(idtr.limit as u32);
        (*vmsa).set_idtr_base(idtr.base.as_u64());

        (*vmsa).set_cr0(SVSM_CR0);
        (*vmsa).set_cr3(Cr3::read().0.start_address().as_u64());
        (*vmsa).set_cr4(SVSM_CR4);
        (*vmsa).set_efer(SVSM_EFER);
        (*vmsa).set_rflags(SVSM_RFLAGS);
        (*vmsa).set_dr6(SVSM_DR6);
        (*vmsa).set_dr7(SVSM_DR7);
        (*vmsa).set_gpat(SVSM_GPAT);
        (*vmsa).set_xcr0(SVSM_XCR0);
        (*vmsa).set_mxcsr(SVSM_MXCSR);
        (*vmsa).set_x87_ftw(SVSM_X87_FTW);
        (*vmsa).set_x87_fcw(SVSM_X87_FCW);

        (*vmsa).set_vmpl(VMPL::Vmpl0 as u8);
        (*vmsa).set_sev_features(rdmsr(MSR_SEV_STATUS) >> 2);
    }

    vmsa_va
}

/// Start a given AP, which includes creating a Stack and Vmsa
fn ap_start(cpu_id: usize) -> bool {
    let apic_id: u32 = unsafe { PERCPU.apic_id_for(cpu_id) };

    let vmsa: VirtAddr = create_svsm_vmsa(cpu_id);

    let ret: u32 = rmpadjust(vmsa.as_u64(), RMP_4K, VMSA_PAGE | VMPL::Vmpl1 as u64);
    if ret != 0 {
        vc_terminate_svsm_general();
    }

    let stack: VirtAddr = create_svsm_stack();
    unsafe {
        cpu_stack = stack.as_u64();
    }

    unsafe {
        PERCPU.set_vmsa_for(vmsa, VMPL::Vmpl0, cpu_id);

        AP_SYNC = AP_STARTING;
        BARRIER!();

        vc_ap_create(vmsa, apic_id);

        while AP_SYNC != AP_STARTED {
            pause();
        }
    }

    true
}

/// Retrieve Vmpl1 Vmsa and start it
pub fn smp_run_bios_vmpl() -> bool {
    unsafe {
        // Retrieve VMPL1 VMSA and start it
        let vmsa: VirtAddr = PERCPU.vmsa(VMPL::Vmpl1);
        if vmsa == VirtAddr::zero() {
            return false;
        }

        vc_ap_create(vmsa, PERCPU.apic_id());
    }

    true
}

/// Create a Vmsa and Caa and prepare them
pub fn smp_prepare_bios_vmpl(caa_pa: PhysAddr) -> bool {
    let vmsa: VirtAddr = create_bios_vmsa();
    let caa: VirtAddr = match pgtable_map_pages_private(caa_pa, 8) {
        Ok(c) => c,
        Err(_e) => return false,
    };

    unsafe {
        PERCPU.set_vmsa(vmsa, VMPL::Vmpl1);
        PERCPU.set_caa(caa, VMPL::Vmpl1);
    }

    // Update the permissions for the CAA and VMSA page.
    //
    // For the VMSA page, restrict it to read-only (at most) to prevent a guest
    // from attempting to alter the VMPL level within the VMSA.
    //
    // On error, do not try to reset the VMPL permission state for the pages,
    // just leak them.
    //
    // The lower VMPL has not been run, yet, so no TLB flushing is needed.
    //
    let ret: u32 = rmpadjust(caa.as_u64(), RMP_4K, VMPL_RWX | VMPL::Vmpl1 as u64);
    if ret != 0 {
        return false;
    }

    let ret: u32 = rmpadjust(vmsa.as_u64(), RMP_4K, VMPL_R | VMPL::Vmpl1 as u64);
    if ret != 0 {
        return false;
    }

    let vmin: u64 = VMPL::Vmpl2 as u64;
    let vmax: u64 = VMPL::VmplMax as u64;
    for i in vmin..vmax {
        let ret: u32 = rmpadjust(caa.as_u64(), RMP_4K, i);
        if ret != 0 {
            return false;
        }

        let ret: u32 = rmpadjust(vmsa.as_u64(), RMP_4K, i);
        if ret != 0 {
            return false;
        }
    }

    let ret: u32 = rmpadjust(vmsa.as_u64(), RMP_4K, VMPL_VMSA | VMPL::Vmpl1 as u64);
    if ret != 0 {
        return false;
    }

    unsafe {
        svsm_request_add_init_vmsa(vmsa, PERCPU.apic_id());
    }

    true
}

/// Get CPU id for a given Apic Id
pub fn smp_get_cpu_id(apic_id: u32) -> Option<usize> {
    unsafe {
        for i in 0..percpu_count() {
            if PERCPU.apic_id_for(i) == apic_id {
                return Some(i);
            }
        }
    }

    return None;
}

unsafe fn __smp_init() {
    hl_main = ap_entry as u64;
    cpu_mode = 1;

    let count: usize = percpu_count();
    let aux: usize = count - 1;

    prints!("> Starting SMP for {aux} APs:\n");

    for i in 1..count {
        if !ap_start(i) {
            vc_terminate_svsm_general();
        }
        prints!("-- AP {i}/{aux} initialized.\n");
    }
}

/// Boot other CPUs (APs)
pub fn smp_init() {
    unsafe {
        __smp_init();
    }
}
