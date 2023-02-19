/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

#![feature(type_ascription)]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
// Disable the (implicitly-linked) standard library. #! defines behavior of the current module; as
// we are in root, the entire crate is affected.
#![no_std]
// We cannot use the Rust runtime, Hence we don't have the C start point (C run time 0 aka crt0).
// Tell the compiler we don't want to use the normal entry chain. Nobody calls main(), since we
// overwrite _start().
#![no_main]

/// Initialize BIOS for the guest
pub mod bios;
/// Prepare and start SMP
pub mod cpu;
/// Global constants
pub mod globals;
/// Prepare page table, handle memory (de)allocations
pub mod mem;
/// Implementation of SVSM protocols and calls
pub mod protocols;
/// Handle requests from the SVSM guest
pub mod svsm_request;
/// Auxiliary functions and macros
pub mod util;
/// Handle the list of VMSA pages
pub mod vmsa_list;

extern crate alloc;

use crate::bios::start_bios;
use crate::cpu::rmpadjust;
use crate::cpu::*;
use crate::globals::*;
use crate::mem::*;
use crate::svsm_request::svsm_request_loop;
use crate::util::*;
use crate::vmsa::*;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(panic_info: &PanicInfo) -> ! {
    prints!("PANIC!\n{}\nPANIC!\n", panic_info);
    loop {}
}

/// Use the RMPADJUST instruction to determine if the SVSM is executing at VMPL0
fn check_vmpl_level() {
    // Use the RMPADJUST instruction to determine if the SVSM is executing
    // at VMPL0. The RMPADJUST instruction can only update the attributes
    // of a lower VMPL-level (e.g.: VMPL0 can change VMPL1, VMPL2 or VMPL3).
    // By attempting to change the VMPL1 attributes of a page, it can be
    // determined if the SVSM is executing at VMPL0.
    //
    // Attempt to clear the VMPL1 attributes of the early GHCB page.

    let ret: u32 = rmpadjust(get_svsm_begin().as_u64(), RMP_4K, VMPL::Vmpl1 as u64);
    if ret != 0 {
        vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_NOT_VMPL0);
    }
}

/// Check addresses are appropriately aligned and within boundaries
fn check_svsm_address() {
    let total_size: u64 = get_svsm_end().as_u64() - get_svsm_begin().as_u64();
    if !PAGE_2MB_ALIGNED!(get_svsm_begin().as_u64()) || !PAGE_2MB_ALIGNED!(total_size) {
        vc_terminate_svsm_general();
    }
    // svsm_end is SVSM_GVA + SVSM_MEM. dyn_mem_begin is calculated based on
    // edata, so make sure it is within boundaries
    if get_svsm_end() < get_dyn_mem_begin() {
        vc_terminate_svsm_general();
    }
}

/// Check SVSM is running with adequate SEV features
fn check_vmpl0_features() {
    let features: u64 = rdmsr(MSR_SEV_STATUS) >> 2;

    if features & VMPL0_REQUIRED_SEV_FEATS != VMPL0_REQUIRED_SEV_FEATS {
        vc_terminate_vmpl0_sev_features();
    }

    if features & VMPL0_UNSUPPORTED_SEV_FEATS != 0 {
        vc_terminate_vmpl0_sev_features();
    }
}

/// Perform initial checkings to ensure adequate execution.
/// This means checking SVSM runs on VMPL0, with proper addresses
/// and sizes, and proper SEV features activate
fn initial_checks() {
    // Ensure execution at VMPL0
    check_vmpl_level();

    // Ensure we are running with proper SEV features
    check_vmpl0_features();

    // Ensure SVSM addresses and sizes are appropiate
    check_svsm_address();
}

/// Main function. Initialize everything and start request loop.
/// This function never returns.
#[no_mangle]
pub extern "C" fn svsm_main() -> ! {
    // Ensure valid SVSM execution environment
    initial_checks();

    // Initialize exception/interrupt handling
    idt_init();

    // Prepare VC handler
    vc_init();

    mem_init();

    // Create 4-level page table and load it
    pgtable_init();

    // Allocate per-CPU data (pointed to by GS register)
    percpu_init();

    // Set up the TSS
    tss_init();

    ghcb_init();

    serial_init();

    fwcfg_init();

    // Initialize and start APs
    smp_init();

    // Load BIOS
    start_bios();

    // Start taking requests from guest in this vCPU
    svsm_request_loop();

    // We should never reach this point
    loop {
        halt()
    }
}
