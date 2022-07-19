/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

#![feature(core_intrinsics)]
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
/// Handle requests from the SVSM guest
pub mod svsm_request;
/// Auxiliary functions and macros
pub mod util;

extern crate alloc;

use crate::bios::start_bios;
use crate::cpu::rmpadjust;
use crate::cpu::*;
use crate::globals::*;
use crate::mem::*;
use crate::svsm_request::svsm_request_loop;
use crate::util::*;

use core::panic::PanicInfo;

extern "C" {
    static sev_encryption_mask: u64;
    static svsm_begin: u64;
    static svsm_end: u64;
    static dyn_mem_begin: u64;
    static dyn_mem_end: u64;
    static early_ghcb: u64;
    static svsm_sbss: u64;
    static svsm_ebss: u64;
    static svsm_sdata: u64;
    static svsm_edata: u64;
    static guard_page: u64;
    static mut hl_main: u64;
    static mut cpu_mode: u64;
    static mut cpu_stack: u64;
    static cpu_start: u64;
    static svsm_secrets_page: u64;
    static svsm_cpuid_page: u64;
    static svsm_cpuid_page_size: u64;
    static bios_vmsa_page: u64;
}

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

    unsafe {
        let ret: u32 = rmpadjust(svsm_begin, RMP_4K, VMPL::Vmpl1 as u64);
        if ret != 0 {
            vc_terminate(SVSM_REASON_CODE_SET, SVSM_TERM_NOT_VMPL0);
        }
    }
}

/// Main function. Initialize everything and start request loop.
/// This function never returns.
#[no_mangle]
pub extern "C" fn svsm_main() -> ! {
    // Ensure execution at VMPL0
    check_vmpl_level();

    // Initialize exception/interrupt handling
    idt_init();

    // Prepare VC handler
    vc_init();

    mem_init();

    // Create 4-level page table and load it
    pgtable_init();

    // Allocate per-CPU data (pointed to by GS register)
    percpu_init();

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
