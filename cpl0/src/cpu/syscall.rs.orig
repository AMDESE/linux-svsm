/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

use crate::*;

/// Returns what MSR STAR should have to allow syscall/sysret
pub fn syscall_gdt() -> u64 {
    // Needed for SYSRET
    let gdt_user32_cs: u64 = get_gdt64_user32_cs() << 48;

    // Needed for SYSCALL
    let gdt_kernel_cs: u64 = get_gdt64_kernel_cs() << 32;

    gdt_user32_cs | gdt_kernel_cs
}

/// Prepare system calls and CPL switches
/// SYSCALL/SYSRET is already enabled in MSR EFER (see start/svsm.h)
pub fn syscall_init() {
    // GDT entries for SYSCALL/SYSRET
    wrmsr(MSR_STAR, syscall_gdt());

    // Disable interrupts when entering a system call
    wrmsr(MSR_SFMASK, SFMASK_INTERRUPTS_DISABLED);
}
