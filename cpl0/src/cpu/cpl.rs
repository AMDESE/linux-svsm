/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

use crate::pgtable::*;
use crate::util::locking::{LockGuard, SpinLock};
use crate::*;
use core::arch::asm;
use lazy_static::lazy_static;
use x86_64::VirtAddr;

// Size of the stack for the user
/// 4
pub const USER_STACK_SIZE: u64 = 4;

lazy_static! {
    // SpinLock to serialize printing of CPU's userspace information
    static ref USER_INFO_MUTEX: SpinLock<()> = SpinLock::new(());
}

#[allow(dead_code)]
fn iretq(ss: u64, stack: u64, cs: u64, code: u64) {
    unsafe {
        let stack_pointer: u64;

        // Save kernel stack for SYSCALL
        asm!("mov {0}, rsp", out(reg) stack_pointer);
        PERCPU.set_kernel_stack(VirtAddr::new(stack_pointer));

        // Make sure user's GS is zero
        wrmsr(MSR_KERNEL_GS_BASE, 0);

        // IRETQ will pop for long mode: RIP, CS, RFLAGS, RSP, SS
        // We add plus 3 on CS and SS to signify CPL=3 (see svsm.h)
        asm!("push rax",
             "push r8",
             "pushfq",
             "push rcx",
             "push rdx",
             "swapgs",
             "iretq",
             in("rax") ss,
             in("r8") stack,
             in("rcx") cs,
             in("rdx") code);
    }
}

fn print_user_info(
    user_stack: u64,
    user_stack_end: u64,
    user_code: u64,
    code_end: u64,
    stack_size: u64,
    code_size: u64,
) {
    let _guard: LockGuard<()> = USER_INFO_MUTEX.lock();

    prints!(
        "\n> SVSM userspace info:\n   Stack start={:#x}  Stack end={:#x}, Stack size={:#x}\n",
        user_stack,
        user_stack_end,
        stack_size
    );
    prints!(
        "   Code start={:#x}   Code end={:#x}\n",
        user_code,
        code_end
    );

    prints!("   Pages of code={}\n", code_size);
    prints!("   ---\n   User stack flags:\n");
    pgtable_print_pte_va(VirtAddr::new(user_stack));

    prints!("   --\n   User code flags:\n");
    pgtable_print_pte_va(VirtAddr::new(user_code));
}

fn jump_to_user(user_stack_va: VirtAddr, user_code_va: VirtAddr, user_code_end: VirtAddr) {
    // Make stack point to its end
    let stack_size: u64 = PAGE_SIZE * USER_STACK_SIZE;
    let code_pages: u64 = ((user_code_end.as_u64() - user_code_va.as_u64()) / PAGE_SIZE) + 1;

    let new_ucode_va: VirtAddr = VirtAddr::new(get_cpl3_start());
    let new_ucode_end: VirtAddr = VirtAddr::new(get_cpl3_start() + (code_pages - 1_u64) * PAGE_SIZE);

    let new_stack_va: VirtAddr = new_ucode_va - stack_size - PAGE_SIZE;

    if map_user_code(new_ucode_va, pgtable_va_to_pa(user_code_va), code_pages) == false {
        prints!("Required page table updates for user code failed!\n");
        vc_terminate_svsm_page_err();
    }

    if map_user_stack(
        new_stack_va,
        pgtable_va_to_pa(user_stack_va),
        USER_STACK_SIZE,
    ) == false
    {
        prints!("Required page table updates for user stack failed!\n");
        vc_terminate_svsm_page_err();
    }

    // Print userspace information of this CPU
    print_user_info(
        new_stack_va.as_u64(),
        new_stack_va.as_u64() + stack_size,
        new_ucode_va.as_u64(),
        new_ucode_end.as_u64(),
        stack_size,
        code_pages,
    );

    iretq(
        get_gdt64_user64_ds(),
        new_stack_va.as_u64(),
        get_gdt64_user64_cs(),
        new_ucode_va.as_u64(),
    );
}

/// Retrieve addresses for user code start and end
fn user_code_va_addr() -> (VirtAddr, VirtAddr) {
    let user_code_va: VirtAddr = get_svsm_edata();
    let user_code_end_va: VirtAddr = get_svsm_size();
    (user_code_va, user_code_end_va)
}

/// Jump from CPL0 to CPL3
/// Information on userspace will be printed if on verbose mode
pub fn cpl_go_unprivileged() {
    let user_stack_va: VirtAddr;
    let user_code_va: VirtAddr;
    let user_code_va_end: VirtAddr;

    // Create stack for userspace
    // Because mem_create_stack() adds guard page, move end address
    user_stack_va = mem_create_stack(USER_STACK_SIZE, true) - PAGE_SIZE;

    (user_code_va, user_code_va_end) = user_code_va_addr();

    jump_to_user(user_stack_va, user_code_va, user_code_va_end);
}

/// Prepare user code for CPL switching
pub fn cpl_init() {
    lazy_static::initialize(&USER_INFO_MUTEX);
}
