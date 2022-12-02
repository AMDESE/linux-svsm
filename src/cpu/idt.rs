/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use alloc::string::String;

use lazy_static::lazy_static;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::cpu::vc_handler;
use crate::DOUBLE_FAULT_IST;

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt: InterruptDescriptorTable = InterruptDescriptorTable::new();

        unsafe {
            idt.double_fault
                .set_handler_fn(df_handler)
                .set_stack_index(DOUBLE_FAULT_IST as u16);
        }
        idt.general_protection_fault.set_handler_fn(gp_handler);
        idt.page_fault.set_handler_fn(pf_handler);
        idt.vmm_communication_exception.set_handler_fn(vc_handler);

        idt
    };
}

fn do_panic(stack_frame: InterruptStackFrame, name: &str, error_code: u64) -> ! {
    let rip: u64 = stack_frame.instruction_pointer.as_u64();
    let msg: String = alloc::format!(
        "#{} at RIP {:#0x} with error code {:#0x}",
        name,
        rip,
        error_code
    );

    panic!("{}", msg);
}

/// Double fault handler
/// Every interruption except for #PF, #VC and #GP will end up here
extern "x86-interrupt" fn df_handler(stack_frame: InterruptStackFrame, _error_code: u64) -> ! {
    do_panic(stack_frame, "DF", 0)
}

/// General protection fault handler
extern "x86-interrupt" fn gp_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    do_panic(stack_frame, "GP", error_code)
}

/// Page fault handler
extern "x86-interrupt" fn pf_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    do_panic(stack_frame, "PF", error_code.bits())
}

/// Load IDT with function handlers for each exception
pub fn idt_init() {
    IDT.load();
}
