/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::vc_handler;

use lazy_static::lazy_static;
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::structures::idt::PageFaultErrorCode;

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt: InterruptDescriptorTable = InterruptDescriptorTable::new();

        idt.divide_error.set_handler_fn(de_handler);
        idt.debug.set_handler_fn(db_handler);
        idt.non_maskable_interrupt.set_handler_fn(nmi_handler);
        idt.breakpoint.set_handler_fn(bp_handler);
        idt.overflow.set_handler_fn(of_handler);
        idt.bound_range_exceeded.set_handler_fn(br_handler);
        idt.invalid_opcode.set_handler_fn(ud_handler);
        idt.device_not_available.set_handler_fn(nm_handler);
        idt.double_fault.set_handler_fn(df_handler);
        idt.invalid_tss.set_handler_fn(ts_handler);
        idt.segment_not_present.set_handler_fn(np_handler);
        idt.stack_segment_fault.set_handler_fn(ss_handler);
        idt.general_protection_fault.set_handler_fn(gp_handler);
        idt.page_fault.set_handler_fn(pf_handler);
        idt.x87_floating_point.set_handler_fn(mf_handler);
        idt.alignment_check.set_handler_fn(ac_handler);
        idt.machine_check.set_handler_fn(mc_handler);
        idt.simd_floating_point.set_handler_fn(xf_handler);
        idt.vmm_communication_exception.set_handler_fn(vc_handler);
        idt.security_exception.set_handler_fn(sx_handler);

        idt
    };
}

fn do_panic(stack_frame: InterruptStackFrame, name: &str, error_code: u64) -> ! {
    let rip: u64 = stack_frame.instruction_pointer.as_u64();

    panic!(
        "{} Exception: (errorcode={:#x}\n{:#?}\nRIP={rip}\n",
        name, error_code, stack_frame
    );
}

extern "x86-interrupt" fn de_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "DE", 0)
}

extern "x86-interrupt" fn db_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "DB", 0)
}

extern "x86-interrupt" fn nmi_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "NMI", 0)
}

extern "x86-interrupt" fn bp_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "BP", 0)
}

extern "x86-interrupt" fn of_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "OF", 0)
}

extern "x86-interrupt" fn br_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "BR", 0)
}

extern "x86-interrupt" fn ud_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "UD", 0)
}

extern "x86-interrupt" fn nm_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "NM", 0)
}

extern "x86-interrupt" fn df_handler(stack_frame: InterruptStackFrame, _error_code: u64) -> ! {
    do_panic(stack_frame, "DF", 0)
}

extern "x86-interrupt" fn ts_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    do_panic(stack_frame, "TS", error_code)
}

extern "x86-interrupt" fn np_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    do_panic(stack_frame, "NP", error_code)
}

extern "x86-interrupt" fn ss_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    do_panic(stack_frame, "SS", error_code)
}

extern "x86-interrupt" fn gp_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    do_panic(stack_frame, "GP", error_code)
}

extern "x86-interrupt" fn pf_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    do_panic(stack_frame, "PF", error_code.bits())
}

extern "x86-interrupt" fn mf_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "MF", 0)
}

extern "x86-interrupt" fn ac_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    do_panic(stack_frame, "AC", error_code)
}

extern "x86-interrupt" fn mc_handler(stack_frame: InterruptStackFrame) -> ! {
    do_panic(stack_frame, "MC", 0)
}

extern "x86-interrupt" fn xf_handler(stack_frame: InterruptStackFrame) {
    do_panic(stack_frame, "XF", 0)
}

extern "x86-interrupt" fn sx_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    do_panic(stack_frame, "SX", error_code)
}

/// Load IDT with function handlers for each exception
pub fn idt_init() {
    IDT.load();
}
