/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

#![no_std]
use core::panic::PanicInfo;

pub mod syscall;

#[panic_handler]
fn panic(_panic_info: &PanicInfo) -> ! {
    loop {}
}

/// Start of the user side of things for SVSM (CPL3)
#[no_mangle]
pub extern "C" fn svsm_user_main() {
    loop {}
}
