/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022, 2023 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

#![no_std]
use core::panic::PanicInfo;

pub mod syscall;
pub mod user_request;
pub mod util;

use syscall::*;
use user_request::*;
use util::*;

#[panic_handler]
fn panic(_panic_info: &PanicInfo) -> ! {
    loop {}
}

/// Start of the user side of things for SVSM (CPL3)
#[no_mangle]
pub extern "C" fn svsm_user_main() {
    user_request_loop();

    // We should never reach this point
    loop {}
}
