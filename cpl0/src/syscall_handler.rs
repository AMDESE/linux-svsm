/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

use crate::*;

// Whenever a request that can be handled by userspace
// is received, return protocol + call ID
fn handle_get_next_request() -> isize {
    svsm_request_loop() as isize
}

fn handle_set_request_finished() -> isize {
    // In the future, when the userspace handles a request,
    // it should be marked as completed in the calling area
    0
}

#[no_mangle]
pub extern "C" fn syscall_handler(
    id: u32,
    _p1: u32,
    _p2: u32,
    _p3: u32,
    _p4: u32,
    _p5: u32,
) -> isize {
    #[allow(unused_assignments)]
    let ret: isize = match id {
        GET_NEXT_REQUEST => handle_get_next_request(),
        SET_REQUEST_FINISHED => handle_set_request_finished(),
        // Match syscalls ids.
        _ => -EINVAL,
    };

    ret
}
