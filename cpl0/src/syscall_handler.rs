/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

use crate::*;

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

    let mut ret: isize = 0;

    match id {
        // Match syscalls ids.
        _ => ret = -EINVAL,
    }

    ret
}
