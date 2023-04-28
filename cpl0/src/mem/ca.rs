/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::*;

#[repr(C, packed)]
pub struct Ca {
    call_pending: u8,
    mem_available: u8,
    reserved1: [u8; 6],
}

impl Ca {
    funcs!(call_pending, u8);
    funcs!(mem_available, u8);
}
