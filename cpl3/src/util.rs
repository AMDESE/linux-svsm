/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

/// 0x80000001
pub const SVSM_ERR_UNSUPPORTED_PROTOCOL: u64 = 0x80000001;

/// Retrieve 32 least significant bits
#[macro_export]
macro_rules! LOWER_32BITS {
    ($x: expr) => {
        (($x) as u32 & 0xffffffff)
    };
}

/// Retrieve 32 most significant bits
#[macro_export]
macro_rules! UPPER_32BITS {
    ($x: expr) => {
        (($x >> 32) as u32 & 0xffffffff)
    };
}
