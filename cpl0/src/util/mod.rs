/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

/// Lock implementation for mutual exclusion
pub mod locking;
/// Serial output support
pub mod serial;
/// Auxiliary functions and macros
pub mod util;

pub use crate::util::serial::{serial_init, serial_out};
