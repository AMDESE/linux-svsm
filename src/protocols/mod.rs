/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Dov Murik <dovmurik@linux.ibm.com>
 */

/// Implementation of the core protocol (0)
pub mod core;
/// Error codes returned from the SVSM calls
pub mod error_codes;

pub use crate::protocols::core::*;

/// 0
pub const SVSM_CORE_PROTOCOL: u32 = 0;
