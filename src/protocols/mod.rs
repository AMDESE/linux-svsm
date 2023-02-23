/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Dov Murik <dovmurik@linux.ibm.com>
 */

/// Implementation of the attestation protocol (1)
pub mod attestation;
/// Implementation of the core protocol (0)
pub mod core;
/// Error codes returned from the SVSM calls
pub mod error_codes;
/// Services manifest table
pub mod services_manifest;

pub use crate::protocols::attestation::*;
pub use crate::protocols::core::*;
pub use crate::protocols::services_manifest::*;

/// 0
pub const SVSM_CORE_PROTOCOL: u32 = ProtocolId::ProtocolId0 as u32;
