/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

/// 0
pub const SVSM_SUCCESS: u64 = 0;
//pub const SVSM_ERR_INCOMPLETE:           u64 = 0x80000000;
/// 0x80000001
pub const SVSM_ERR_UNSUPPORTED_PROTOCOL: u64 = 0x80000001;
/// 0x80000002
pub const SVSM_ERR_UNSUPPORTED_CALLID: u64 = 0x80000002;
/// 0x80000003
pub const SVSM_ERR_INVALID_ADDRESS: u64 = 0x80000003;
//pub const SVSM_ERR_INVALID_FORMAT:       u64 = 0x80000004;
/// 0x80000005
pub const SVSM_ERR_INVALID_PARAMETER: u64 = 0x80000005;
/// 0x80000006
pub const SVSM_ERR_INVALID_REQUEST: u64 = 0x80000006;

/// 0x80001000
pub const SVSM_ERR_PROTOCOL_BASE: u64 = 0x80001000;
/// 0x80001003
pub const SVSM_ERR_PROTOCOL_FAIL_INUSE: u64 = 0x80001003;
