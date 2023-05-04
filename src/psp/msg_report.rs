/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

/// 64
pub const USER_DATA_SIZE: usize = 64;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportRequest {
    user_data: [u8; USER_DATA_SIZE],
    vmpl: u32,
    rsvd: [u8; 28usize],
}

#[repr(C)]
#[repr(align(2048))]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportResponse {
    status: u32,
    report_size: u32,
    _reserved: [u8; 24],
    report: AttestationReport,
}

// Converted tcb_version from enum to
// struct to make alignment simple.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct TcbVersion {
    raw: u64,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Signature {
    r: [u8; 72usize],
    s: [u8; 72usize],
    reserved: [u8; 368usize],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct AttestationReport {
    version: u32,
    guest_svn: u32,
    policy: u64,
    family_id: [u8; 16usize],
    image_id: [u8; 16usize],
    vmpl: u32,
    signature_algo: u32,
    platform_version: TcbVersion,
    platform_info: u64,
    flags: u32,
    reserved0: u32,
    report_data: [u8; 64usize],
    measurement: [u8; 48usize],
    host_data: [u8; 32usize],
    id_key_digest: [u8; 48usize],
    author_key_digest: [u8; 48usize],
    report_id: [u8; 32usize],
    report_id_ma: [u8; 32usize],
    reported_tcb: TcbVersion,
    reserved1: [u8; 24usize],
    chip_id: [u8; 64usize],
    reserved2: [u8; 192usize],
    signature: Signature,
}
