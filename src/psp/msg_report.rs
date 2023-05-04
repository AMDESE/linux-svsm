/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::{getter_func, prints};

use alloc::boxed::Box;
use core::slice;

/// SnpReportRequest size
const REQUEST_SIZE: usize = core::mem::size_of::<SnpReportRequest>();

/// 64
pub const USER_DATA_SIZE: usize = 64;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SnpReportRequest {
    user_data: [u8; USER_DATA_SIZE],
    vmpl: u32,
    rsvd: [u8; 28usize],
}

impl SnpReportRequest {
    pub fn new() -> Self {
        Self {
            user_data: [0u8; USER_DATA_SIZE],
            vmpl: 0u32,
            rsvd: [0u8; 28],
        }
    }

    pub fn set_user_data(&mut self, data: &[u8; USER_DATA_SIZE]) {
        self.user_data.copy_from_slice(data);
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const _ as *const u8, REQUEST_SIZE) }
    }
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

impl SnpReportResponse {
    getter_func!(status, u32);
    getter_func!(report_size, u32);
    getter_func!(report, AttestationReport);

    pub fn is_valid(&self) -> bool {
        // Check status
        if self.status != 0 {
            prints!("ERR: Bad report status={}\n", { self.status });
            return false;
        }

        const REPORT_SIZE: usize = core::mem::size_of::<AttestationReport>();

        // Check report size
        if self.report_size != REPORT_SIZE as u32 {
            prints!(
                "ERR: Report size {:#x}, but should be {:#x} bytes)\n",
                { self.report_size },
                REPORT_SIZE
            );
            return false;
        }

        true
    }
}

impl TryFrom<Box<[u8]>> for SnpReportResponse {
    type Error = ();

    fn try_from(payload: Box<[u8]>) -> Result<Self, Self::Error> {
        let resp: SnpReportResponse = {
            let (head, body, _tail) = unsafe { payload.align_to::<SnpReportResponse>() };
            if !head.is_empty() {
                prints!("ERR: Report response not aligned\n");
                return Err(());
            }
            body[0]
        };

        Ok(resp)
    }
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
