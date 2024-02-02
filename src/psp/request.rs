/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::protocols::error_codes::*;
use crate::psp::guest_request_cmd::{
    SnpGuestRequestCmd, SNP_GUEST_REQ_INVALID_LEN, SNP_GUEST_REQ_MAX_DATA_SIZE, SNP_MSG_REPORT_REQ,
};
use crate::psp::msg_report::{SnpReportRequest, SnpReportResponse, USER_DATA_SIZE};
use crate::util::locking::{LockGuard, SpinLock};
use crate::{prints, ALIGN, ALIGNED, PAGE_COUNT, PAGE_SHIFT, PAGE_SIZE};

use alloc::boxed::Box;
use x86_64::VirtAddr;

/// SNP_GUEST_REQUEST Object
static GUEST_REQUEST_CMD: SpinLock<SnpGuestRequestCmd> = SpinLock::new(SnpGuestRequestCmd::new());

pub struct CertsBuf {
    addr: VirtAddr,
    size: usize,
}

impl CertsBuf {
    pub fn new(va: VirtAddr, sz: usize) -> Self {
        CertsBuf { addr: va, size: sz }
    }
}

pub fn snp_guest_request_init() {
    if GUEST_REQUEST_CMD.lock().init().is_err() {
        // Since the SNP_GUEST_REQUET resources failed to initialize,
        // all subsequent SNP Guest Request will fail
        prints!("ERR: Failed to initialize SNP_GUEST_REQUEST\n");
    }
}

/// Request a vmpl0 attestation report to the platform security processor (PSP).
///
/// @user_data: data that will be included in the attestation report and signed
/// @psp_rc   : PSP return code.
/// @certs_buf: Optional. Buffer to store the certificate chain needed to verify
///             the attestation report. Make sure to load the certificates from
///             from the host using the sev-guest tools.
///
/// It returns the SnpReportResponse if success, otherwise an error code.
///
/// Further information can be found in the Secure Nested Paging Firmware ABI
/// Specification, Chapter 7, subsection Attestation
pub fn get_report(
    user_data: &[u8; USER_DATA_SIZE],
    psp_rc: &mut u64,
    mut certs_buf: Option<&mut CertsBuf>,
) -> Result<SnpReportResponse, u64> {
    const REPORT_REQUEST_SIZE: usize = core::mem::size_of::<SnpReportRequest>();
    // The size of the SnpReportRequest structure needs to fit in the
    // SnpGuestRequest.hdr.msg_size field, which is a u16.
    let req_size: u16 = match u16::try_from(REPORT_REQUEST_SIZE) {
        Ok(sz) => sz,
        Err(_) => {
            prints!(
                "ERR: BUG: Report request size={} is too big for u16\n",
                REPORT_REQUEST_SIZE
            );
            return Err(SVSM_ERR_PROTOCOL_BASE);
        }
    };

    let mut cmd: LockGuard<SnpGuestRequestCmd> = GUEST_REQUEST_CMD.lock();
    let extended: bool = certs_buf.is_some();

    if extended {
        // Get a mutable raw pointer, otherwise we will not be able to use certs_buf later again
        let buf: &mut CertsBuf = certs_buf.as_mut().unwrap();

        if buf.addr.is_null() || buf.size == 0 {
            return Err(SVSM_ERR_INVALID_PARAMETER);
        }
        if buf.size > SNP_GUEST_REQ_MAX_DATA_SIZE as usize {
            prints!("ERR: certs_buf_size={:#x} too big\n", { buf.size });
            return Err(SVSM_ERR_INVALID_PARAMETER);
        }
        if !ALIGNED!({ buf.addr.as_u64() }, PAGE_SIZE) {
            prints!("ERR: certs_buf_size={:#x} not page aligned\n", { buf.addr });
            return Err(SVSM_ERR_INVALID_PARAMETER);
        }
        let npages: usize = PAGE_COUNT!({ buf.size as u64 }) as usize;
        cmd.set_data_npages(npages);
        cmd.clear_data_bytes(buf.size);
    }

    // Instantiate a vmpl0 report request
    let mut req: SnpReportRequest = SnpReportRequest::new();
    req.set_user_data(user_data);

    let result: Result<Box<[u8]>, ()> = cmd.send_request(
        SNP_MSG_REPORT_REQ,
        extended,
        VirtAddr::from_ptr(&req),
        req_size,
        psp_rc,
    );

    if result.is_err() {
        if extended && *psp_rc == SNP_GUEST_REQ_INVALID_LEN {
            let buf: &mut CertsBuf = certs_buf.as_mut().unwrap();
            prints!("ERR: Certificate buffer is too small, {} bytes\n", {
                buf.size
            });
            buf.size = (cmd.data_npages() << PAGE_SHIFT) as usize;
            return Err(SVSM_ERR_INVALID_PARAMETER);
        }

        return Err(SVSM_ERR_PROTOCOL_BASE);
    }

    let message: Box<[u8]> = result.unwrap();
    let resp: SnpReportResponse = match SnpReportResponse::try_from(message) {
        Ok(r) => r,
        Err(()) => return Err(SVSM_ERR_PROTOCOL_BASE),
    };
    if !resp.is_valid() {
        return Err(SVSM_ERR_PROTOCOL_BASE);
    }

    // The sev-guest tools, in the host, are used to load the certificates needed to
    // verify the attestation report. If they were not loaded (yet), print a warning.
    if extended {
        let buf: &mut CertsBuf = certs_buf.as_mut().unwrap();
        if cmd.is_data_bytes_empty(buf.size) {
            prints!("WARNING: Attestation report certificates not found.\n");
        } else {
            cmd.copy_from_data(buf.addr, buf.size);
        }
    }

    Ok(resp)
}
