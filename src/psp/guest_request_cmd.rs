/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::{funcs, getter_func, BIT};

use x86_64::addr::VirtAddr;

///
/// AEAD Algorithm
///

#[allow(dead_code)]
/// 0
const SNP_AEAD_INVALID: u8 = 0;
/// 1
const SNP_AEAD_AES_256_GCM: u8 = 1;

///
/// SNP_GUEST_REQUEST hypervisor error codes
///

/// BIT!(32)
pub const SNP_GUEST_REQ_INVALID_LEN: u64 = BIT!(32);
/// BIT!(33)
pub const SNP_GUEST_REQ_ERR_BUSY: u64 = BIT!(33);

///
/// SNP_GUEST_MESSAGE type
///

/// 0
pub const SNP_MSG_TYPE_INVALID: u8 = 0;

/// 1
const HDR_VERSION: u8 = 1;
/// 1
const MSG_VERSION: u8 = 1;
/// 16
const AUTHTAG_SIZE: c_int = 16;
/// 12
const IV_SIZE: c_int = 12;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SnpGuestRequestMsgHdr {
    authtag: [u8; 32usize],
    msg_seqno: u64,
    rsvd1: [u8; 8usize],
    algo: u8,
    hdr_version: u8,
    hdr_sz: u16,
    msg_type: u8,
    msg_version: u8,
    msg_sz: u16,
    rsvd2: u32,
    msg_vmpck: u8,
    rsvd3: [u8; 35usize],
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SnpGuestRequestMsg {
    hdr: SnpGuestRequestMsgHdr,
    payload: [u8; 4000usize],
}

pub struct SnpGuestRequestCmd {
    // SNP_GUEST_REQUEST requires two unique pages: one for
    // the request and another for the response message. Both
    // of them are assigned to the hypervisor (shared).
    req_shared_page: VirtAddr,
    resp_shared_page: VirtAddr,

    // Message encryption and decryption are performed in a
    // private page to avoid data leaking.
    staging_priv_page: VirtAddr,

    // Openssl context is saved to simplify the clean-up logic in
    // the error path. We free it after use.
    ossl_ctx: VirtAddr,

    // SNP Extended Guest Request.
    data_gva: VirtAddr,
    data_npages: usize,

    is_initialized: bool,
}

impl SnpGuestRequestCmd {
    getter_func!(req_shared_page, VirtAddr);
    getter_func!(resp_shared_page, VirtAddr);
    getter_func!(data_gva, VirtAddr);
    funcs!(data_npages, usize);
}
