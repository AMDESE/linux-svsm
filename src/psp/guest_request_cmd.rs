/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use x86_64::addr::VirtAddr;

/// 4000
const MSG_PAYLOAD_SIZE: usize = 4000;

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
    payload: [u8; MSG_PAYLOAD_SIZE],
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

    // SSL context is saved to simplify the clean-up logic in
    // the error path. We free it after use.
    ssl_ctx: *mut VirtAddr,

    // SNP Extended Guest Request. Its pages are also shared
    // with the hypervisor
    data_gva: VirtAddr,
    data_npages: usize,

    is_initialized: bool,
}
