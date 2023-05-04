/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::mem::{mem_allocate, pgtable_make_pages_shared};
use crate::{prints, ALIGN, ALIGNED, PAGE_COUNT, PAGE_SHIFT, PAGE_SIZE};

use x86_64::addr::VirtAddr;

/// 4000
const MSG_PAYLOAD_SIZE: usize = 4000;

/// 0x4000
pub const SNP_GUEST_REQ_MAX_DATA_SIZE: usize = 0x4000;

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

impl SnpGuestRequestCmd {
    pub const fn new() -> Self {
        SnpGuestRequestCmd {
            req_shared_page: VirtAddr::zero(),
            resp_shared_page: VirtAddr::zero(),

            data_gva: VirtAddr::zero(),
            data_npages: 0,

            staging_priv_page: VirtAddr::zero(),
            ssl_ctx: VirtAddr::zero().as_mut_ptr(),

            is_initialized: false,
        }
    }

    pub fn init(&mut self) -> Result<(), ()> {
        if !self.is_initialized {
            self.req_shared_page = mem_allocate(PAGE_SIZE as usize)?;
            self.resp_shared_page = mem_allocate(PAGE_SIZE as usize)?;
            self.staging_priv_page = mem_allocate(PAGE_SIZE as usize)?;

            self.data_gva = mem_allocate(SNP_GUEST_REQ_MAX_DATA_SIZE)?;
            if !ALIGNED!(self.data_gva.as_u64(), PAGE_SIZE) {
                prints!("ERR: data_gva is not page aligned\n");
                return Err(());
            }
            self.data_npages = PAGE_COUNT!(SNP_GUEST_REQ_MAX_DATA_SIZE as u64) as usize;

            // The SNP ABI spec says the request, response and data pages have
            // to be shared with the hypervisor
            pgtable_make_pages_shared(self.req_shared_page, PAGE_SIZE);
            pgtable_make_pages_shared(self.resp_shared_page, PAGE_SIZE);
            pgtable_make_pages_shared(self.data_gva, SNP_GUEST_REQ_MAX_DATA_SIZE as u64);

            self.is_initialized = true;
        }

        Ok(())
    }
}
