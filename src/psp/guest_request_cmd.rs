/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::cpu::vc::vc_snp_guest_request;
use crate::crypto::ssl::{
    aes_256_gcm_decrypt, aes_256_gcm_encrypt, init_aes_256_gcm_ctx, new_ssl_ctx,
};
use crate::mem::snpsecrets::{disable_vmpck0, is_vmpck0_clear};
use crate::mem::{mem_allocate, pgtable_make_pages_shared, SnpSecrets, VMPCK_SIZE};
use crate::util::util::memset;
use crate::{
    funcs, get_svsm_secrets_page, getter_func, prints, ALIGN, ALIGNED, BIT, PAGE_COUNT, PAGE_SHIFT,
    PAGE_SIZE,
};

use alloc::boxed::Box;
use core::cmp::min;
use core::ffi::c_int;
use core::ptr;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::{AtomicU64, Ordering};
use memoffset::offset_of;
use x86_64::addr::VirtAddr;

///
/// AEAD Algorithm
///

/// 1
const SNP_AEAD_AES_256_GCM: u8 = 1;

///
/// Hypervisor error codes
///

/// BIT!(32)
pub const SNP_GUEST_REQ_INVALID_LEN: u64 = BIT!(32);
/// BIT!(33)
pub const SNP_GUEST_REQ_ERR_BUSY: u64 = BIT!(33);

///
/// SnpGuestRequestMsg
///

/// 0
pub const SNP_MSG_TYPE_INVALID: u8 = 0;
/// 5
pub const SNP_MSG_REPORT_REQ: u8 = 5;
/// 6
pub const SNP_MSG_REPORT_RSP: u8 = 6;

/// 1
const HDR_VERSION: u8 = 1;
/// 1
const MSG_VERSION: u8 = 1;
/// In the SEV-SNP ABI spec, the authentication tag should be at most
/// 128 bits.
/// 16
const AUTHTAG_SIZE: c_int = 16;
/// In the SEV-SNP ABI spec, the IV should be at most 96 bits; but
/// the bits not used must be zeroed.
/// 12
const IV_SIZE: c_int = 12;
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

impl SnpGuestRequestMsgHdr {
    pub fn is_valid(&self, msg_type: u8, msg_seqno: u64) -> bool {
        const MSG_HDR_SIZE: usize = core::mem::size_of::<SnpGuestRequestMsgHdr>();

        let header_size: u16 = match u16::try_from(MSG_HDR_SIZE) {
            Ok(v) => v,
            Err(_) => {
                prints!("ERR: header size too big, {} bytes\n", MSG_HDR_SIZE);
                return false;
            }
        };

        // header version
        if self.hdr_version != HDR_VERSION {
            prints!(
                "ERR: response header version {} should be {}\n",
                { self.hdr_version },
                HDR_VERSION
            );
            return false;
        }

        // header size
        if self.hdr_sz != header_size {
            prints!(
                "ERR: response header size {} should be {}\n",
                { self.hdr_sz },
                header_size
            );
            return false;
        }

        // algo
        if self.algo != SNP_AEAD_AES_256_GCM {
            prints!(
                "ERR: response algo {}, but should be {}\n",
                { self.algo },
                SNP_AEAD_AES_256_GCM
            );
            return false;
        }

        // message type
        if self.msg_type != msg_type {
            prints!(
                "ERR: response message type {}, but should be {}\n",
                { self.msg_type },
                { msg_type }
            );
            return false;
        }

        // message vmpck
        if self.msg_vmpck != 0 {
            prints!("ERR: response message vmpck {}, but should be 0\n", {
                self.msg_vmpck
            });
            return false;
        }

        // message sequence number
        if self.msg_seqno != msg_seqno {
            prints!(
                "ERR: response message seqno {}, but should be {}\n",
                { self.msg_seqno },
                msg_seqno
            );
            return false;
        }

        true
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SnpGuestRequestMsg {
    hdr: SnpGuestRequestMsgHdr,
    payload: [u8; MSG_PAYLOAD_SIZE],
}

static SEQ_NUM: AtomicU64 = AtomicU64::new(0);

fn seqno_last_used() -> u64 {
    SEQ_NUM.load(Ordering::Relaxed)
}

fn seqno_add_two() {
    SEQ_NUM.fetch_add(2, Ordering::Relaxed);
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
    getter_func!(req_shared_page, VirtAddr);
    getter_func!(resp_shared_page, VirtAddr);
    getter_func!(data_gva, VirtAddr);
    funcs!(data_npages, usize);

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

    fn set_ssl_ctx(&mut self, is_encryption: bool, msg_seqno: u64) -> Result<(), ()> {
        self.ssl_ctx = new_ssl_ctx(self.ssl_ctx);
        if self.ssl_ctx.is_null() {
            prints!("ERR: Failed to create a new SSL context for encryption\n");
            return Err(());
        }

        let svsm_secrets_ptr: *mut SnpSecrets = get_svsm_secrets_page().as_mut_ptr();
        let vmpck0_va = VirtAddr::from_ptr(unsafe { *svsm_secrets_ptr }.vmpck0().as_ptr());
        let vmpck0_len: c_int = match c_int::try_from(VMPCK_SIZE) {
            Ok(c) => c,
            Err(_) => {
                prints!("ERR: VMPCK too big for c_int\n");
                return Err(());
            }
        };
        let mut msg_seqno_array: [u8; IV_SIZE as usize] = [0u8; IV_SIZE as usize];
        const U64_SIZE: usize = core::mem::size_of::<u64>();
        msg_seqno_array[..U64_SIZE].copy_from_slice(&u64::to_ne_bytes(msg_seqno));
        let msg_seqno_array_va = VirtAddr::from_ptr(msg_seqno_array.as_ptr());

        init_aes_256_gcm_ctx(
            self.ssl_ctx,
            is_encryption,
            vmpck0_va,
            vmpck0_len,
            msg_seqno_array_va,
            IV_SIZE,
        )?;

        Ok(())
    }

    /// Encrypt the plaintext using AES-256-GCM as described in the SNP ABI spec, where:
    /// key = vmpck[0]
    /// IV = sequence number
    /// AAD = last 16 bytes of the SnpGuestRequestMsgHdr
    fn encrypt_request(
        &mut self,
        msg_type: u8,
        plaintext: VirtAddr,
        plaintext_len: u16,
    ) -> Result<(), ()> {
        // Check VMPCK0 is valid
        if is_vmpck0_clear() {
            prints!("ERR: vmpck0 invalid\n");
            return Err(());
        }

        // Clear the staging private page before using it for encrypting the request
        memset(
            self.staging_priv_page.as_mut_ptr::<u8>(),
            0u8,
            PAGE_SIZE as usize,
        );

        const MSG_HDR_SIZE: usize = core::mem::size_of::<SnpGuestRequestMsgHdr>();

        // Construct the request message header
        let req: *mut SnpGuestRequestMsg = self.staging_priv_page.as_mut_ptr();
        let msg_seqno: u64 = match seqno_last_used().checked_add(1) {
            Some(v) => v,
            None => {
                prints!("ERR: Request sequence number overflow\n");
                return Err(());
            }
        };
        unsafe {
            (*req).hdr.hdr_sz = match u16::try_from(MSG_HDR_SIZE) {
                Ok(v) => v,
                Err(_) => {
                    prints!("ERR: header size={} too big for u16\n", MSG_HDR_SIZE);
                    return Err(());
                }
            };
            (*req).hdr.algo = SNP_AEAD_AES_256_GCM;
            (*req).hdr.hdr_version = HDR_VERSION;
            (*req).hdr.msg_sz = plaintext_len;
            (*req).hdr.msg_type = msg_type;
            (*req).hdr.msg_version = MSG_VERSION;
            (*req).hdr.msg_vmpck = 0;
            (*req).hdr.msg_seqno = msg_seqno;
        }

        self.set_ssl_ctx(true, msg_seqno)?;

        let algo_offset: c_int = match c_int::try_from(offset_of!(SnpGuestRequestMsgHdr, algo)) {
            Ok(o) => o,
            Err(_) => {
                prints!("ERR: algo offset is too big for c_int\n");
                return Err(());
            }
        };
        let msg_hdr_size_cint: c_int = match c_int::try_from(MSG_HDR_SIZE) {
            Ok(c) => c,
            Err(_) => {
                prints!("ERR: msg header size too big for c_int\n");
                return Err(());
            }
        };
        let aad_len: c_int = msg_hdr_size_cint - algo_offset;
        let aad: VirtAddr = unsafe { VirtAddr::from_ptr(&(*req).hdr.algo) };
        let ciphertext: VirtAddr = unsafe { VirtAddr::from_ptr((*req).payload.as_ptr()) };
        let mut ciphertext_len: c_int = match c_int::try_from(MSG_PAYLOAD_SIZE) {
            Ok(c) => c,
            Err(_) => {
                prints!("ERR: msg payload size too big for c_int\n");
                return Err(());
            }
        };
        let authtag: VirtAddr = unsafe { VirtAddr::from_ptr((*req).hdr.authtag.as_mut_ptr()) };

        aes_256_gcm_encrypt(
            self.ssl_ctx,
            plaintext,
            c_int::from(plaintext_len),
            aad,
            aad_len,
            ciphertext,
            ptr::addr_of_mut!(ciphertext_len),
            authtag,
            AUTHTAG_SIZE,
        )?;

        prints!(
            "INFO: SNP_GUEST_REQUEST msg_type {} encrypted ({} bytes)\n",
            msg_type,
            ciphertext_len
        );
        //prints!("DEBUG: req_msg {:p} {:x?}\n", { &(*req) }, { *req });

        memset(
            self.req_shared_page.as_mut_ptr::<u8>(),
            0u8,
            PAGE_SIZE as usize,
        );
        unsafe {
            copy_nonoverlapping(
                self.staging_priv_page.as_ptr::<u8>(),
                self.req_shared_page.as_mut_ptr::<u8>(),
                PAGE_SIZE as usize,
            );
        }

        Ok(())
    }

    /// Send the encrypted SNP_GUEST_REQUEST message to the PSP.
    fn send(&mut self, extended: bool, mut psp_rc: &mut u64) -> Result<(), ()> {
        memset(
            self.resp_shared_page.as_mut_ptr::<u8>(),
            0u8,
            PAGE_SIZE as usize,
        );

        // Send the encrypted request
        vc_snp_guest_request(extended, &mut psp_rc, self)?;

        match *psp_rc {
            // Success
            0 => {}
            // certs_buf too small, the hypervisor did not forward the request.
            // Save the number of pages required for the certificate chain
            // and send the request again as a non-extended request
            // to prevent IV reuse.
            SNP_GUEST_REQ_INVALID_LEN => {
                if extended {
                    let npages_required: usize = self.data_npages();
                    vc_snp_guest_request(false, &mut psp_rc, self)?;
                    self.set_data_npages(npages_required);
                    if *psp_rc != 0 {
                        return Err(());
                    }
                    *psp_rc = SNP_GUEST_REQ_INVALID_LEN;
                }
            }
            // Hypervisor busy, the request was not forwarded to the PSP. Send
            // the request again to prevent IV reuse.
            SNP_GUEST_REQ_ERR_BUSY => {
                vc_snp_guest_request(extended, &mut psp_rc, self)?;
                if *psp_rc != 0 {
                    return Err(());
                }
            }
            // Failed. See the status codes in the SEV SNP ABI spec or in the
            // linux kernel include/uapi/linux/psp-sev.h
            _ => {
                prints!("ERR: SNP_GUEST_REQUEST failed, rc={}\n", { *psp_rc });
                return Err(());
            }
        }

        // The PSP firmware increases the sequence number only when
        // it receives a request successfully. Hence, we sync our
        // sequence number (add two) only when we receive a response
        // successfully.
        seqno_add_two();

        Ok(())
    }

    fn decrypt_response(&mut self, msg_type: u8) -> Result<Box<[u8]>, ()> {
        // Check VMPCK0 is valid
        if is_vmpck0_clear() {
            prints!("ERR: vmpck0 invalid\n");
            return Err(());
        }

        // Decrypt the response in a private page to avoid any interference from
        // the hypervisor
        memset(
            self.staging_priv_page.as_mut_ptr::<u8>(),
            0u8,
            PAGE_SIZE as usize,
        );
        unsafe {
            copy_nonoverlapping(
                self.resp_shared_page.as_ptr::<u8>(),
                self.staging_priv_page.as_mut_ptr::<u8>(),
                PAGE_SIZE as usize,
            );
        }

        let resp: *const SnpGuestRequestMsg = self.staging_priv_page.as_ptr();

        unsafe {
            // Check if the response header is valid
            if !(*resp).hdr.is_valid(msg_type, seqno_last_used()) {
                return Err(());
            }
        }

        self.set_ssl_ctx(false, seqno_last_used())?;

        let mut plaintext: [u8; MSG_PAYLOAD_SIZE] = [0u8; MSG_PAYLOAD_SIZE];
        let mut plaintext_len: c_int = match c_int::try_from(MSG_PAYLOAD_SIZE) {
            Ok(c) => c,
            Err(_) => {
                prints!("ERR: msg payload size too big for c_int\n");
                return Err(());
            }
        };
        let algo_offset: c_int = match c_int::try_from(offset_of!(SnpGuestRequestMsgHdr, algo)) {
            Ok(o) => o,
            Err(_) => {
                prints!("ERR: algo offset is too big for c_int\n");
                return Err(());
            }
        };
        const MSG_HDR_SIZE: usize = core::mem::size_of::<SnpGuestRequestMsgHdr>();
        let __msg_hdr_size: c_int = match c_int::try_from(MSG_HDR_SIZE) {
            Ok(c) => c,
            Err(_) => {
                prints!("ERR: msg header size is too big for c_int\n");
                return Err(());
            }
        };
        let aad_len: c_int = __msg_hdr_size - algo_offset;
        let aad: VirtAddr = unsafe { VirtAddr::from_ptr(&(*resp).hdr.algo) };
        let ciphertext: VirtAddr = unsafe { VirtAddr::from_ptr((*resp).payload.as_ptr()) };
        let ciphertext_len: c_int = unsafe { c_int::from((*resp).hdr.msg_sz) };
        let authtag: VirtAddr = unsafe { VirtAddr::from_ptr((*resp).hdr.authtag.as_ptr()) };

        aes_256_gcm_decrypt(
            self.ssl_ctx,
            VirtAddr::from_ptr(plaintext.as_mut_ptr()),
            ptr::addr_of_mut!(plaintext_len),
            aad,
            aad_len,
            ciphertext,
            ciphertext_len,
            authtag,
            AUTHTAG_SIZE,
        )?;

        prints!(
            "INFO: SNP_GUEST_REQUEST msg_type {} decrypted ({} bytes)\n",
            msg_type,
            plaintext_len
        );
        //prints!("DEBUG: resp_msg {:x?}\n", { &buf[..500] });

        Ok(plaintext.into())
    }

    /// Send a SNP_GUEST_REQUEST message to the platform security processor (PSP) following
    /// the GHCB protocol. Messages are a encrypted/decrypted using AES_GCM.
    pub fn send_request(
        &mut self,
        msg_type: u8,
        extended: bool,
        payload: VirtAddr,
        payload_size: u16,
        psp_rc: &mut u64,
    ) -> Result<Box<[u8]>, ()> {
        if !self.is_initialized {
            return Err(());
        }
        self.encrypt_request(msg_type, payload, payload_size)?;

        if self.send(extended, psp_rc).is_err() {
            disable_vmpck0();
            return Err(());
        }

        let result: Result<Box<[u8]>, ()> = self.decrypt_response(msg_type + 1);
        if result.is_err() {
            disable_vmpck0();
        }

        result
    }

    /// Copy to buf the certificates obtained in the last extended report request
    pub fn copy_from_data(&self, buf: VirtAddr, buf_size: usize) {
        unsafe {
            ptr::copy_nonoverlapping(
                self.data_gva.as_mut_ptr::<u8>(),
                buf.as_mut_ptr::<u8>(),
                min(buf_size, SNP_GUEST_REQ_MAX_DATA_SIZE as usize),
            );
        }
    }

    /// Check if the first sz bytes of the data buffer are empty
    pub fn is_data_bytes_empty(&self, sz: usize) -> bool {
        let m: usize = min(sz, SNP_GUEST_REQ_MAX_DATA_SIZE);
        let buf: *const [u8; SNP_GUEST_REQ_MAX_DATA_SIZE] =
            self.data_gva.as_ptr() as *const [u8; SNP_GUEST_REQ_MAX_DATA_SIZE];
        unsafe { (*buf)[..m].is_empty() }
    }

    /// Clear sz bytes from the data buffer
    pub fn clear_data_bytes(&self, sz: usize) {
        memset(
            self.data_gva.as_mut_ptr::<u8>(),
            0u8,
            min(sz, SNP_GUEST_REQ_MAX_DATA_SIZE),
        );
    }
}
