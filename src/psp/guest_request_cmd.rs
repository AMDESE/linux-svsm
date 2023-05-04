/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::bindings::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_key_length,
    EVP_DecryptInit_ex, EVP_EncryptInit_ex, EVP_aes_256_gcm, EVP_CIPHER_CTX,
    EVP_CTRL_GCM_SET_IVLEN,
};
use crate::mem::{mem_allocate, pgtable_make_pages_shared, SnpSecrets, VMPCK_SIZE};
use crate::{
    funcs, get_svsm_secrets_page, getter_func, prints, ALIGN, ALIGNED, BIT, PAGE_COUNT, PAGE_SHIFT,
    PAGE_SIZE,
};

use core::ptr;
use cty::c_int;
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

/// 0x4000
pub const SNP_GUEST_REQ_MAX_DATA_SIZE: usize = 0x4000;

const U64_SIZE: usize = core::mem::size_of::<u64>();

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

    pub const fn new() -> Self {
        SnpGuestRequestCmd {
            req_shared_page: VirtAddr::zero(),
            resp_shared_page: VirtAddr::zero(),

            data_gva: VirtAddr::zero(),
            data_npages: 0,

            staging_priv_page: VirtAddr::zero(),
            ossl_ctx: VirtAddr::zero(),

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
        }

        Ok(())
    }

    /// Allocate the openssl context and initialize it for encrypting or
    /// decrypting SNP_GUEST_REQUEST messages. The message sequence number
    /// is used as IV.
    unsafe fn init_ossl_ctx(
        &mut self,
        encryption: bool,
        seqno: &u64,
    ) -> Result<*mut EVP_CIPHER_CTX, ()> {
        // Clear the OpenSSL context before (re)using it
        if !self.ossl_ctx.is_null() {
            EVP_CIPHER_CTX_free(self.ossl_ctx.as_mut_ptr());
            self.ossl_ctx = VirtAddr::zero();
        }

        // Create new context
        let ctx: *mut EVP_CIPHER_CTX = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            prints!("ERR: Failed to get a new openssl CTX for encryption\n");
            return Err(());
        }
        self.ossl_ctx = VirtAddr::from_ptr(ctx);

        if encryption {
            // Set encrypt operation
            let ret: c_int = EVP_EncryptInit_ex(
                ctx,
                EVP_aes_256_gcm(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            );
            if ret != 1 {
                prints!("ERR: EVP_EncryptInit_ex failed, rc={}\n", ret);
                return Err(());
            }
        } else {
            // Set decrypt operation
            let ret: c_int = EVP_DecryptInit_ex(
                ctx,
                EVP_aes_256_gcm(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            );
            if ret != 1 {
                prints!("ERR: EVP_DecryptInit_ex failed, rc={}\n", ret);
                return Err(());
            }
        }

        // Provide key size
        let __vmpck_size: c_int = match c_int::try_from(VMPCK_SIZE) {
            Ok(c) => c,
            Err(_) => {
                prints!("ERR: VMPCK too big for c_int\n");
                return Err(());
            }
        };
        let mut ret: c_int = EVP_CIPHER_CTX_set_key_length(ctx, __vmpck_size);
        if ret != 1 {
            prints!(
                "ERR: Failed to set the key length for encryption ({})\n",
                ret
            );
            return Err(());
        }

        // Provide iv size
        let __gcm_set_ivlen: c_int = match c_int::try_from(EVP_CTRL_GCM_SET_IVLEN) {
            Ok(c) => c,
            Err(_) => {
                prints!("ERR: Operation SET_IVLEN too big for c_int\n");
                return Err(());
            }
        };
        ret = EVP_CIPHER_CTX_ctrl(ctx, __gcm_set_ivlen, IV_SIZE, ptr::null_mut());
        if ret != 1 {
            prints!("ERR: EVP_CIPHER_CTX_ctrl failed ({})\n", ret);
            return Err(());
        }

        // Provide key and iv
        let svsm_secrets_ptr: *mut SnpSecrets = get_svsm_secrets_page().as_mut_ptr();
        let key: [u8; VMPCK_SIZE] = (*svsm_secrets_ptr).vmpck0();

        let mut iv: [u8; IV_SIZE as usize] = [0u8; IV_SIZE as usize];
        iv[..U64_SIZE].copy_from_slice(&u64::to_ne_bytes(*seqno));

        if encryption {
            ret = EVP_EncryptInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                &key as *const _ as *const u8,
                &iv as *const _ as *const u8,
            );
            if ret != 1 {
                prints!("ERR: EVP_EncryptInit_ex failed ({})\n", ret);
                return Err(());
            }
        } else {
            ret = EVP_DecryptInit_ex(
                ctx,
                ptr::null(),
                ptr::null_mut(),
                &key as *const _ as *const u8,
                &iv as *const _ as *const u8,
            );
            if ret != 1 {
                prints!("ERR: EVP_DecryptInit_ex failed, rc={}\n", ret);
                return Err(());
            }
        }

        Ok(ctx)
    }
}
