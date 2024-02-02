/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use core::ffi::c_int;
use x86_64::VirtAddr;

/// Create a new SSL context
pub fn new_ssl_ctx(_ctx: *mut VirtAddr) -> *mut VirtAddr {
    VirtAddr::zero().as_mut_ptr()
}

/// Initialize SSL context for AES-GCM-256 for either
/// encryption or decryption
pub fn init_aes_256_gcm_ctx(
    _ssl_ctx: *mut VirtAddr,
    _is_for_encryption: bool,
    _key: VirtAddr,
    _key_len: c_int,
    _iv: VirtAddr,
    _iv_len: c_int,
) -> Result<(), ()> {
    Ok(())
}

/// Encrypt plaintext using AES-256-GCM
pub fn aes_256_gcm_encrypt(
    _ssl_ctx: *mut VirtAddr,
    _plaintext: VirtAddr,
    _plaintext_len: c_int,
    _aad: VirtAddr,
    _aad_len: c_int,
    _ciphertext: VirtAddr,
    _ciphertext_len: *mut c_int,
    _authtag: VirtAddr,
    _authtag_len: c_int,
) -> Result<(), ()> {
    Ok(())
}

/// Decrypt ciphertext using AES-GCM-256
pub fn aes_256_gcm_decrypt(
    _ssl_ctx: *mut VirtAddr,
    _plaintext: VirtAddr,
    _plaintext_len: *mut c_int,
    _aad: VirtAddr,
    _aad_len: c_int,
    _ciphertext: VirtAddr,
    _ciphertext_len: c_int,
    _authtag: VirtAddr,
    _authtag_len: c_int,
) -> Result<(), ()> {
    Ok(())
}
