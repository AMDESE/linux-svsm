/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;
use x86_64::addr::VirtAddr;

use crate::{
    bindings::{
        EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new,
        EVP_CIPHER_CTX_set_key_length, EVP_DecryptFinal_ex, EVP_DecryptInit_ex, EVP_DecryptUpdate,
        EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_aes_256_gcm,
        EVP_CIPHER_CTX, EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_SET_IVLEN, EVP_CTRL_GCM_SET_TAG,
    },
    prints,
};

pub fn new_ssl_ctx(ctx: *mut VirtAddr) -> *mut VirtAddr {
    if !ctx.is_null() {
        unsafe { EVP_CIPHER_CTX_free(ctx as *mut EVP_CIPHER_CTX) };
    }
    VirtAddr::from_ptr(unsafe { EVP_CIPHER_CTX_new() }).as_mut_ptr()
}

pub fn init_aes_256_gcm_ctx(
    ssl_ctx: *mut VirtAddr,
    is_encryption: bool,
    key: VirtAddr,
    key_len: c_int,
    iv: VirtAddr,
    iv_len: c_int,
) -> Result<(), ()> {
    if ssl_ctx.is_null() {
        prints!("ERR: SSL context can't be null\n");
        return Err(());
    }

    let ctx: *mut EVP_CIPHER_CTX = ssl_ctx as *mut EVP_CIPHER_CTX;

    if is_encryption {
        // Set encrypt operation
        let ret: c_int = unsafe {
            EVP_EncryptInit_ex(
                ctx,
                EVP_aes_256_gcm(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        };
        if ret != 1 {
            prints!("ERR: EVP_EncryptInit_ex failed, rc={}\n", ret);
            return Err(());
        }
    } else {
        // Set decrypt operation
        let ret: c_int = unsafe {
            EVP_DecryptInit_ex(
                ctx,
                EVP_aes_256_gcm(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        };
        if ret != 1 {
            prints!("ERR: EVP_DecryptInit_ex failed, rc={}\n", ret);
            return Err(());
        }
    }

    // Set key size
    let mut ret: c_int = unsafe { EVP_CIPHER_CTX_set_key_length(ctx, key_len) };
    if ret != 1 {
        prints!(
            "ERR: Failed to set the key length for encryption ({})\n",
            ret
        );
        return Err(());
    }

    // Set IV size
    let gcm_set_ivlen_cint: c_int = match c_int::try_from(EVP_CTRL_GCM_SET_IVLEN) {
        Ok(c) => c,
        Err(_) => {
            prints!("ERR: Operation SET_IVLEN too big for c_int\n");
            return Err(());
        }
    };
    ret = unsafe { EVP_CIPHER_CTX_ctrl(ctx, gcm_set_ivlen_cint, iv_len, ptr::null_mut()) };
    if ret != 1 {
        prints!("ERR: EVP_CIPHER_CTX_ctrl failed ({})\n", ret);
        return Err(());
    }

    // Set key and IV
    if is_encryption {
        ret = unsafe {
            EVP_EncryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), iv.as_ptr())
        };
        if ret != 1 {
            prints!("ERR: EVP_EncryptInit_ex failed ({})\n", ret);
            return Err(());
        }
    } else {
        ret = unsafe {
            EVP_DecryptInit_ex(ctx, ptr::null(), ptr::null_mut(), key.as_ptr(), iv.as_ptr())
        };
        if ret != 1 {
            prints!("ERR: EVP_DecryptInit_ex failed, rc={}\n", ret);
            return Err(());
        }
    }

    Ok(())
}

pub fn aes_256_gcm_encrypt(
    ssl_ctx: *mut VirtAddr,
    plaintext: VirtAddr,
    plaintext_len: c_int,
    aad: VirtAddr,
    aad_len: c_int,
    ciphertext: VirtAddr,
    ciphertext_len: *mut c_int,
    authtag: VirtAddr,
    authtag_len: c_int,
) -> Result<(), ()> {
    if ssl_ctx.is_null() {
        prints!("ERR: SSL context can't be null for encryption\n");
        return Err(());
    }
    if plaintext_len > unsafe { *ciphertext_len } {
        prints!(
            "ERR: plaintext can't be bigger than the ciphertext buffer ({} > {})",
            plaintext_len,
            { unsafe { *ciphertext_len } }
        );
        return Err(());
    }

    let ctx: *mut EVP_CIPHER_CTX = ssl_ctx as *mut EVP_CIPHER_CTX;

    let mut len: c_int = 0;

    // Provide Additional Authenticated Data (AAD)
    let mut ret: i32 = unsafe {
        EVP_EncryptUpdate(
            ctx,
            ptr::null_mut(),
            ptr::addr_of_mut!(len),
            aad.as_ptr(),
            aad_len,
        )
    };
    if ret != 1 {
        prints!("ERR: Failed to provide AAD for encryption ({})\n", ret);
        return Err(());
    }

    // Provide plaintext
    ret = unsafe {
        EVP_EncryptUpdate(
            ctx,
            ciphertext.as_mut_ptr(),
            ptr::addr_of_mut!(len),
            plaintext.as_ptr(),
            plaintext_len,
        )
    };
    if ret != 1 {
        prints!(
            "ERR: Failed to provide the message to be encrypted ({})\n",
            ret
        );
        return Err(());
    }

    unsafe {
        *ciphertext_len = len;
    }

    // Finalize encryption
    let count: isize = match isize::try_from(len) {
        Ok(c) => c,
        Err(_) => {
            prints!("ERR: ciphertext len too big, {} bytes\n", len);
            return Err(());
        }
    };
    let ciphertext_offset_ptr: *mut c_uchar =
        unsafe { ciphertext.as_mut_ptr::<u8>().offset(count) };
    ret = unsafe { EVP_EncryptFinal_ex(ctx, ciphertext_offset_ptr, ptr::addr_of_mut!(len)) };
    if ret != 1 {
        prints!("ERR: Failed to finalise the encryption ({})\n", ret);
        return Err(());
    }

    // Get auth tag
    let get_tag_value: c_int = match c_int::try_from(EVP_CTRL_GCM_GET_TAG) {
        Ok(g) => g,
        Err(_) => {
            prints!("ERR: GCM_GET_TAG too big, value {}\n", EVP_CTRL_GCM_GET_TAG);
            return Err(());
        }
    };
    ret = unsafe {
        EVP_CIPHER_CTX_ctrl(
            ctx,
            get_tag_value,
            authtag_len,
            authtag.as_mut_ptr() as *mut c_void,
        )
    };
    if ret != 1 {
        prints!("ERR: Failed to get the tag in the encryption ({})\n", ret);
        return Err(());
    }

    Ok(())
}

pub fn aes_256_gcm_decrypt(
    ssl_ctx: *mut VirtAddr,
    plaintext: VirtAddr,
    plaintext_len: *mut c_int,
    aad: VirtAddr,
    aad_len: c_int,
    ciphertext: VirtAddr,
    ciphertext_len: c_int,
    authtag: VirtAddr,
    authtag_len: c_int,
) -> Result<(), ()> {
    if ssl_ctx.is_null() {
        prints!("ERR: SSL context can't be null for decryption\n");
        return Err(());
    }
    if ciphertext_len > unsafe { *plaintext_len } {
        prints!(
            "ERR: ciphertext can't be bigger than plaintext buffer ({} > {})",
            ciphertext_len,
            { unsafe { *plaintext_len } }
        );
        return Err(());
    }

    let ctx: *mut EVP_CIPHER_CTX = ssl_ctx as *mut EVP_CIPHER_CTX;

    let mut len: c_int = 0;

    // Provide Additional Authenticated Data (AAD)
    let mut ret: i32 = unsafe {
        EVP_DecryptUpdate(
            ctx,
            ptr::null_mut(),
            ptr::addr_of_mut!(len),
            aad.as_ptr(),
            aad_len,
        )
    };
    if ret != 1 {
        prints!("ERR: Failed to provide the AAD for decryption ({})\n", ret);
        return Err(());
    }

    // Provide ciphertext
    ret = unsafe {
        EVP_DecryptUpdate(
            ctx,
            plaintext.as_mut_ptr(),
            ptr::addr_of_mut!(len),
            ciphertext.as_ptr(),
            ciphertext_len,
        )
    };
    if ret != 1 {
        prints!(
            "ERR: Failed to provide the ciphertext for decryption ({})\n",
            ret
        );
        return Err(());
    }

    unsafe {
        *plaintext_len = len;
    }

    // Provide auth tag
    let set_tag_value: c_int = match c_int::try_from(EVP_CTRL_GCM_SET_TAG) {
        Ok(t) => t,
        Err(_) => {
            prints!("ERR: GCM_SET_TAG too big, value {}\n", EVP_CTRL_GCM_SET_TAG);
            return Err(());
        }
    };
    ret = unsafe {
        EVP_CIPHER_CTX_ctrl(
            ctx,
            set_tag_value,
            authtag_len,
            authtag.as_mut_ptr() as *mut c_void,
        )
    };
    if ret != 1 {
        prints!(
            "ERR: Failed to provide the auth tag for decryption ({})\n",
            ret
        );
        return Err(());
    }

    // Finalize decryption
    let count: isize = match isize::try_from(unsafe { *plaintext_len }) {
        Ok(c) => c,
        Err(_) => {
            prints!("ERR: Decrypted data too big, {} bytes\n", {
                unsafe { *plaintext_len }
            });
            return Err(());
        }
    };
    let plaintext_offset_ptr: *mut c_uchar = unsafe { plaintext.as_mut_ptr::<u8>().offset(count) };
    ret = unsafe { EVP_DecryptFinal_ex(ctx, plaintext_offset_ptr, ptr::addr_of_mut!(len)) };
    if ret != 1 {
        prints!("ERR: Failed to finalize decryption ({})\n", ret);
        return Err(());
    }

    Ok(())
}
