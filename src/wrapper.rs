/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@ibm.com>
 *   Vikram Narayanan <vikram186@gmail.com>
 */

use crate::mem::{mem_allocate, mem_callocate, mem_free, mem_reallocate};
use crate::{prints, vc_terminate_svsm_general};

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::{ptr, slice, str};
use x86_64::VirtAddr;

#[no_mangle]
pub extern "C" fn malloc(size: c_ulong) -> *mut c_void {
    if let Ok(va) = mem_allocate(size as usize) {
        return va.as_mut_ptr();
    };
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn calloc(items: c_ulong, size: c_ulong) -> *mut c_void {
    if let Some(num_bytes) = items.checked_mul(size as u64) {
        if let Ok(va) = mem_callocate(num_bytes as usize) {
            return va.as_mut_ptr();
        }
    }
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn realloc(p: *mut c_void, size: c_ulong) -> *mut c_void {
    if let Ok(va) = mem_reallocate(VirtAddr::new(p as u64), size as usize) {
        return va.as_mut_ptr();
    }
    ptr::null_mut()
}

#[no_mangle]
#[cfg(not(test))]
pub extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    mem_free(VirtAddr::new(p as u64));
}

#[no_mangle]
pub extern "C" fn serial_out(s: *const c_char, size: c_int) {
    let str_slice: &[u8] = unsafe { slice::from_raw_parts(s as *const u8, size as usize) };
    if let Ok(rust_str) = str::from_utf8(str_slice) {
        prints!("{}", rust_str);
    } else {
        prints!("ERR: BUG: serial_out arg1 is not a valid utf8 string\n");
    }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    vc_terminate_svsm_general();
}
