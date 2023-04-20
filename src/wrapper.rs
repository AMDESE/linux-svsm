/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@ibm.com>
 *   Vikram Narayanan <vikram186@gmail.com>
 */

#![allow(non_camel_case_types)]

#[cfg(not(test))]
mod wrappers {
    use crate::mem::{mem_allocate, mem_callocate, mem_free, mem_reallocate};
    use crate::prints;

    use core::{ptr, slice, str};
    use x86_64::VirtAddr;

    #[no_mangle]
    pub extern "C" fn malloc(size: cty::c_ulong) -> *mut cty::c_void {
        if let Ok(va) = mem_allocate(size as usize) {
            return va.as_mut_ptr();
        };
        ptr::null_mut()
    }

    #[no_mangle]
    pub extern "C" fn calloc(items: cty::c_ulong, size: cty::c_ulong) -> *mut cty::c_void {
        if let Some(num_bytes) = items.checked_mul(size as u64) {
            if let Ok(va) = mem_callocate(num_bytes as usize) {
                return va.as_mut_ptr();
            }
        }
        ptr::null_mut()
    }

    #[no_mangle]
    pub extern "C" fn realloc(p: *mut cty::c_void, size: cty::c_ulong) -> *mut cty::c_void {
        if let Ok(va) = mem_reallocate(VirtAddr::new(p as u64), size as usize) {
            return va.as_mut_ptr();
        }
        ptr::null_mut()
    }

    #[no_mangle]
    #[cfg(not(test))]
    pub extern "C" fn free(p: *mut cty::c_void) {
        if p.is_null() {
            return;
        }
        mem_free(VirtAddr::new(p as u64));
    }

    #[no_mangle]
    pub extern "C" fn serial_out(s: *const cty::c_char, size: cty::c_int) {
        let str_slice: &[u8] = unsafe { slice::from_raw_parts(s as *const u8, size as usize) };
        if let Ok(rust_str) = str::from_utf8(str_slice) {
            prints!("{}", rust_str);
        } else {
            prints!("ERR: BUG: serial_out arg1 is not a valid utf8 string\n");
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test_wrappers {

    extern "C" {
        fn malloc(size: cty::c_ulong) -> *mut cty::c_void;
        fn calloc(items: cty::c_ulong, size: cty::c_ulong) -> *mut cty::c_void;
        fn realloc(p: *mut cty::c_void, size: cty::c_ulong) -> *mut cty::c_void;
        fn free(ptr: *mut cty::c_void);
    }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    use crate::vc_terminate_svsm_general;
    vc_terminate_svsm_general();
}
