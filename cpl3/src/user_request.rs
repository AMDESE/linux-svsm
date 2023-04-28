/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022, 2023 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

use crate::*;

#[inline]
fn get_next_request() -> (u32, u32) {
    let request: u64 = system_call!(SystemCalls::GetNextRequest as u32);
    (UPPER_32BITS!(request) as u32, LOWER_32BITS!(request) as u32)
}

#[inline]
fn set_request_finished(rax: u64) {
    system_call!(SystemCalls::SetRequestFinished as u32, rax);
}

pub fn user_request_loop() {
    loop {
        // Ask kernel to start listening for guest requests and
        // get back to us when there is a request that userspace
        // can handle

        let (protocol, _callid) = get_next_request();
        let rax: u64;

        match protocol {
            _ => rax = SVSM_ERR_UNSUPPORTED_PROTOCOL,
        }

        // Update vmsa.rax with the result and mark call as completed
        set_request_finished(rax);
    }
}
