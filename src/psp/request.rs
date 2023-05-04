/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

use crate::cpu::vc_terminate_svsm_general;
use crate::psp::guest_request_cmd::SnpGuestRequestCmd;
use crate::util::locking::{LockGuard, SpinLock};
use crate::prints;

/// SNP_GUEST_REQUEST Object
static GUEST_REQUEST_CMD: SpinLock<SnpGuestRequestCmd> = SpinLock::new(SnpGuestRequestCmd::new());

pub fn snp_guest_request_init() {
    if GUEST_REQUEST_CMD.lock().init().is_err() {
        prints!("ERR: Failed to initialize SNP_GUEST_REQUEST\n");
        vc_terminate_svsm_general();
    }
}
