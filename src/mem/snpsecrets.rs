/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::{funcs, get_svsm_secrets_page, prints};

/// 32
pub const VMPCK_SIZE: usize = 32;

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct SnpSecrets {
    version: u32,
    flags: u32,
    fms: u32,
    reserved1: [u8; 4],

    gosvw: [u8; 16],

    vmpck0: [u8; VMPCK_SIZE],
    vmpck1: [u8; VMPCK_SIZE],
    vmpck2: [u8; VMPCK_SIZE],
    vmpck3: [u8; VMPCK_SIZE],

    os_reserved: [u8; 96],

    reserved2: [u8; 64],

    // SVSM fields start at offset 0x140 into the secrets page
    svsm_base: u64,
    svsm_size: u64,
    svsm_caa: u64,
    svsm_max_version: u32,
    svsm_guest_vmpl: u8,
    reserved3: [u8; 3],
}

#[allow(dead_code)]
impl SnpSecrets {
    pub fn clear_vmpck0(&mut self) {
        self.vmpck0.iter_mut().for_each(|e| *e = 0);
    }

    pub fn is_vmpck0_clear(self) -> bool {
        self.vmpck0.into_iter().all(|e: u8| e == 0)
    }

    funcs!(svsm_base, u64);
    funcs!(svsm_size, u64);
    funcs!(svsm_caa, u64);
    funcs!(svsm_max_version, u32);
    funcs!(svsm_guest_vmpl, u8);
    funcs!(vmpck0, [u8; VMPCK_SIZE]);
}

pub fn disable_vmpck0() {
    let svsm_secrets_ptr: *mut SnpSecrets = get_svsm_secrets_page().as_mut_ptr();
    prints!("WARNING: VMPCK0 disabled!\n");
    unsafe { (*svsm_secrets_ptr).clear_vmpck0() }
}

pub fn is_vmpck0_clear() -> bool {
    let svsm_secrets_ptr: *mut SnpSecrets = get_svsm_secrets_page().as_mut_ptr();

    unsafe { (*svsm_secrets_ptr).is_vmpck0_clear() }
}
