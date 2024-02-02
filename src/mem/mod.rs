/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

/// Dynamic memory allocation handling
mod alloc;
/// Calling area (for guest requests)
pub mod ca;
/// Firmware configuration
pub mod fwcfg;
/// Guest Host Communication Block support
pub mod ghcb;
/// MapGuard
pub mod map_guard;
/// Page Table and its related operations
pub mod pgtable;
/// SNP Secrets
pub mod snpsecrets;

pub use crate::mem::alloc::{
    mem_allocate, mem_allocate_frame, mem_allocate_frames, mem_callocate, mem_create_stack,
    mem_free, mem_free_frame, mem_free_frames, mem_init, mem_reallocate,
};

pub use crate::mem::pgtable::{
    pgtable_init, pgtable_make_pages_np, pgtable_make_pages_nx, pgtable_make_pages_private,
    pgtable_make_pages_shared, pgtable_pa_to_va, pgtable_print_pte_pa, pgtable_print_pte_va,
    pgtable_va_to_pa,
};

pub use crate::mem::map_guard::MapGuard;

pub use crate::mem::snpsecrets::{SnpSecrets, VMPCK_SIZE};

pub use crate::mem::ghcb::ghcb_init;

pub use crate::mem::fwcfg::{fwcfg_get_bios_area, fwcfg_init};
