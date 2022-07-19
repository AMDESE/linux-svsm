/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

/// Calling area (for guest requests)
pub mod ca;
/// Dynamic memory allocation handling
pub mod dynam;
/// Firmware configuration
pub mod fwcfg;
/// Guest Host Communication Block support
pub mod ghcb;
/// Page Table and its related operations
pub mod pgtable;

pub use crate::mem::dynam::mem_allocate_frame;
pub use crate::mem::dynam::mem_allocate_frames;
pub use crate::mem::dynam::mem_free_frame;
pub use crate::mem::dynam::mem_free_frames;
pub use crate::mem::dynam::mem_init;

pub use crate::mem::pgtable::pgtable_init;
pub use crate::mem::pgtable::pgtable_make_pages_np;
pub use crate::mem::pgtable::pgtable_make_pages_nx;
pub use crate::mem::pgtable::pgtable_make_pages_private;
pub use crate::mem::pgtable::pgtable_make_pages_shared;
pub use crate::mem::pgtable::pgtable_map_pages_private;
pub use crate::mem::pgtable::pgtable_pa_to_va;
pub use crate::mem::pgtable::pgtable_va_to_pa;

pub use crate::mem::ghcb::ghcb_init;

pub use crate::mem::fwcfg::fwcfg_init;
pub use crate::mem::fwcfg::fwcfg_map_bios;
