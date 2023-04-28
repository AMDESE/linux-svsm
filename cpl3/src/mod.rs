/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Author: Carlos Bilbao <carlos.bilbao@amd.com>
 *
 */

/// Macros for system calls requests
pub mod syscall;
/// Userspace SVSM
pub mod user;

pub use crate::user::user::svsm_user_main;
