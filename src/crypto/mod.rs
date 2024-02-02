/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM
 *
 * Authors:
 *   Claudio Carvalho <cclaudio@linux.ibm.com>
 */

/// SSL
#[cfg_attr(test, path = "nossl.rs")]
#[cfg_attr(not(test), path = "openssl.rs")]
pub mod ssl;
