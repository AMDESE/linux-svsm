/* SPDX-License-Identifier: MIT */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Add bindgen generated FFI bindings and test cases.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindgen_out.rs"));
