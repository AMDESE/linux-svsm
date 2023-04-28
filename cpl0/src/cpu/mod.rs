/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022, 2023 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

/// CPL handling
pub mod cpl;
/// Handle CpuidPages and their entries.
pub mod cpuid;
/// Create IDT and handle exceptions
pub mod idt;
/// Handle per-vCPU information (Vmsa and Caa)
pub mod percpu;
/// Initialize and start SMP
pub mod smp;
/// Auxiliary assembly functions
pub mod sys;
/// System call initialization
pub mod syscall;
/// Per-CPU TSS support
pub mod tss;
/// VC functions
pub mod vc;
/// Vmsa (Virtual Machine Saving Area) support
pub mod vmsa;

pub use crate::cpu::cpl::*;
pub use crate::cpu::idt::*;
pub use crate::cpu::percpu::*;
pub use crate::cpu::smp::*;
pub use crate::cpu::sys::*;
pub use crate::cpu::syscall::*;
pub use crate::cpu::tss::*;
pub use crate::cpu::vc::*;
