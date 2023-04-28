/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

#[cfg(feature = "verbose")]
pub mod verbose_serial {

    use crate::BIT;

    /// 0x3f8
    pub const TTYS0: u16 = 0x3f8;

    /// 115200
    pub const DIV_BASE: u64 = 115200;
    /// Bit 7
    pub const DLAB_BIT: u8 = BIT!(7);

    /// 1
    pub const IER: u16 = 1;
    /// 2
    pub const FCR: u16 = 2;
    /// 3
    pub const LCR: u16 = 3;
    /// 4
    pub const MCR: u16 = 4;

    /// 0
    pub const DLL: u16 = 0;
    /// 1
    pub const DLM: u16 = 1;

    pub static PORT: u16 = TTYS0;

    pub static mut SERIAL_READY: bool = false;
}

#[cfg(not(feature = "verbose"))]
pub fn serial_out(_string: &str) {}
#[cfg(not(feature = "verbose"))]
pub fn serial_init() {}

/// Print with format to the serial output
#[macro_export]
macro_rules! prints {
    ($($args:tt),*) => {{
            use crate::util::serial::serial_out;
            serial_out(&alloc::format!($($args),*))
    }};
}

#[inline]
#[cfg(feature = "verbose")]
pub fn serial_out(string: &str) {
    use crate::cpu::vc_outb;
    use crate::serial::verbose_serial::{PORT, SERIAL_READY};
    unsafe {
        if !SERIAL_READY {
            return;
        }
    }

    for b in string.as_bytes() {
        vc_outb(PORT, *b);
    }
}

/// Initialize serial port
#[cfg(feature = "verbose")]
pub fn serial_init() {
    use crate::cpu::{vc_inb, vc_outb};
    use crate::serial::verbose_serial::*;
    vc_outb(PORT + IER, 0); /* Disable all interrupts */
    vc_outb(PORT + FCR, 0); /* Disable all FIFOs */
    vc_outb(PORT + LCR, 3); /* 8n1 */
    vc_outb(PORT + MCR, 3); /* DTR and RTS */

    let div: u16 = (DIV_BASE / 115200) as u16;
    let div_lo: u8 = (div & 0xff) as u8;
    let div_hi: u8 = ((div >> 8) & 0xff) as u8;

    let c: u8 = vc_inb(PORT + LCR);
    vc_outb(PORT + LCR, c | DLAB_BIT);
    vc_outb(PORT + DLL, div_lo);
    vc_outb(PORT + DLM, div_hi);
    vc_outb(PORT + LCR, c);

    unsafe {
        SERIAL_READY = true;
    }
}
