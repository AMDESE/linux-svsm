/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::funcs;
use crate::locking::LockGuard;
use crate::locking::SpinLock;

use alloc::vec::Vec;
use lazy_static::lazy_static;
use x86_64::addr::PhysAddr;

#[derive(Clone, Copy, Debug)]
struct VmsaInfo {
    gpa: u64,
    apic_id: u32,
}

#[allow(dead_code)]
impl VmsaInfo {
    funcs!(gpa, u64);
    funcs!(apic_id, u32);
}

lazy_static! {
    static ref VMSA_LIST: SpinLock<Vec<VmsaInfo>> = SpinLock::new(Vec::with_capacity(512));
}

pub fn del_vmsa(gpa: PhysAddr) -> bool {
    let mut vmsa_list: LockGuard<Vec<VmsaInfo>> = VMSA_LIST.lock();

    for i in 0..vmsa_list.len() {
        if vmsa_list[i].gpa == gpa.as_u64() {
            vmsa_list.swap_remove(i);
            return true;
        }
    }

    false
}

#[inline]
pub fn add_vmsa(gpa: PhysAddr, apic_id: u32) -> bool {
    let mut vmsa_list: LockGuard<Vec<VmsaInfo>> = VMSA_LIST.lock();
    vmsa_list.push(VmsaInfo {
        gpa: gpa.as_u64(),
        apic_id: apic_id,
    });
    true
}

pub fn vmsa_to_apic_id(gpa: PhysAddr) -> Option<u32> {
    let vmsa_list: LockGuard<Vec<VmsaInfo>> = VMSA_LIST.lock();

    for i in 0..vmsa_list.len() {
        if vmsa_list[i].gpa() == gpa.as_u64() {
            return Some(vmsa_list[i].apic_id());
        }
    }

    return None;
}

pub fn vmsa_page(gpa: PhysAddr) -> bool {
    let vmsa_list: LockGuard<Vec<VmsaInfo>> = VMSA_LIST.lock();

    for i in 0..vmsa_list.len() {
        if vmsa_list[i].gpa() == gpa.as_u64() {
            return true;
        }
    }

    false
}
