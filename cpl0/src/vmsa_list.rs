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

/// List of VMSAs (their GPAs and APIC IDs), with methods to inspect
/// and modify the list in a safe (locked) manner.
pub struct VmsaList {
    list: SpinLock<Vec<VmsaInfo>>,
}

impl Default for VmsaList {
    fn default() -> Self {
        Self {
            list: SpinLock::new(Vec::with_capacity(512)),
        }
    }
}

impl VmsaList {
    pub fn remove(&self, gpa: PhysAddr) -> bool {
        let mut vmsa_list: LockGuard<Vec<VmsaInfo>> = self.list.lock();
        match vmsa_list.iter().position(|&vi| vi.gpa() == gpa.as_u64()) {
            Some(i) => {
                vmsa_list.swap_remove(i);
                true
            }
            None => false,
        }
    }

    #[inline]
    pub fn push(&self, gpa: PhysAddr, apic_id: u32) {
        let mut vmsa_list: LockGuard<Vec<VmsaInfo>> = self.list.lock();
        vmsa_list.push(VmsaInfo {
            gpa: gpa.as_u64(),
            apic_id: apic_id,
        });
    }

    pub fn get_apic_id(&self, gpa: PhysAddr) -> Option<u32> {
        let vmsa_list: LockGuard<Vec<VmsaInfo>> = self.list.lock();
        vmsa_list
            .iter()
            .find(|&vi| vi.gpa() == gpa.as_u64())
            .map(|&vi| vi.apic_id())
    }

    pub fn contains(&self, gpa: PhysAddr) -> bool {
        let vmsa_list: LockGuard<Vec<VmsaInfo>> = self.list.lock();
        vmsa_list.iter().any(|&vi| vi.gpa() == gpa.as_u64())
    }
}

lazy_static! {
    /// Global list of VMSAs
    pub static ref VMSA_LIST: VmsaList = VmsaList::default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_apic_id() {
        let list: VmsaList = VmsaList::default();
        list.push(PhysAddr::new(0x1000), 2);
        list.push(PhysAddr::new(0x5000), 1);
        assert_eq!(list.get_apic_id(PhysAddr::new(0x1000)), Some(2));
        assert_eq!(list.get_apic_id(PhysAddr::new(0x5000)), Some(1));
        assert_eq!(list.get_apic_id(PhysAddr::new(0x3000)), None);
    }

    #[test]
    fn test_contains() {
        let list: VmsaList = VmsaList::default();
        list.push(PhysAddr::new(0x1000), 2);
        list.push(PhysAddr::new(0x5000), 1);
        assert_eq!(list.contains(PhysAddr::new(0x1000)), true);
        assert_eq!(list.contains(PhysAddr::new(0x5000)), true);
        assert_eq!(list.contains(PhysAddr::new(0x3000)), false);
    }

    #[test]
    fn test_remove() {
        let list: VmsaList = VmsaList::default();
        list.push(PhysAddr::new(0x1000), 2);
        list.push(PhysAddr::new(0x5000), 1);
        assert_eq!(list.remove(PhysAddr::new(0x1000)), true);
        assert_eq!(list.contains(PhysAddr::new(0x1000)), false);
        assert_eq!(list.contains(PhysAddr::new(0x5000)), true);

        // Test remove of non-existing vmsa
        assert_eq!(list.remove(PhysAddr::new(0x3000)), false);
    }
}
