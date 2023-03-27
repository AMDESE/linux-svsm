/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Dov Murik <dovmurik@linux.ibm.com>
 */

use crate::getter_func;
use crate::mem::pgtable::{
    pgtable_map_pages_private, pgtable_map_pages_shared, pgtable_unmap_pages,
};

use core::slice;
use x86_64::structures::paging::mapper::MapToError;
use x86_64::structures::paging::page::Size4KiB;
use x86_64::{PhysAddr, VirtAddr};

/// An area mapped into virtual memory. If `unmap_on_drop` is true, the
/// area is unmapped when the `MapGuard` is dropped (out of scope).
///
/// # Examples
///
/// ```
/// fn work() -> Result<()> {
///   let map1 = MapGuard::new_private(gpa, size)?;
///   // view the memory as a C struct
///   let req: &MyRequestStruct = map1.as_object();
///   let map2 = MapGuard::new_private(gpa2, size)?; // <--- an error here will cause map1 to unmap
///   // view the memory as a slice of bytes with the correct size (the entire mapped area)
///   let buf: &[u8] = map2.as_bytes();
///
///   // read from the mapped memory
///   if some_condition {
///     return Err(...); // here both areas are unmapped
///   }
///
///   Ok(())
///   // here both areas are unmapped
/// }
/// ```

pub struct MapGuard {
    pa: PhysAddr,
    va: VirtAddr,
    len: u64,
    unmap_on_drop: bool,
}

impl MapGuard {
    /// Map an area to virtual memory as private (encrypted) pages; when
    /// the MapGuard is dropped, the area will be unmapped.
    pub fn new_private(pa: PhysAddr, len: u64) -> Result<Self, MapToError<Size4KiB>> {
        let va: VirtAddr = pgtable_map_pages_private(pa, len)?;
        Ok(Self {
            pa,
            va,
            len,
            unmap_on_drop: true,
        })
    }

    /// Map an area to virtual memory as private (encrypted) pages but
    /// don't unmap it when the MapGuard is dropped.
    pub fn new_private_persistent(pa: PhysAddr, len: u64) -> Result<Self, MapToError<Size4KiB>> {
        let va: VirtAddr = pgtable_map_pages_private(pa, len)?;
        Ok(Self {
            pa,
            va,
            len,
            unmap_on_drop: false,
        })
    }

    /// Map an area to virtual memory as shared (plaintext) pages; when
    /// the MapGuard is dropped, the area will be unmapped.
    pub fn new_shared(pa: PhysAddr, len: u64) -> Result<Self, MapToError<Size4KiB>> {
        let va: VirtAddr = pgtable_map_pages_shared(pa, len)?;
        Ok(Self {
            pa,
            va,
            len,
            unmap_on_drop: true,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.va.as_ptr(), self.len as usize) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.va.as_mut_ptr(), self.len as usize) }
    }

    pub fn as_object<T>(&self) -> &T {
        unsafe { &slice::from_raw_parts::<T>(self.va.as_ptr() as *const _, 1)[0] }
    }

    pub fn as_object_mut<T>(&mut self) -> &mut T {
        unsafe { &mut slice::from_raw_parts_mut::<T>(self.va.as_mut_ptr() as *mut _, 1)[0] }
    }

    getter_func!(pa, PhysAddr);
    getter_func!(va, VirtAddr);
    getter_func!(len, u64);
}

impl Drop for MapGuard {
    fn drop(&mut self) {
        if self.unmap_on_drop {
            pgtable_unmap_pages(self.va, self.len);
        }
    }
}
