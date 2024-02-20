/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Dov Murik <dovmurik@linux.ibm.com>
 */

use crate::locking::SpinLock;

use alloc::vec::Vec;
use core::mem::size_of;
use core::slice;
use lazy_static::lazy_static;
use uuid::{uuid, Uuid};

const SERVICES_MANIFEST_HEADER_UUID: Uuid = uuid!("63849ebb-3d92-4670-a1ff-58f9c94b87bb");

/// SVSM Spec Chapter 7 (Attestation): Table 12: Services Manifest
#[allow(dead_code)]
#[repr(C, packed)]
struct ManifestHeader {
    guid: uuid::Bytes,
    size: u32,
    num_services: u32,
}

impl ManifestHeader {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// SVSM Spec Chapter 7 (Attestation): Table 12: Services Manifest
#[allow(dead_code)]
#[repr(C, packed)]
struct ServiceEntry {
    guid: uuid::Bytes,
    data_offset: u32,
    data_size: u32,
}

impl ServiceEntry {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

struct Service {
    guid: Uuid,
    data: Vec<u8>,
}

pub struct Services {
    list: Vec<Service>,
}

impl Services {
    pub const fn new() -> Self {
        Services { list: Vec::new() }
    }

    pub fn add_service(&mut self, guid: Uuid, data: &[u8]) {
        self.list.push(Service {
            guid,
            data: data.to_vec(),
        });
    }

    /// Serialize the services manifest.  Set `single_service_guid` to `None` to
    /// include all services in the manifest, or to `Some(guid)` to include only
    /// a single service.
    pub fn get_manifest(
        &self,
        single_service_guid: Option<Uuid>,
        _manifest_version: Option<u32>,
    ) -> Vec<u8> {
        let mut service_entries: Vec<u8> = Vec::new();
        let data_start_offset: usize = size_of::<ManifestHeader>() as usize
            + (size_of::<ServiceEntry>() as usize * self.list.len());
        let mut data: Vec<u8> = Vec::new();
        for service in &self.list {
            if let Some(filter_guid) = single_service_guid {
                if service.guid != filter_guid {
                    continue;
                }
            }
            let entry: ServiceEntry = ServiceEntry {
                guid: service.guid.to_bytes_le(),
                data_offset: (data_start_offset + data.len()) as u32,
                data_size: service.data.len() as u32,
            };
            service_entries.extend_from_slice(entry.as_bytes());
            data.extend_from_slice(&service.data);
        }
        let total_size: usize =
            size_of::<ManifestHeader>() as usize + service_entries.len() + data.len();
        let header: ManifestHeader = ManifestHeader {
            guid: SERVICES_MANIFEST_HEADER_UUID.to_bytes_le(),
            size: total_size as u32,
            num_services: self.list.len() as u32,
        };
        let mut res: Vec<u8> = Vec::with_capacity(total_size);
        res.extend_from_slice(header.as_bytes());
        res.extend_from_slice(&service_entries);
        res.extend_from_slice(&data);
        res
    }
}

lazy_static! {
    /// Global registry of services
    pub static ref SERVICES: SpinLock<Services> = SpinLock::new(Services::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_serialize_empty_manifest() {
        let s: Services = Services::new();
        let b: Vec<u8> = s.get_manifest(None, None);
        assert_eq!(b.len(), 24);
    }

    #[test]
    pub fn test_serialize_manifest_with_services_and_data() {
        let mut s: Services = Services::new();
        s.add_service(
            uuid!("11112222-1234-5678-9abc-ddddeeeeffff"),
            b"TheServiceData",
        );
        s.add_service(
            uuid!("88889999-8888-9999-8888-999988889999"),
            b"OtherServiceData",
        );
        let b: Vec<u8> = s.get_manifest(None, None);
        assert_eq!(b.len(), 24 + 24 + 24 + 14 + 16);
        assert_eq!(&b[72..86], b"TheServiceData");
        assert_eq!(&b[86..], b"OtherServiceData");
    }

    #[test]
    pub fn test_serialize_single_service_manifest() {
        let mut s: Services = Services::new();
        s.add_service(
            uuid!("11112222-1234-5678-9abc-ddddeeeeffff"),
            b"TheServiceData",
        );
        s.add_service(
            uuid!("88889999-8888-9999-8888-999988889999"),
            b"OtherServiceData",
        );
        let b: Vec<u8> = s.get_manifest(Some(uuid!("11112222-1234-5678-9abc-ddddeeeeffff")), None);
        assert_eq!(b.len(), 24 + 24 + 14);
        assert_eq!(&b[48..], b"TheServiceData");
    }
}
