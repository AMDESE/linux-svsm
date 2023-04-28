/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use crate::cpu::percpu::PERCPU;
use crate::cpu::vc_run_vmpl;
use crate::cpu::vmsa::Vmsa;
use crate::globals::*;
use crate::mem::ca::Ca;
use crate::protocols::error_codes::*;
use crate::protocols::*;
use crate::vmsa_list::*;
use crate::*;

use alloc::string::String;
use x86_64::addr::PhysAddr;

/// 0x403
const VMEXIT_VMGEXIT: u64 = 0x403;

// Returns false if the request should be handled by userspace
unsafe fn handle_request(vmsa: *mut Vmsa) -> bool {
    let protocol: u32 = UPPER_32BITS!((*vmsa).rax()) as u32;
    let callid: u32 = LOWER_32BITS!((*vmsa).rax()) as u32;

    // Return false in future operations that the user can handle
    // handle_set_request_finished() will also require updates

    match protocol {
        SVSM_CORE_PROTOCOL => core_handle_request(callid, vmsa),
        _ => (*vmsa).set_rax(SVSM_ERR_UNSUPPORTED_PROTOCOL),
    }

    true
}

pub fn svsm_request_add_init_vmsa(vmsa_pa: PhysAddr, apic_id: u32) {
    VMSA_LIST.push(vmsa_pa, apic_id);
}

enum ProcessResult {
    Ok,
    Err(String),
    Int(u64),
}

fn process_one_request(vmpl: VMPL) -> ProcessResult {
    //
    // Limit the mapping of guest memory to only what is needed to process
    // the request.
    //
    let caa_gpa: PhysAddr = unsafe { PERCPU.caa(vmpl) };
    let mut ca_map: MapGuard = match MapGuard::new_private(caa_gpa, CAA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => {
            return ProcessResult::Err(alloc::format!("Error mapping guest calling area: {e:?}"))
        }
    };

    let vmsa_gpa: PhysAddr = unsafe { PERCPU.vmsa(vmpl) };
    let mut vmsa_map: MapGuard = match MapGuard::new_private(vmsa_gpa, VMSA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => return ProcessResult::Err(alloc::format!("Error mapping guest VMSA: {e:?}")),
    };

    if !vmsa_clear_efer_svme(vmsa_map.va()) {
        let msg: String = alloc::format!("map_guest_input: vmsa_clear_efer_svme() failed");
        return ProcessResult::Err(msg);
    }

    let vmsa: &mut Vmsa = vmsa_map.as_object_mut();
    let ca: &mut Ca = ca_map.as_object_mut();

    if vmsa.guest_exitcode() == VMEXIT_VMGEXIT && ca.call_pending() == 1 {
        unsafe {
            // Is this an operation for userspace?
            if handle_request(&mut *vmsa) == false {
                return ProcessResult::Int((*vmsa).rax());
            }
        };
        ca.set_call_pending(0);
    }

    //
    // Set EFER.SVME to 1 to allow the VMSA to be run by the hypervisor.
    //
    vmsa_set_efer_svme(vmsa_map.va());

    ProcessResult::Ok
}

/// Process SVSM requests
pub fn svsm_request_loop() -> u64 {
    loop {
        match process_one_request(VMPL::Vmpl1) {
            ProcessResult::Ok => (),
            // This might be an operation for userspace
            ProcessResult::Int(rax) => return rax,
            ProcessResult::Err(e) => prints!("{}", e),
        };
        vc_run_vmpl(VMPL::Vmpl1);
    }
}
