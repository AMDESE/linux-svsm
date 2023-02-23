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

unsafe fn handle_request(vmsa: *mut Vmsa) {
    let protocol: u32 = UPPER_32BITS!((*vmsa).rax()) as u32;
    let callid: u32 = LOWER_32BITS!((*vmsa).rax()) as u32;

    match protocol {
        SVSM_CORE_PROTOCOL => core_handle_request(callid, vmsa),
        SVSM_ATTESTATION_PROTOCOL => attestation_handle_request(callid, vmsa),
        _ => (*vmsa).set_rax(SVSM_ERR_UNSUPPORTED_PROTOCOL),
    }
}

pub fn svsm_request_add_init_vmsa(vmsa_pa: PhysAddr, apic_id: u32) {
    VMSA_LIST.push(vmsa_pa, apic_id);
}

fn process_one_request(vmpl: VMPL) -> Result<(), String> {
    //
    // Limit the mapping of guest memory to only what is needed to process
    // the request.
    //
    let caa_gpa: PhysAddr = unsafe { PERCPU.caa(vmpl) };
    let mut ca_map: MapGuard = match MapGuard::new_private(caa_gpa, CAA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => return Err(alloc::format!("Error mapping guest calling area: {e:?}")),
    };

    let vmsa_gpa: PhysAddr = unsafe { PERCPU.vmsa(vmpl) };
    let mut vmsa_map: MapGuard = match MapGuard::new_private(vmsa_gpa, VMSA_MAP_SIZE) {
        Ok(m) => m,
        Err(e) => return Err(alloc::format!("Error mapping guest VMSA: {e:?}")),
    };

    if !vmsa_clear_efer_svme(vmsa_map.va()) {
        let msg: String = alloc::format!("map_guest_input: vmsa_clear_efer_svme() failed");
        return Err(msg);
    }

    let vmsa: &mut Vmsa = vmsa_map.as_object_mut();
    let ca: &mut Ca = ca_map.as_object_mut();

    if vmsa.guest_exitcode() == VMEXIT_VMGEXIT && ca.call_pending() == 1 {
        unsafe { handle_request(&mut *vmsa) };
        ca.set_call_pending(0);
    }

    //
    // Set EFER.SVME to 1 to allow the VMSA to be run by the hypervisor.
    //
    vmsa_set_efer_svme(vmsa_map.va());

    Ok(())
}

/// Process SVSM requests
pub fn svsm_request_loop() {
    loop {
        match process_one_request(VMPL::Vmpl1) {
            Ok(()) => (),
            Err(e) => prints!("{}", e),
        };
        vc_run_vmpl(VMPL::Vmpl1);
    }
}
