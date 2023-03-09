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
use crate::mem::pgtable_map_pages_private;
use crate::mem::pgtable_unmap_pages;
use crate::protocols::error_codes::*;
use crate::protocols::*;
use crate::vmsa_list::*;
use crate::*;

use alloc::string::String;
use x86_64::addr::{PhysAddr, VirtAddr};

/// 0x403
const VMEXIT_VMGEXIT: u64 = 0x403;

unsafe fn handle_request(vmsa: *mut Vmsa) {
    let protocol: u32 = UPPER_32BITS!((*vmsa).rax()) as u32;
    let callid: u32 = LOWER_32BITS!((*vmsa).rax()) as u32;

    match protocol {
        SVSM_CORE_PROTOCOL => core_handle_request(callid, vmsa),
        _ => (*vmsa).set_rax(SVSM_ERR_UNSUPPORTED_PROTOCOL),
    }
}

fn map_gpa(gpa: PhysAddr, len: u64) -> Result<VirtAddr, String> {
    if gpa == PhysAddr::zero() {
        let msg: String = alloc::format!("map_gpa: gpa cannot be zero");
        return Err(msg);
    }

    let va: VirtAddr = match pgtable_map_pages_private(gpa, len) {
        Ok(r) => r,
        Err(e) => {
            let msg: String = alloc::format!("map_gpa: {:?}", e);
            return Err(msg);
        }
    };

    Ok(va)
}

fn unmap_vmsa(va: VirtAddr) {
    pgtable_unmap_pages(va, VMSA_MAP_SIZE);
}

fn map_vmsa(vmpl: VMPL) -> Result<VirtAddr, String> {
    unsafe { map_gpa(PERCPU.vmsa(vmpl), VMSA_MAP_SIZE) }
}

fn unmap_ca(va: VirtAddr) {
    pgtable_unmap_pages(va, CAA_MAP_SIZE);
}

fn map_ca(vmpl: VMPL) -> Result<VirtAddr, String> {
    unsafe { map_gpa(PERCPU.caa(vmpl), CAA_MAP_SIZE) }
}

fn unmap_guest_input(ca_va: VirtAddr, vmsa_va: VirtAddr) {
    //
    // Set EFER.SVME to 1 to allow the VMSA to be run by the hypervisor.
    //
    vmsa_set_efer_svme(vmsa_va);

    unmap_vmsa(vmsa_va);
    unmap_ca(ca_va);
}

fn map_guest_input(vmpl: VMPL) -> Result<(VirtAddr, VirtAddr), String> {
    let ca_va: VirtAddr = match map_ca(vmpl) {
        Ok(r) => r,
        Err(e) => {
            return Err(e);
        }
    };

    let vmsa_va: VirtAddr = match map_vmsa(vmpl) {
        Ok(r) => r,
        Err(e) => {
            unmap_ca(ca_va);
            return Err(e);
        }
    };

    //
    // Set EFER.SVME to 0 to prevent the hypervisor from trying to
    // run the vCPU while a request is being handled.
    //
    if !vmsa_clear_efer_svme(vmsa_va) {
        unmap_vmsa(vmsa_va);
        unmap_ca(ca_va);

        let msg: String = alloc::format!("map_guest_input: clr_vmsa_efer_svme() failed");
        return Err(msg);
    }

    Ok((ca_va, vmsa_va))
}

pub fn svsm_request_add_init_vmsa(vmsa_pa: PhysAddr, apic_id: u32) {
    VMSA_LIST.push(vmsa_pa, apic_id);
}

/// Process SVSM requests
pub fn svsm_request_loop() {
    loop {
        //
        // Limit the mapping of guest memory to only what is needed to process
        // the request.
        //
        match map_guest_input(VMPL::Vmpl1) {
            Ok((ca_va, vmsa_va)) => unsafe {
                let vmsa: *mut Vmsa = vmsa_va.as_mut_ptr();
                let ca: *mut Ca = ca_va.as_mut_ptr();

                if (*vmsa).guest_exitcode() == VMEXIT_VMGEXIT && (*ca).call_pending() == 1 {
                    handle_request(vmsa);

                    (*ca).set_call_pending(0);
                }

                unmap_guest_input(ca_va, vmsa_va);
            },
            Err(e) => prints!("{}", e),
        }

        vc_run_vmpl(VMPL::Vmpl1);
    }
}
