/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * Authors: Carlos Bilbao <carlos.bilbao@amd.com> and
 *          Tom Lendacky <thomas.lendacky@amd.com>
 */

use core::arch::asm;
use core::intrinsics::size_of;

use memoffset::offset_of;
use x86_64::addr::*;
use x86_64::structures::paging::PhysFrame;

use crate::cpu::{vc_cpuid, wrmsr, *};
use crate::globals::*;
use crate::mem::*;
use crate::percpu::alloc::vec::Vec;
use crate::*;

#[repr(C)]
#[derive(Debug)]
///
/// Each CPU runs one vCPU, which mainly needs to save execution context
/// (Vmsa) and Caa
///
pub struct PerCpu {
    cpu_id: u32,
    apic_id: u32,

    ghcb: u64,

    vmsa: [u64; VMPL::VmplMax as usize],
    caa: [u64; VMPL::VmplMax as usize],

    tss: u64,
}

//
// This implementation doesn't use the struct to actually hold data. Offsets are obtained and then
// assembler loads/stores using the GS segment or directly to memory actually perform the per-CPU
// support.
//
impl PerCpu {
    pub const fn new() -> Self {
        PerCpu {
            cpu_id: 0,
            apic_id: 0,

            ghcb: 0,
            vmsa: [0; VMPL::VmplMax as usize],
            caa: [0; VMPL::VmplMax as usize],

            tss: 0,
        }
    }

    /// Retrieve id of current CPU (i.e. current vCPU)
    pub fn cpu_id(&mut self) -> u32 {
        let cpu_id: u32;

        unsafe {
            asm!("mov {1:e}, gs:[{0}]",
                 in(reg) offset_of!(PerCpu, cpu_id),
                 out(reg) cpu_id,
            );
        }

        cpu_id
    }

    /// Set id of current CPU
    pub fn set_cpu_id(&mut self, cpu_id: u32) {
        unsafe {
            asm!("mov gs:[{0}], {1:e}",
                 in(reg) offset_of!(PerCpu, cpu_id),
                 in(reg) cpu_id,
            );
        }
    }

    /// Retrieve id for a given CPU
    pub fn cpu_id_for(&mut self, for_id: usize) -> u32 {
        let cpu_id: u32;

        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *const PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *const PerCpu;
            cpu_id = (*p).cpu_id;

            assert!((cpu_id as usize) == for_id);
        }

        cpu_id
    }

    /// Set id for a given CPU
    pub fn set_cpu_id_for(&mut self, cpu_id: u32, for_id: usize) {
        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *mut PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *mut PerCpu;
            (*p).cpu_id = cpu_id;
        }
    }

    /// Obtain ApicId of current CPU
    pub fn apic_id(&mut self) -> u32 {
        let apic_id: u32;

        unsafe {
            asm!("mov {1:e}, gs:[{0}]",
                 in(reg) offset_of!(PerCpu, apic_id),
                 out(reg) apic_id,
            );
        }

        apic_id
    }

    /// Set ApicId of current CPU
    pub fn set_apic_id(&mut self, apic_id: u32) {
        unsafe {
            asm!("mov gs:[{0}], {1:e}",
                 in(reg) offset_of!(PerCpu, apic_id),
                 in(reg) apic_id,
            );
        }
    }

    /// Obtain ApicId of a given CPU
    pub fn apic_id_for(&mut self, for_id: usize) -> u32 {
        let apic_id: u32;

        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *const PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *const PerCpu;
            apic_id = (*p).cpu_id;
        }

        apic_id
    }

    /// Set ApicId of a given CPU
    pub fn set_apic_id_for(&mut self, apic_id: u32, for_id: usize) {
        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *mut PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *mut PerCpu;
            (*p).apic_id = apic_id;
        }
    }

    /// Return virtual address of GHCB of a CPU
    pub fn ghcb(&mut self) -> VirtAddr {
        let ghcb: u64;

        unsafe {
            asm!("mov {1}, gs:[{0}]",
                 in(reg) offset_of!(PerCpu, ghcb),
                 out(reg) ghcb,
            );
        }

        VirtAddr::new_truncate(ghcb)
    }

    /// Set GHCB of current CPU
    pub fn set_ghcb(&mut self, ghcb: VirtAddr) {
        unsafe {
            asm!("mov gs:[{0}], {1}",
                 in(reg) offset_of!(PerCpu, ghcb),
                 in(reg) ghcb.as_u64(),
            );
        }
    }

    /// Obtain GHCB for a given CPU
    pub fn ghcb_for(&mut self, for_id: usize) -> VirtAddr {
        let ghcb: u64;

        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *const PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *const PerCpu;
            ghcb = (*p).ghcb
        }

        VirtAddr::new_truncate(ghcb)
    }

    /// Set GHCB for a given CPU
    pub fn set_ghcb_for(&mut self, ghcb: VirtAddr, for_id: usize) {
        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *mut PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *mut PerCpu;
            (*p).ghcb = ghcb.as_u64();
        }
    }

    /// Obtain Vmsa for current CPU (i.e. its execution context)
    pub fn vmsa(&mut self, vmpl: VMPL) -> VirtAddr {
        let vmsa: u64;

        unsafe {
            let mut offset: usize = offset_of!(PerCpu, vmsa);
            offset += vmpl as usize * size_of::<u64>();

            asm!("mov {1}, gs:[{0}]",
                 in(reg) offset,
                 out(reg) vmsa,
            );
        }

        VirtAddr::new_truncate(vmsa)
    }

    /// Set Vmsa for current CPU
    pub fn set_vmsa(&mut self, vmsa: VirtAddr, vmpl: VMPL) {
        unsafe {
            let mut offset: usize = offset_of!(PerCpu, vmsa);
            offset += vmpl as usize * size_of::<u64>();

            asm!("mov gs:[{0}], {1}",
                 in(reg) offset,
                 in(reg) vmsa.as_u64(),
            );
        }
    }

    /// Obtain Vmsa for a given vCPU
    pub fn vmsa_for(&mut self, vmpl: VMPL, for_id: usize) -> VirtAddr {
        let vmsa: u64;

        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *const PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *const PerCpu;
            vmsa = (*p).vmsa[vmpl as usize];
        }

        VirtAddr::new_truncate(vmsa)
    }

    /// Set Vmsa for a given CPU
    pub fn set_vmsa_for(&mut self, vmsa: VirtAddr, vmpl: VMPL, for_id: usize) {
        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *mut PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *mut PerCpu;
            (*p).vmsa[vmpl as usize] = vmsa.as_u64();
        }
    }

    /// Retrieve Caa of current CPU
    pub fn caa(&mut self, vmpl: VMPL) -> VirtAddr {
        let caa: u64;

        unsafe {
            let mut offset: usize = offset_of!(PerCpu, caa);
            offset += vmpl as usize * size_of::<u64>();

            asm!("mov {1}, gs:[{0}]",
                 in(reg) offset,
                 out(reg) caa,
            );
        }

        VirtAddr::new_truncate(caa)
    }

    /// Set Caa of current CPU
    pub fn set_caa(&mut self, caa: VirtAddr, vmpl: VMPL) {
        unsafe {
            let mut offset: usize = offset_of!(PerCpu, caa);
            offset += vmpl as usize * size_of::<u64>();

            asm!("mov gs:[{0}], {1}",
                 in(reg) offset,
                 in(reg) caa.as_u64(),
            );
        }
    }

    /// Retrieve Caa of a given CPU
    pub fn caa_for(&mut self, vmpl: VMPL, for_id: usize) -> VirtAddr {
        let caa: u64;

        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *const PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *const PerCpu;
            caa = (*p).caa[vmpl as usize];
        }

        VirtAddr::new_truncate(caa)
    }

    /// Set Caa of a given CPU
    pub fn set_caa_for(&mut self, caa: VirtAddr, vmpl: VMPL, for_id: usize) {
        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *mut PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *mut PerCpu;
            (*p).caa[vmpl as usize] = caa.as_u64();
        }
    }

    /// Return virtual address of TSS of a CPU
    pub fn tss(&mut self) -> VirtAddr {
        let tss: u64;

        unsafe {
            asm!("mov {1}, gs:[{0}]",
                 in(reg) offset_of!(PerCpu, tss),
                 out(reg) tss,
            );
        }

        VirtAddr::new_truncate(tss)
    }

    /// Set TSS of current CPU
    pub fn set_tss(&mut self, tss: VirtAddr) {
        unsafe {
            asm!("mov gs:[{0}], {1}",
                 in(reg) offset_of!(PerCpu, tss),
                 in(reg) tss.as_u64(),
            );
        }
    }

    /// Obtain TSS for a given CPU
    pub fn tss_for(&mut self, for_id: usize) -> VirtAddr {
        let tss: u64;

        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *const PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *const PerCpu;
            tss = (*p).tss
        }

        VirtAddr::new_truncate(tss)
    }

    /// Set TSS for a given CPU
    pub fn set_tss_for(&mut self, tss: VirtAddr, for_id: usize) {
        unsafe {
            assert!(for_id < CPU_COUNT);

            let p: *mut PerCpu =
                (PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE)) as *mut PerCpu;
            (*p).tss = tss.as_u64();
        }
    }
}

static mut CPU_COUNT: usize = 1;
static mut PERCPU_VA: VirtAddr = VirtAddr::zero();

static CACHE_LINE: u64 = 64;
static PERCPU_SIZE: u64 = ALIGN!(size_of::<PerCpu>() as u64, CACHE_LINE);

pub static mut PERCPU: PerCpu = PerCpu::new();

fn get_apic_id() -> u32 {
    let eax: u32 = CPUID_EXTENDED_TOPO;
    let ecx: u32 = 0;
    let edx: u32;

    (_, _, _, edx) = vc_cpuid(eax, ecx);

    edx
}

/// Obtain per-CPU data address for a given Apic Id
pub fn percpu_address(for_id: usize) -> VirtAddr {
    unsafe {
        assert!(for_id < CPU_COUNT);
        VirtAddr::new(PERCPU_VA.as_u64() + (for_id as u64 * PERCPU_SIZE))
    }
}

/// Obtain CPU count according to number of Apic Ids
pub fn percpu_count() -> usize {
    unsafe { CPU_COUNT as usize }
}

unsafe fn __percpu_init(init_frame: PhysFrame, init_count: u64) -> u64 {
    // Place BSP early GHCB into per-CPU data for use in VC
    let va: VirtAddr;
    va = pgtable_pa_to_va(PhysAddr::new(early_ghcb));

    PERCPU.set_ghcb(va);

    // Retrieve the list of APIC IDs
    let bsp_apic_id: u32 = get_apic_id();

    let apic_ids: Vec<u32> = vc_get_apic_ids(bsp_apic_id);
    CPU_COUNT = apic_ids.len();

    let count: u64 = PAGE_COUNT!(apic_ids.len() as u64 * PERCPU_SIZE);

    let frame: PhysFrame;
    if count != init_count {
        frame = match mem_allocate_frames(count) {
            Some(f) => f,
            None => vc_terminate_svsm_enomem(),
        };
    } else {
        frame = init_frame;
    }

    PERCPU_VA = pgtable_pa_to_va(frame.start_address());
    wrmsr(MSR_GS_BASE, PERCPU_VA.as_u64());

    PERCPU.set_cpu_id(0);
    PERCPU.set_apic_id(bsp_apic_id);
    PERCPU.set_ghcb(va);

    let mut cpu: u32 = 1;
    for i in 0..CPU_COUNT {
        if apic_ids[i] == bsp_apic_id {
            continue;
        }

        PERCPU.set_cpu_id_for(cpu, i);
        PERCPU.set_apic_id_for(apic_ids[i], i);
        cpu += 1;
    }

    count
}

/// Allocate a per-CPU data page, pointed to by GS regs. Also obtain Apic
/// Ids (needed for SMP).
pub fn percpu_init() {
    // Start with a enough pages for one piece of per-CPU data
    let init_count: u64 = PAGE_COUNT!(PERCPU_SIZE);
    let init_frame: PhysFrame = match mem_allocate_frames(init_count) {
        Some(f) => f,
        None => vc_terminate_svsm_enomem(),
    };
    let count: u64;

    wrmsr(
        MSR_GS_BASE,
        pgtable_pa_to_va(init_frame.start_address()).as_u64(),
    );

    unsafe {
        count = __percpu_init(init_frame, init_count);
    }

    if count != init_count {
        mem_free_frames(init_frame, init_count);
    }
}
