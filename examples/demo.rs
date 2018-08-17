// Copyright (C) 2018, Cloudbase Solutions Srl
//
// Licensed under LGPL version 2 or any later version.

extern crate libc;
extern crate libkvm;

use libkvm::linux::kvm_bindings::*;
use libkvm::mem::MemorySlot;
use libkvm::system::*;
use libkvm::vcpu::VirtualCPU;
use std::fs::File;
use std::io::prelude::*;
use std::io::{self, Write};
use std::path::PathBuf;

const CPUID_EXT_HYPERVISOR: u32 = 1 << 31;

const PDE64_PRESENT: u64 = 1;
const PDE64_RW: u64 = 1 << 1;
const PDE64_USER: u64 = 1 << 2;
const PDE64_PS: u64 = 1 << 7;
const CR4_PAE: u64 = 1 << 5;

const CR0_PE: u64 = 1;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

fn main() {
    check_architecture();

    let kvm = KVMSystem::new().unwrap();
    let api = kvm.api_version().unwrap();
    println!("KVM API version: {}", api);

    // let tss_addr = 0xfffbd000;
    let identity_base = 0xfeffc000;
    let tss_addr = identity_base + 0x1000;
    let vm = kvm.create_vm().unwrap();

    vm.set_identity_map_addr(identity_base).unwrap();
    if kvm.check_cap_set_tss_address().unwrap() > 0 {
        println!("Setting TSS address");
        vm.set_tss_address(tss_addr as u32).unwrap();
    }

    let mem_size = 128 << 20;
    let fw_size = 2 << 20;

    let mut mem = MmapMemorySlot::new(mem_size, 0, 0, 0);
    vm.set_user_memory_region(&mem).unwrap();
    let mut bios_mem = MmapMemorySlot::new(fw_size, 0xffe00000, 1, 2);
    vm.set_user_memory_region(&bios_mem).unwrap();

    read_payload(&mut bios_mem);

    let mut vcpu = vm.create_vcpu().unwrap();

    init_regs(&vcpu);
    setup_cpuid(&kvm, &vcpu);
    setup_msrs(&kvm, &vcpu);

    let mut dump_regs = false;
    loop {
        vcpu.run().unwrap();
        let mut kvm_run = vcpu.kvm_run_mut();
        match kvm_run.exit_reason {
            KVM_EXIT_HLT => {
                println!("Halt");
                break;
            }
            KVM_EXIT_MMIO => {
                handle_mmio(&mut kvm_run);
            }
            KVM_EXIT_IO => {
                handle_io_port(&kvm_run);
            }
            KVM_EXIT_SHUTDOWN => {
                println!("Guest shutdown.");
            }
            KVM_EXIT_INTERNAL_ERROR => {
                dump_regs = true;
                unsafe {
                let suberr = kvm_run.__bindgen_anon_1.internal.suberror;
                let data_len = kvm_run.__bindgen_anon_1.internal.ndata as usize;

                println!("KVM internal error: {}. Extra data: {:#?}",
                         suberr,
                         if data_len > 0 {
                            kvm_run.__bindgen_anon_1.internal.data.chunks(data_len);
                         }
                         else {
                            0;
                         });
                }
                break;
            }
            _ => {
                panic!("Not supported exit reason: {}", kvm_run.exit_reason);
            }
        }
    }

    if dump_regs {
        dump_vcpu(&vcpu);
    }
}

fn dump_vcpu(vcpu: &VirtualCPU) {
    let regs = vcpu.get_kvm_regs();
    let sregs = vcpu.get_kvm_sregs();

    println!("CPU regs: {:#?}", regs);
    println!("CPU sregs: {:#?}", sregs);
}

fn handle_io_port(kvm_run: &kvm_run) {
    let io = unsafe { &kvm_run.__bindgen_anon_1.io };

    println!(">>> IOPort access.");
    if io.direction == KVM_EXIT_IO_OUT as u8 {
        let data_addr = kvm_run as *const _ as u64 + io.data_offset;
        let data = unsafe { std::slice::from_raw_parts(data_addr as *const u8, io.size as usize) };
        io::stdout().write(data).unwrap();
    }
}

fn handle_mmio(kvm_run: &mut kvm_run) {
    let mmio = unsafe { kvm_run.__bindgen_anon_1.mmio };

    let addr = mmio.phys_addr;
    let len = mmio.len;
    // let data = mmio.data[0..len as u8];
    // let data = unsafe {
    //     std::slice::from_raw_parts(addr as *const u64, len as usize)
    // };
    let data = mmio.data.chunks(len as usize);

    println!("MMIO {}, length: {}: [0x{:x}] {:?}",
             if mmio.is_write == 0 {"read"} else {"write"},
             len,
             addr,
             if mmio.is_write == 1 {format!("{:?}", data)}
             else {std::string::String::new()});
    // if mmio.len == 8 {
    //     if mmio.is_write == 0 {
    //         let data = &mmio.data as *const _ as *mut u64;
    //         unsafe {
    //             // *data = 0x1000;
    //             println!("MMIO read: [0x{:x}],  ", *data, );
    //         }
    //     } else {
    //         let value = unsafe { *(&mmio.data as *const _ as *const u64) };
    //         println!("MMIO write: 0x{:x}", value);
    //     }
    // }
}

fn setup_cpuid(kvm: &KVMSystem, vcpu: &VirtualCPU) {
    let mut kvm_cpuid_entries = kvm.get_supported_cpuid().unwrap();

    let i = kvm_cpuid_entries
        .iter()
        .position(|&r| r.function == 0x40000000)
        .unwrap();

    let mut id_reg_values: [u32; 3] = [0; 3];
    let id = "libwhp\0";
    unsafe {
        std::ptr::copy_nonoverlapping(id.as_ptr(), id_reg_values.as_mut_ptr() as *mut u8, id.len());
    }
    kvm_cpuid_entries[i].ebx = id_reg_values[0];
    kvm_cpuid_entries[i].ecx = id_reg_values[1];
    kvm_cpuid_entries[i].edx = id_reg_values[2];

    let i = kvm_cpuid_entries
        .iter()
        .position(|&r| r.function == 1)
        .unwrap();

    kvm_cpuid_entries[i].ecx |= CPUID_EXT_HYPERVISOR;

    vcpu.set_cpuid(&kvm_cpuid_entries).unwrap();
}

fn setup_msrs(kvm: &KVMSystem, vcpu: &VirtualCPU) {
    let msr_list = kvm.get_msr_index_list().unwrap();
    let ignored_msrs = [0x40000020, 0x40000022, 0x40000023];
    // let ignored_msrs = [];

    let msr_entries = msr_list
        .iter().filter(|i| !ignored_msrs.contains(i))
        .map(|i| kvm_msr_entry {
            index: *i,
            data: 0,
            ..Default::default()
        })
        .collect::<Vec<_>>();

    vcpu.set_msrs(&msr_entries).unwrap();
}

// fn get_seg(base: usize, selector: usize, flags: usize,
//            ) {
//     unsigned flags = rhs->flags;
//     lhs->selector = rhs->selector;
//     lhs->base = rhs->base;
//     lhs->limit = rhs->limit;
//     lhs->type = (flags >> DESC_TYPE_SHIFT) & 15;
//     lhs->present = (flags & DESC_P_MASK) != 0;
//     lhs->dpl = (flags >> DESC_DPL_SHIFT) & 3;
//     lhs->db = (flags >> DESC_B_SHIFT) & 1;
//     lhs->s = (flags & DESC_S_MASK) != 0;
//     lhs->l = (flags >> DESC_L_SHIFT) & 1;
//     lhs->g = (flags & DESC_G_MASK) != 0;
//     lhs->avl = (flags & DESC_AVL_MASK) != 0;
//     lhs->unusable = !lhs->present;
//     lhs->padding = 0;
// }

fn init_regs(vcpu: &VirtualCPU) {
    let mut sregs = vcpu.get_kvm_sregs().unwrap();
    // let mem_addr = mem.host_address();

    // let pml4_addr: u64 = 0x2000;
    // let pdpt_addr: u64 = 0x3000;
    // let pd_addr: u64 = 0x4000;
    // let pml4: u64 = mem_addr + pml4_addr;
    // let pdpt: u64 = mem_addr + pdpt_addr;
    // let pd: u64 = mem_addr + pd_addr;

    // unsafe {
    //     *(pml4 as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    //     *(pdpt as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
    //     *(pd as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
    // }

    // sregs.cr3 = pml4_addr;
    // sregs.cr4 = CR4_PAE;
    // sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    // sregs.efer = EFER_LME | EFER_LMA;

    sregs.cr0 = 0x60000010;
    let mut seg = kvm_segment {
        base: 0xffff0000,
        limit: 0xffff,
        selector: 0xf000,
        present: 1,
        type_: 11,
        dpl: 0,
        db: 0,
        s: 1,
        l: 0,
        g: 0,
        ..Default::default()
    };

    sregs.cs = seg;

    seg.base = 0;
    seg.type_ = 3;
    seg.selector = 0;
    sregs.ds = seg;
    sregs.es = seg;
    sregs.fs = seg;
    sregs.gs = seg;
    sregs.ss = seg;

    vcpu.set_kvm_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_kvm_regs().unwrap();
    // regs.rflags = 2;
    // regs.rip = 0;
    // regs.rsp = mem.memory_size() as u64;
    regs.rdx = 0x663;  // cpuid version
    regs.rip = 0xfff0;
    
    regs.rflags = 0x2;

    vcpu.set_kvm_regs(&regs).unwrap();
}

fn read_payload(mem: &mut MmapMemorySlot) {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("examples");
    p.push("payload");
    // p.push("payload.img");
    p.push("coreboot.rom");
    // p.push("bios.bin");

    let mut f = File::open(&p).expect(&format!(
        "Cannot find \"{}\". Run \"make\" in the same folder to build it",
        &p.to_str().unwrap()
    ));
    f.read(mem.as_slice_mut()).unwrap();
}

fn check_architecture() {
    #[cfg(not(target_arch = "x86_64"))]
    {
        panic!("Unsupported architecture");
    }
}

struct MmapMemorySlot {
    memory_size: usize,
    guest_address: u64,
    host_address: *mut libc::c_void,
    slot: u32,
    flags: u32,
}

impl MmapMemorySlot {
    pub fn new(memory_size: usize, guest_address: u64,
               slot: u32, flags: u32) -> MmapMemorySlot {
        let host_address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                memory_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };

        if host_address == libc::MAP_FAILED {
            panic!("mmapp failed with: {}", unsafe {
                *libc::__errno_location()
            });
        }

        let result = unsafe { libc::madvise(host_address, memory_size, libc::MADV_MERGEABLE) };
        if result == -1 {
            panic!("madvise failed with: {}", unsafe {
                *libc::__errno_location()
            });
        }

        MmapMemorySlot {
            memory_size: memory_size,
            guest_address: guest_address,
            host_address,
            slot,
            flags,
        }
    }

    fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.host_address as *mut u8, self.memory_size) }
    }
}

impl MemorySlot for MmapMemorySlot {
    fn slot_id(&self) -> u32 {
        self.slot
    }

    fn flags(&self) -> u32 {
        self.flags
    }

    fn memory_size(&self) -> usize {
        self.memory_size
    }

    fn guest_address(&self) -> u64 {
        self.guest_address
    }

    fn host_address(&self) -> u64 {
        self.host_address as u64
    }
}

impl Drop for MmapMemorySlot {
    fn drop(&mut self) {
        let result = unsafe { libc::munmap(self.host_address, self.memory_size) };
        if result != 0 {
            panic!("munmap failed with: {}", unsafe {
                *libc::__errno_location()
            });
        }
    }
}
