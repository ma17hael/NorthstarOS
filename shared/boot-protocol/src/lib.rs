#![no_std]

use core::mem::size_of;
// "NSTBOOT" en ASCII
pub const BOOT_INFO_MAGIC: u64 = 0x4E53_5452_424F_4F54;
pub const BOOT_INFO_VERSION: u32 = 1;
// La carte memoire ne sera valide qu'apres
// une acquisition finale avant ExitBootService
pub const FLAG_MEMORY_MAP_VALID: u64 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelInfo {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub image_size: u64,
    pub entry_virtual: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackInfo {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub size: u64,
    pub top_virtual: u64,
    pub guard_virtual: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingInfo {
    pub pml4_physical: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryMapInfo {
    pub physical_base: u64,
    pub size_bytes: u64,
    pub descriptor_size: u64,
    pub descriptor_version: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfo {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    pub flags: u64,

    pub kernel: KernelInfo,
    pub stack: StackInfo,
    pub paging: PagingInfo,
    pub memory_map: MemoryMapInfo,
}

impl BootInfo {
    pub const fn new(kernel: KernelInfo, stack: StackInfo, paging: PagingInfo) -> Self {
        Self {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            size: size_of::<Self>() as u32,
            flags: 0,
            kernel,
            stack,
            paging,
            memory_map: MemoryMapInfo {
                physical_base: 0,
                size_bytes: 0,
                descriptor_size: 0,
                descriptor_version: 0,
                reserved: 0,
            },
        }
    }

    pub fn validate(&self) -> bool {
        self.magic == BOOT_INFO_MAGIC
            && self.version == BOOT_INFO_VERSION
            && self.size as usize == size_of::<Self>()
            && self.kernel.image_size != 0
            && self.stack.size != 0
            && self.stack.top_virtual > self.stack.virtual_base
            && self.paging.pml4_physical != 0
    }

    pub fn has_memory_map(&self) -> bool {
        self.flags & FLAG_MEMORY_MAP_VALID != 0
    }
}
