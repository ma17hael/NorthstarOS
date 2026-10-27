use core::ffi::c_void;

use super::file::Guid;
use super::table::TableHeader;
use super::types::{EfiHandle, EfiStatus};

pub type EfiPhysicalAddress = u64;
pub type EfiAllocateType = u32;
pub type EfiMemoryType = u32;

pub const ALLOCATE_ANY_PAGES: EfiAllocateType = 0;
pub const EFI_LOADER_DATA: EfiMemoryType = 2;

#[repr(C)]
pub struct BootServices {
    pub header: TableHeader,
    // Task Priority Services
    _raise_tpl: usize,
    _restore_tpl: usize,
    // Memory Services
    pub allocate_pages: unsafe extern "efiapi" fn(
        allocation_type: EfiAllocateType,
        memory_type: EfiMemoryType,
        pages: usize,
        memory: *mut EfiPhysicalAddress,
    ) -> EfiStatus,

    pub free_pages:
        unsafe extern "efiapi" fn(memory: EfiPhysicalAddress, pages: usize) -> EfiStatus,

    pub get_memory_map: unsafe extern "efiapi" fn(
        memory_map_size: *mut usize,
        memory_map: *mut c_void,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> EfiStatus,
    // 11 services entre GetMemoryMap et HandleProtocol :
    // AllocatePool, FreePool, evenements, temporisateurs
    // et gestion des interfaces de protocoles.
    _intermediate_services: [usize; 11],

    pub handle_protocol: unsafe extern "efiapi" fn(
        handle: EfiHandle,
        protocol: *const Guid,
        interface: *mut *mut c_void,
    ) -> EfiStatus,
}
