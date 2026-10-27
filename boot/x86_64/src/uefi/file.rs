use core::ffi::c_void;

use super::table::SystemTable;
use super::types::{EfiHandle, EfiStatus};

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

pub const LOADED_IMAGE_GUID: Guid = Guid {
    data1: 0x5B1B31A1,
    data2: 0x9562,
    data3: 0x11D2,
    data4: [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

pub const SIMPLE_FILE_SYSTEM_GUID: Guid = Guid {
    data1: 0x964E5B22,
    data2: 0x6459,
    data3: 0x11D2,
    data4: [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

#[repr(C)]
pub struct LoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: EfiHandle,
    pub system_table: *mut SystemTable,
    pub device_handle: EfiHandle,
}

#[repr(C)]
pub struct SimpleFileSystemProtocol {
    pub revision: u64,

    pub open_volume: unsafe extern "efiapi" fn(
        this: *mut SimpleFileSystemProtocol,
        root: *mut *mut FileProtocol,
    ) -> EfiStatus,
}

#[repr(C)]
pub struct FileProtocol {
    pub revision: u64,

    pub open: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        new_handle: *mut *mut FileProtocol,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> EfiStatus,

    pub close: unsafe extern "efiapi" fn(this: *mut FileProtocol) -> EfiStatus,

    pub delete: unsafe extern "efiapi" fn(this: *mut FileProtocol) -> EfiStatus,

    pub read: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        buffer_size: *mut usize,
        buffer: *mut c_void,
    ) -> EfiStatus,

    pub write: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        buffer_size: *mut usize,
        buffer: *const c_void,
    ) -> EfiStatus,

    pub get_position:
        unsafe extern "efiapi" fn(this: *mut FileProtocol, position: *mut u64) -> EfiStatus,

    pub set_position:
        unsafe extern "efiapi" fn(this: *mut FileProtocol, position: u64) -> EfiStatus,
}
