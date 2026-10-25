use super::protocol::SimpleTextOutputProtocol;
use super::types::{EfiChar16, EfiHandle};

#[repr(C)]
#[allow(dead_code)]
pub struct TableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
#[allow(dead_code)]
pub struct SystemTable {
    pub header: TableHeader,

    pub firmware_vendor: *mut EfiChar16,
    pub firmware_revision: u32,

    pub console_in_handle: EfiHandle,
    pub console_in: *mut core::ffi::c_void,

    pub console_out_handle: EfiHandle,
    pub console_out: *mut SimpleTextOutputProtocol,

    pub standard_error_handle: EfiHandle,
    pub standard_error: *mut core::ffi::c_void,

    pub runtime_services: *mut core::ffi::c_void,
    pub boot_services: *mut super::services::BootServices,
}
