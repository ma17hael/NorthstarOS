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
    header: TableHeader,
    firmware_vendor: *mut EfiChar16,
    firmware_revision: u32,
    console_in_handle: EfiHandle,
    console_in: *mut core::ffi::c_void,
    console_out_handle: EfiHandle,
    pub console_out: *mut SimpleTextOutputProtocol,
}
