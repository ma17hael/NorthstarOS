use core::ffi::c_void;

use super::file::Guid;
use super::table::TableHeader;
use super::types::{EfiHandle, EfiStatus};

#[repr(C)]
pub struct BootServices {
    pub header: TableHeader,
    // Les 16 pointeurs de fonctions qui precedent HandleProtocol.
    // Nous les definirons individuellement plus tard.
    _previous_services: [usize; 16],

    pub handle_protocol: unsafe extern "efiapi" fn(
        handle: EfiHandle,
        protocol: *const Guid,
        interface: *mut *mut c_void,
    ) -> EfiStatus,
}
