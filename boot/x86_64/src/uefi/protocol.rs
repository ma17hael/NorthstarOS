use super::types::{EfiChar16, EfiStatus};

#[repr(C)]
#[allow(dead_code)]
pub struct SimpleTextOutputProtocol {
    pub reset: unsafe extern "efiapi" fn(
        this: *mut SimpleTextOutputProtocol,
        extended_verification: u8,
    ) -> EfiStatus,

    pub output_string: unsafe extern "efiapi" fn(
        this: *mut SimpleTextOutputProtocol,
        string: *const EfiChar16,
    ) -> EfiStatus,
}
