use core::ffi::c_void;

pub type EfiHandle = *mut c_void;
pub type EfiStatus = usize;
pub type EfiChar16 = u16;

const EFI_ERROR_BIT: usize = 1usize << (usize::BITS - 1);

pub const EFI_SUCCESS: EfiStatus = 0;
pub const EFI_INVALID_PARAMETER: EfiStatus = EFI_ERROR_BIT | 2;
pub const EFI_UNSUPPORTED: EfiStatus = EFI_ERROR_BIT | 3;
