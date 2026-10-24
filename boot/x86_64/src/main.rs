#![no_std]
#![no_main]

use core::ffi::c_void;
use core::hint::spin_loop;
use core::panic::PanicInfo;

type EfiStatus = usize;
type EfiHandle = *mut c_void;
type EfiChar16 = u16;

const EFI_SUCCESS: EfiStatus = 0;

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32
}

#[repr(C)]
struct EfiSimpleTextOutputProtocol {
    reset: unsafe extern "efiapi" fn(this: *mut EfiSimpleTextOutputProtocol, extended_verification: u8) -> EfiStatus,
    output_string: unsafe extern "efiapi" fn(this: *mut EfiSimpleTextOutputProtocol, string: *const EfiChar16) -> EfiStatus
}

#[repr(C)]
pub struct EfiSystemTable {
    header: EfiTableHeader,
    firmware_vendor: *mut EfiChar16,
    firmware_revision: u32,
    console_in_handle: EfiHandle,
    console_in: *mut c_void,
    console_out_handle: EfiHandle,
    console_out: *mut EfiSimpleTextOutputProtocol,
}

static MESSAGE: [u16; 17] = [
    0x004E, //N
    0x006F, //o
    0x0072, //r
    0x0074, //t
    0x0068, //h
    0x0073, //s
    0x0074, //t
    0x0061, //a
    0x0072, //r
    0x0020, //
    0x0042, //B
    0x006F, //o
    0x006F, //o
    0x0074, //t
    0x000D, //\r
    0x000A, //\n
    0x0000, //terminator
];

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(_image_handle: EfiHandle, system_table: *mut EfiSystemTable) -> EfiStatus {
    if system_table.is_null() {
        return EFI_SUCCESS;
    }

    unsafe {
        let console = (*system_table).console_out;
        if console.is_null() {
            return EFI_SUCCESS;
        }
        ((*console).output_string)(console, MESSAGE.as_ptr());
    }

    loop {
        spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        spin_loop();
    }
}