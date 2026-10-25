use crate::console::Console;
use crate::loader;
use crate::uefi::EfiHandle;
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

pub fn run(image_handle: EfiHandle, system_table: *mut SystemTable) -> EfiStatus {
    let mut console = match unsafe { Console::from_system_table(system_table) } {
        Ok(console) => console,
        Err(status) => return status,
    };

    if let Err(status) = console.write_ascii(
        "Northstar Boot\n\
        Version 0.1.0\n\
        Architecture: x86_64\n\
        UEFI initialized successfully\n\n\
        Searching for Northstar Kernel...\n",
    ) {
        return status;
    }

    match loader::inspect_kernel(image_handle, system_table) {
        Ok(()) => {
            match console.write_ascii(
                "Kernel Found\n\
                ELF64 header validated\n",
            ) {
                Ok(()) => EFI_SUCCESS,
                Err(status) => status,
            }
        }
        Err(status) => {
            let _ = console.write_ascii("ERROR: Unable to read or validate kernel\n");

            status
        }
    }
}
