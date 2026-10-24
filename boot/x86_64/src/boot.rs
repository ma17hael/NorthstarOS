use crate::console::Console;
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

pub fn run(system_table: *mut SystemTable) -> EfiStatus {
    let mut console = match unsafe { Console::from_system_table(system_table) } {
        Ok(console) => console,
        Err(status) => return status,
    };

    let result = console.write_ascii(
        "Northstar Boot\n\
        Version 0.1.0\n\
        Architecture: x86_64\n\
        UEFI initialized successfully\n",
    );

    match result {
        Ok(()) => EFI_SUCCESS,
        Err(status) => status,
    }
}
