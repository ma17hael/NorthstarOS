use crate::console::Console;
use crate::loader;
use crate::memory;
use crate::uefi::EfiHandle;
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

pub fn run(image_handle: EfiHandle, system_table: *mut SystemTable) -> EfiStatus {
    let mut console = match unsafe { Console::from_system_table(system_table) } {
        Ok(console) => console,
        Err(status) => return status,
    };

    let result = (|| -> Result<(), EfiStatus> {
        console.write_ascii(
            "Northstar Boot\n\
            Version 0.1.0\n\
            Architecture: x86_64\n\
            UEFI initialized successfully\n\n",
        )?;
        // Validation du noyau ELF64.
        console.write_ascii("Searching for Northstar Kernel...\n")?;

        if let Err(status) = loader::inspect_kernel(image_handle, system_table) {
            let _ = console.write_ascii("ERROR: Kernel validation failed\n");
            return Err(status);
        }

        console.write_ascii(
            "Kernel found\n\
            ELF64 header validated\n\
            Program headers validated\n\
            Executable entry point found\n\n",
        )?;
        // Test des services de gestion mémoire.
        console.write_ascii("Initializing memory services...\n")?;

        let address = match memory::test_allocation(system_table) {
            Ok(address) => address,
            Err(status) => {
                let _ = console.write_ascii("ERROR: Memory allocation test failed\n");
                return Err(status);
            }
        };

        console.write_ascii(
            "Allocated 4 pages (16 KiB)\n\
            Physical address: ",
        )?;

        console.write_hex_u64(address)?;

        console.write_ascii(
            "\nMemory alignement verified\n\
            Memory released successfully\n",
        )?;

        Ok(())
    })();

    match result {
        Ok(()) => EFI_SUCCESS,
        Err(status) => status,
    }
}
