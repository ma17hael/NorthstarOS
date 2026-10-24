#![no_std]
#![no_main]

mod boot;
mod console;
mod uefi;

use core::hint::spin_loop;
use core::panic::PanicInfo;

use uefi::{EFI_SUCCESS, EfiHandle, EfiStatus, SystemTable};

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(
    _image_handle: EfiHandle,
    system_table: *mut SystemTable,
) -> EfiStatus {
    let status = boot::run(system_table);

    if status != EFI_SUCCESS {
        return status;
    }

    // Maintient l'affichage pour le premier prototype.
    // Un véritable transfert vers le noyau remplacera
    // cette boucle
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
