#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

use northstar_boot_protocol::{BootInfo, KernelEntry};

const COM1: u16 = 0x3F8;
const _: KernelEntry = _start;

unsafe fn serial_write_byte(byte: u8) {
    // SAFETY: necessite un port serie COM1 disponible
    // et les privileges d'E/S du noyau.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") COM1,
            in("al") byte,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn serial_write(text: &str) {
    for byte in text.bytes() {
        unsafe {
            serial_write_byte(byte);
        }
    }
}

/// # Safety
///
/// L'appelant doit garantir que :
/// - Le processeur est en Long Mode avec les privileges Ring 0.
/// - Les services de demarrage UEFI ont ete quittes.
/// - Les tables de pagination du noyau sont actives.
/// - La pile du noyau est mappee et respecte l'ABI System V AMD64.
/// - Le pointeur BootInfo est valide, aligne et accessible.
/// - Les interruptions masquables sont desactivees.
/// - Le Direction Flag est desactive.
/// - Le port serie COM1 est initialise et accessible.
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn _start(_boot_info: *const BootInfo) -> ! {
    serial_write("Northstar Kernel initialized\n");

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
