#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::spin_loop;
use core::panic::PanicInfo;

const COM1: u16 = 0x3F8;

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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
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
