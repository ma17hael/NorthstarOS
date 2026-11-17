use core::arch::asm;
use core::hint::spin_loop;

const COM1: u16 = 0x3F8;
const LINE_STATUS: u16 = 5;
const TRANSMITTER_EMPTY: u8 = 1 << 5;
// Eviter une attente infini si le port ne répond pas.
const MAX_POLLS: usize = 100_000;

#[inline]
fn outb(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        )
    }
}

#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;

    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            lateout("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    value
}
// Configurer le port serie COM1 en 115200 bauds, 8N1
pub fn init() {
    outb(COM1 + 1, 0x00); // Descativer les interruptions
    outb(COM1 + 3, 0x80); // Activer DLAB
    outb(COM1, 0x01); // Diviseur : 1
    outb(COM1 + 1, 0x00); // Partie haute du diviseur
    outb(COM1 + 3, 0x03); // 8 bits, aucune parite, 1 stop
    outb(COM1 + 2, 0xC7); // FIFO activees
    outb(COM1 + 4, 0x03); // DTR et RTS
}
// Retourne false si le port n'est pas disponible.
fn write_byte(byte: u8) -> bool {
    for _ in 0..MAX_POLLS {
        if inb(COM1 + LINE_STATUS) & TRANSMITTER_EMPTY != 0 {
            outb(COM1, byte);
            return true;
        }

        spin_loop();
    }

    false
}
// Ecriture directe sans allocation dynamique.
pub fn write_ascii(text: &str) {
    let mut previous_cr = false;

    for byte in text.bytes() {
        if byte == b'\n' && !previous_cr && !write_byte(b'\r') {
            return;
        }

        if !write_byte(byte) {
            return;
        }

        previous_cr = byte == b'\r';
    }
}
