use core::ptr::NonNull;

use crate::uefi::protocol::SimpleTextOutputProtocol;
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_INVALID_PARAMETER, EFI_SUCCESS, EFI_UNSUPPORTED, EfiStatus};

pub struct Console {
    protocol: NonNull<SimpleTextOutputProtocol>,
}

impl Console {
    /// # Safety
    /// `system_table` doit pointer vers une table UEFI valide
    /// fournie par le firmware, et rester valide pendant
    /// l'utilisation de la console.
    pub unsafe fn from_system_table(system_table: *mut SystemTable) -> Result<Self, EfiStatus> {
        let table = unsafe { system_table.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;
        let protocol = NonNull::new(table.console_out).ok_or(EFI_INVALID_PARAMETER)?;

        Ok(Self { protocol })
    }

    /// Affiche du texte ASCII sur le protocol UEFI
    /// Convertit LF en CRLF et ne nécessite aucune allocation.
    pub fn write_ascii(&mut self, text: &str) -> Result<(), EfiStatus> {
        let mut buffer = [0u16; 128];
        let mut length = 0usize;

        for byte in text.bytes() {
            if byte == 0 || !byte.is_ascii() {
                return Err(EFI_UNSUPPORTED);
            }

            if byte == b'\n' {
                self.push_char(b'\r' as u16, &mut buffer, &mut length)?;
            }

            self.push_char(byte as u16, &mut buffer, &mut length)?;
        }
        self.flush(&mut buffer, length)
    }

    fn push_char(
        &mut self,
        character: u16,
        buffer: &mut [u16; 128],
        length: &mut usize,
    ) -> Result<(), EfiStatus> {
        if *length == buffer.len() - 1 {
            self.flush(buffer, *length)?;
            *length = 0;
        }

        buffer[*length] = character;
        *length += 1;

        Ok(())
    }

    fn flush(&mut self, buffer: &mut [u16; 128], length: usize) -> Result<(), EfiStatus> {
        if length == 0 {
            return Ok(());
        }

        buffer[length] = 0;

        let protocol = self.protocol.as_ptr();
        // SAFETY:
        // Le pointeur provient de la table système UEFI.
        // Le buffer UTF-16 est terminé par zéro et reste
        // valide pendant l'appel du firmware.
        let status = unsafe { ((*protocol).output_string)(protocol, buffer.as_ptr()) };

        if status != EFI_SUCCESS {
            return Err(status);
        }

        Ok(())
    }
}
