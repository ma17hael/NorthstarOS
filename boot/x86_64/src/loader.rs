use core::ffi::c_void;
use core::ptr::null_mut;

use crate::elf::{ElfHeader, PT_LOAD, ProgramHeader};
use crate::uefi::file::{
    FileProtocol, LOADED_IMAGE_GUID, LoadedImageProtocol, SIMPLE_FILE_SYSTEM_GUID,
    SimpleFileSystemProtocol,
};
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_INVALID_PARAMETER, EFI_SUCCESS, EfiHandle, EfiStatus};

const EFI_LOAD_ERROR: EfiStatus = (1usize << (usize::BITS - 1)) | 1;

const EFI_FILE_MODE_READ: u64 = 1;

pub fn inspect_kernel(
    image_handle: EfiHandle,
    system_table: *mut SystemTable,
) -> Result<(), EfiStatus> {
    let table = unsafe { system_table.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;

    let services = unsafe { table.boot_services.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;
    // Retrouver le peripherique de Northstar Boot.
    let mut loaded_image: *mut c_void = null_mut();

    let status =
        unsafe { (services.handle_protocol)(image_handle, &LOADED_IMAGE_GUID, &mut loaded_image) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let image =
        unsafe { (loaded_image as *mut LoadedImageProtocol).as_ref() }.ok_or(EFI_LOAD_ERROR)?;

    let mut filesystem: *mut c_void = null_mut();

    let status = unsafe {
        (services.handle_protocol)(
            image.device_handle,
            &SIMPLE_FILE_SYSTEM_GUID,
            &mut filesystem,
        )
    };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let filesystem = filesystem as *mut SimpleFileSystemProtocol;

    if filesystem.is_null() {
        return Err(EFI_LOAD_ERROR);
    }

    let mut root: *mut FileProtocol = null_mut();

    let status = unsafe { ((*filesystem).open_volume)(filesystem, &mut root) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    if root.is_null() {
        return Err(EFI_LOAD_ERROR);
    }
    // Nom de fichier UEFI en UTF-16 termine par zero.
    let name = b"\\EFI\\NORTHSTAR\\KERNEL.ELF";
    let mut path = [0u16; 64];

    for (index, byte) in name.iter().enumerate() {
        path[index] = *byte as u16;
    }

    let mut file: *mut FileProtocol = null_mut();

    let status = unsafe { ((*root).open)(root, &mut file, path.as_ptr(), EFI_FILE_MODE_READ, 0) };

    if status != EFI_SUCCESS || file.is_null() {
        unsafe {
            ((*root).close)(root);
        }

        return Err(if status == EFI_SUCCESS {
            EFI_LOAD_ERROR
        } else {
            status
        });
    }
    //Analyser le noyau tout en conservant les handles ouverts
    let result = (|| -> Result<(), EfiStatus> {
        // 1. Lire l'en tete ELF64
        let mut header_bytes = [0u8; 64];

        read_exact_at(file, 0, &mut header_bytes)?;

        let elf = ElfHeader::parse(&header_bytes).map_err(|_| EFI_LOAD_ERROR)?;
        // 2. Parcourir la table des Program Headers.
        let mut loadable_segments = 0usize;
        let mut entry_valid = false;

        for index in 0..usize::from(elf.program_header_count) {
            let relative_offset = (index as u64).checked_mul(56).ok_or(EFI_LOAD_ERROR)?;

            let offset = elf
                .program_header_offset
                .checked_add(relative_offset)
                .ok_or(EFI_LOAD_ERROR)?;

            let mut segment_bytes = [0u8; 56];

            read_exact_at(file, offset, &mut segment_bytes)?;

            let segment = ProgramHeader::parse(&segment_bytes).map_err(|_| EFI_LOAD_ERROR)?;

            if segment.segment_type == PT_LOAD {
                loadable_segments += 1;

                if segment.contains_executable_entry(elf.entry) {
                    entry_valid = true;
                }
            }
        }
        // 3. Un executable doit comporter au moins un
        // segment chargeable, et son point d'entree
        // doit appartenir a un segment executable.
        if loadable_segments == 0 || !entry_valid {
            return Err(EFI_LOAD_ERROR);
        }

        Ok(())
    })();
    // Fermer les handles, meme en cas d'echec du parseur.
    let file_close_status = unsafe { ((*file).close)(file) };

    let root_close_status = unsafe { ((*root).close)(root) };

    result?;

    if file_close_status != EFI_SUCCESS {
        return Err(file_close_status);
    }

    if root_close_status != EFI_SUCCESS {
        return Err(root_close_status);
    }

    Ok(())
}

fn read_exact_at(file: *mut FileProtocol, offset: u64, buffer: &mut [u8]) -> Result<(), EfiStatus> {
    if file.is_null() {
        return Err(EFI_INVALID_PARAMETER);
    }
    // Placer le curseur de lecture
    let status = unsafe { ((*file).set_position)(file, offset) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let mut total_read = 0usize;

    while total_read < buffer.len() {
        let remaining = buffer.len() - total_read;
        let mut bytes_read = remaining;

        let destination = unsafe { buffer.as_mut_ptr().add(total_read) };

        let status = unsafe { ((*file).read)(file, &mut bytes_read, destination.cast()) };

        if status != EFI_SUCCESS {
            return Err(status);
        }
        // Une lecture de zero octet signifie que nous
        // avons atteint la fin du fichier
        if bytes_read == 0 || bytes_read > remaining {
            return Err(EFI_LOAD_ERROR);
        }

        total_read += bytes_read;
    }

    Ok(())
}
