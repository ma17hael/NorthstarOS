use core::ffi::c_void;
use core::ptr::null_mut;

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
    // Un en-tete ELF64 occupe 64 octets.
    let mut header = [0u8; 64];
    let mut bytes_read = header.len();

    let status = unsafe { ((*file).read)(file, &mut bytes_read, header.as_mut_ptr().cast()) };
    // Fermer les deux handles, meme en cas d'erreur
    unsafe {
        ((*file).close)(file);
        ((*root).close)(root);
    }

    if status != EFI_SUCCESS || bytes_read != header.len() {
        return Err(EFI_LOAD_ERROR);
    }
    // Signature ELF.
    if &header[0..4] != b"\x7FELF" {
        return Err(EFI_LOAD_ERROR);
    }
    // ELF64 + Little Endian + version courante.
    if header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(EFI_LOAD_ERROR);
    }
    // e_machine = 0x003E = AMD64.
    let machine = u16::from_le_bytes([header[18], header[19]]);

    if machine != 0x003E {
        return Err(EFI_LOAD_ERROR);
    }

    Ok(())
}
