use crate::uefi::services::{ALLOCATE_ANY_PAGES, EFI_LOADER_DATA};
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_INVALID_PARAMETER, EFI_SUCCESS, EfiStatus};

const PAGE_SIZE: u64 = 4096;
const TEST_PAGES: usize = 4;

pub fn test_allocation(system_table: *mut SystemTable) -> Result<u64, EfiStatus> {
    // Recuperer la table systeme UEFI.
    let table = unsafe { system_table.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;
    // Recuperer les services de demarrage.
    let services = unsafe { table.boot_services.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;
    // Adresse physique retourne le firmware.
    let mut address: u64 = 0;
    // 1. Reserver quatre pages physiques.
    let status = unsafe {
        (services.allocate_pages)(
            ALLOCATE_ANY_PAGES,
            EFI_LOADER_DATA,
            TEST_PAGES,
            &mut address,
        )
    };

    if status != EFI_SUCCESS {
        return Err(status);
    }
    // 2. Verifier l'alignement de l'adresse
    let aligned = address % PAGE_SIZE == 0;
    // 3. Liberer les pages, meme si l'alignement
    // obtenu etait incorrect.
    let free_status = unsafe { (services.free_pages)(address, TEST_PAGES) };

    if free_status != EFI_SUCCESS {
        return Err(free_status);
    }

    if !aligned {
        return Err(EFI_INVALID_PARAMETER);
    }
    // L'adresse est conservee uniquement
    // pour le diagnostic.
    // Les pages ont déjà ete liberees.
    Ok(address)
}
