use core::slice;

use crate::uefi::services::{ALLOCATE_ANY_PAGES, EFI_LOADER_DATA};
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_INVALID_PARAMETER, EFI_SUCCESS, EfiStatus};

const EFI_LOAD_ERROR: EfiStatus = (1usize << (usize::BITS - 1)) | 1;

const PAGE_SIZE: u64 = 4096;
const ENTRIES_PER_TABLE: usize = 512;
const ALLOCATED_PAGES: usize = 5;
// Masque sur les adresses physiques sur 52 bits.
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
// Indicateurs des entrees x86-64
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
// Addresse virtuelle de test : higher half
const TEST_VIRTUAL_ADDRESS: u64 = 0xFFFF_8000_0000_0000;

pub struct PagingTestReport {
    pub pml4_physical: u64,
    pub virtual_address: u64,
    pub target_physical: u64,
}

fn table_index(address: u64, shift: u32) -> usize {
    ((address >> shift) & 0x1FF) as usize
}

pub fn test_mapping(system_table: *mut SystemTable) -> Result<PagingTestReport, EfiStatus> {
    let table = unsafe { system_table.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;

    let services = unsafe { table.boot_services.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;
    // Reserver quatres tables et une page de test
    let mut physical_base = 0u64;

    let status = unsafe {
        (services.allocate_pages)(
            ALLOCATE_ANY_PAGES,
            EFI_LOADER_DATA,
            ALLOCATED_PAGES,
            &mut physical_base,
        )
    };

    if status != EFI_SUCCESS {
        return Err(status);
    }
    // Garder l'allocation active pendant le test
    let result = (|| -> Result<PagingTestReport, EfiStatus> {
        if physical_base == 0 || physical_base % PAGE_SIZE != 0 {
            return Err(EFI_LOAD_ERROR);
        }

        let pdpt_base = physical_base.checked_add(PAGE_SIZE).ok_or(EFI_LOAD_ERROR)?;

        let pd_base = physical_base
            .checked_add(PAGE_SIZE * 2)
            .ok_or(EFI_LOAD_ERROR)?;

        let pt_base = physical_base
            .checked_add(PAGE_SIZE * 3)
            .ok_or(EFI_LOAD_ERROR)?;

        let target_base = physical_base
            .checked_add(PAGE_SIZE * 4)
            .ok_or(EFI_LOAD_ERROR)?;
        // Verifier que nos adresses peuvent être
        // encodees dans les entrees de pagination.
        if target_base & !ADDRESS_MASK != 0 {
            return Err(EFI_LOAD_ERROR);
        }

        let address = usize::try_from(physical_base).map_err(|_| EFI_LOAD_ERROR)?;
        // Hypothese limite a EDK II/QEMU :
        // ces pages physiques sont accessibles
        // via le mapping courant du firmware.
        //
        // Les tables restent INACTIVES.
        let entries = unsafe {
            slice::from_raw_parts_mut(address as *mut u64, ALLOCATED_PAGES * ENTRIES_PER_TABLE)
        };
        // Initialiser les cinq pages.
        entries.fill(0);
        // Indices dans les quatres niveaux.
        let pml4_index = table_index(TEST_VIRTUAL_ADDRESS, 39);
        let pdpt_index = table_index(TEST_VIRTUAL_ADDRESS, 30);
        let pd_index = table_index(TEST_VIRTUAL_ADDRESS, 21);
        let pt_index = table_index(TEST_VIRTUAL_ADDRESS, 12);

        let flags = PRESENT | WRITABLE;
        // PML4 -> PDPT
        entries[pml4_index] = pdpt_base | flags;
        // PDPT -> PD
        entries[ENTRIES_PER_TABLE + pdpt_index] = pd_base | flags;
        // PD -> PT
        entries[ENTRIES_PER_TABLE * 2 + pd_index] = pt_base | flags;
        // PT -> page physique de test
        entries[ENTRIES_PER_TABLE * 3 + pt_index] = target_base | flags;
        // Verifier chaque lien de la hierarchie
        let valid = entries[pml4_index] == (pdpt_base | flags)
            && entries[ENTRIES_PER_TABLE + pdpt_index] == (pd_base | flags)
            && entries[ENTRIES_PER_TABLE * 2 + pd_index] == (pt_base | flags)
            && entries[ENTRIES_PER_TABLE * 3 + pt_index] == (target_base | flags);

        if !valid {
            return Err(EFI_LOAD_ERROR);
        }

        Ok(PagingTestReport {
            pml4_physical: physical_base,
            virtual_address: TEST_VIRTUAL_ADDRESS,
            target_physical: target_base,
        })
    })();
    // Liberer l'allocation meme si le test echoue
    let free_status = unsafe { (services.free_pages)(physical_base, ALLOCATED_PAGES) };

    if free_status != EFI_SUCCESS {
        return Err(free_status);
    }

    result
}
