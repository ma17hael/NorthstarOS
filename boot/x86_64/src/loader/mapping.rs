use core::slice;

use super::{EFI_LOAD_ERROR, read_exact_at, stage::StageReport};

use crate::elf::header::ElfHeader;
use crate::elf::program::{PROGRAM_HEADER_SIZE, PT_LOAD, ProgramHeader};
use crate::uefi::file::FileProtocol;
use crate::uefi::services::{ALLOCATE_ANY_PAGES, BootServices, EFI_LOADER_DATA};
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

const PAGE_SIZE: u64 = 4096;
const TABLE_ENTRIES: usize = 512;
const TABLE_PAGES: usize = 4;
const MAX_KERNEL_PAGES: usize = 512;

const KERNEL_VIRTUAL_BASE: u64 = 0xFFFF_8000_0000_0000;

const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const NO_EXECUTE: u64 = 1 << 63;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const PAGE_PRESENT: u8 = 1;
const PAGE_WRITABLE: u8 = 2;
const PAGE_EXECUTABLE: u8 = 4;

pub(super) struct MappingReport {
    pub pml4_physical: u64,
    pub virtual_base: u64,
    pub entry_virtual: u64,
    pub mapped_pages: usize,
    pub writable_pages: usize,
    pub executable_pages: usize,
}

pub(super) fn build_kernel_mapping(
    file: *mut FileProtocol,
    services: &BootServices,
    elf: &ElfHeader,
    kernel: &StageReport,
) -> Result<MappingReport, EfiStatus> {
    // Le prototype accepte une image situee dans
    // une seule region virtuelle de 2 Mio
    if kernel.pages == 0 || kernel.pages > MAX_KERNEL_PAGES {
        return Err(EFI_LOAD_ERROR);
    }

    let image_size = (kernel.pages as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(EFI_LOAD_ERROR)?;

    let virtual_end = KERNEL_VIRTUAL_BASE
        .checked_add(image_size - 1)
        .ok_or(EFI_LOAD_ERROR)?;

    if (KERNEL_VIRTUAL_BASE >> 21) != (virtual_end >> 21) {
        return Err(EFI_LOAD_ERROR);
    }
    // Permissions attendues, une entree par page.
    // Les pages non couvertes par PT_LOAD restent absentes.
    let mut permissions = [0u8; MAX_KERNEL_PAGES];

    for index in 0..usize::from(elf.program_header_count) {
        let relative = (index as u64)
            .checked_mul(PROGRAM_HEADER_SIZE as u64)
            .ok_or(EFI_LOAD_ERROR)?;

        let offset = elf
            .program_header_offset
            .checked_add(relative)
            .ok_or(EFI_LOAD_ERROR)?;

        let mut bytes = [0u8; PROGRAM_HEADER_SIZE];
        read_exact_at(file, offset, &mut bytes)?;

        let segment = ProgramHeader::parse(&bytes).map_err(|_| EFI_LOAD_ERROR)?;

        if segment.segment_type != PT_LOAD || segment.memory_size == 0 {
            continue;
        }
        // p_flags occupe les octets 4..8
        // de l'en-tête de programme ELF64.
        let flags = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        if flags & !(PF_R | PF_W | PF_X) != 0 {
            return Err(EFI_LOAD_ERROR);
        }

        let start = segment
            .virtual_address
            .checked_sub(kernel.virtual_start)
            .ok_or(EFI_LOAD_ERROR)?;

        let end = start
            .checked_add(segment.memory_size)
            .ok_or(EFI_LOAD_ERROR)?;

        if end == 0 || end > image_size {
            return Err(EFI_LOAD_ERROR);
        }

        let first_page = (start / PAGE_SIZE) as usize;
        let last_page = ((end - 1) / PAGE_SIZE) as usize;

        for permission in &mut permissions[first_page..=last_page] {
            *permission |= PAGE_PRESENT;

            if flags & PF_W != 0 {
                *permission |= PAGE_WRITABLE;
            }

            if flags & PF_X != 0 {
                *permission |= PAGE_EXECUTABLE;
            }
        }
    }
    // Refuser une page simultanement inscriptible
    // et executable. Deux segments peuvent partager
    // une page sans se chevaucher en octets.
    for permission in &permissions[..kernel.pages] {
        if permission & PAGE_WRITABLE != 0 && permission & PAGE_EXECUTABLE != 0 {
            return Err(EFI_LOAD_ERROR);
        }
    }

    let entry_page = (kernel.entry_offset / PAGE_SIZE) as usize;

    if entry_page >= kernel.pages || permissions[entry_page] & PAGE_EXECUTABLE == 0 {
        return Err(EFI_LOAD_ERROR);
    }

    let entry_virtual = KERNEL_VIRTUAL_BASE
        .checked_add(kernel.entry_offset)
        .ok_or(EFI_LOAD_ERROR)?;
    // Reserver quatre tables :
    // PML4, PDPT, PD et PT.
    let mut tables_physical = 0u64;

    let status = unsafe {
        (services.allocate_pages)(
            ALLOCATE_ANY_PAGES,
            EFI_LOADER_DATA,
            TABLE_PAGES,
            &mut tables_physical,
        )
    };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let result = (|| -> Result<MappingReport, EfiStatus> {
        if tables_physical == 0 || !tables_physical.is_multiple_of(PAGE_SIZE) {
            return Err(EFI_LOAD_ERROR);
        }

        let pdpt = tables_physical
            .checked_add(PAGE_SIZE)
            .ok_or(EFI_LOAD_ERROR)?;

        let pd = tables_physical
            .checked_add(2 * PAGE_SIZE)
            .ok_or(EFI_LOAD_ERROR)?;

        let pt = tables_physical
            .checked_add(3 * PAGE_SIZE)
            .ok_or(EFI_LOAD_ERROR)?;

        for address in [tables_physical, pdpt, pd, pt] {
            if address & !ADDRESS_MASK != 0 {
                return Err(EFI_LOAD_ERROR);
            }
        }

        let address = usize::try_from(tables_physical).map_err(|_| EFI_LOAD_ERROR)?;
        // SAFETY:
        // Notre prototype sous EDK II/QEMU utilise
        // le mapping physique accessible du firmware.
        // Ces tables ne seront pas actives dans CR3.
        let entries =
            unsafe { slice::from_raw_parts_mut(address as *mut u64, TABLE_PAGES * TABLE_ENTRIES) };

        entries.fill(0);

        let pml4_index = ((KERNEL_VIRTUAL_BASE >> 39) & 0x1FF) as usize;
        let pdpt_index = ((KERNEL_VIRTUAL_BASE >> 30) & 0x1FF) as usize;
        let pd_index = ((KERNEL_VIRTUAL_BASE >> 21) & 0x1FF) as usize;
        let pt_index = ((KERNEL_VIRTUAL_BASE >> 12) & 0x1FF) as usize;

        if pt_index + kernel.pages > TABLE_ENTRIES {
            return Err(EFI_LOAD_ERROR);
        }

        let table_flags = PRESENT | WRITABLE;

        entries[pml4_index] = pdpt | table_flags;
        entries[TABLE_ENTRIES + pdpt_index] = pd | table_flags;
        entries[2 * TABLE_ENTRIES + pd_index] = pt | table_flags;

        let mut mapped_pages = 0usize;
        let mut writable_pages = 0usize;
        let mut executable_pages = 0usize;
        // Mapper les pages du noyau.
        for (index, permission) in permissions[..kernel.pages].iter().enumerate() {
            if permission & PAGE_PRESENT == 0 {
                continue;
            }

            let physical = kernel
                .physical_base
                .checked_add(index as u64 * PAGE_SIZE)
                .ok_or(EFI_LOAD_ERROR)?;

            if physical & !ADDRESS_MASK != 0 {
                return Err(EFI_LOAD_ERROR);
            }

            let mut flags = PRESENT;

            if permission & PAGE_WRITABLE != 0 {
                flags |= WRITABLE;
                writable_pages += 1;
            }

            if permission & PAGE_EXECUTABLE == 0 {
                flags |= NO_EXECUTE;
            } else {
                executable_pages += 1;
            }

            entries[3 * TABLE_ENTRIES + pt_index + index] = physical | flags;

            mapped_pages += 1;
        }
        // Verifier les liens entre les quatres tables
        if entries[pml4_index] != (pdpt | table_flags)
            || entries[TABLE_ENTRIES + pdpt_index] != (pd | table_flags)
            || entries[2 * TABLE_ENTRIES + pd_index] != (pt | table_flags)
        {
            return Err(EFI_LOAD_ERROR);
        }
        //Verifier chaque PTE et les pages absentes.
        for (index, permission) in permissions[..kernel.pages].iter().enumerate() {
            let actual = entries[3 * TABLE_ENTRIES + pt_index + index];

            if permission & PAGE_PRESENT == 0 {
                if actual != 0 {
                    return Err(EFI_LOAD_ERROR);
                }
                continue;
            }

            let physical = kernel
                .physical_base
                .checked_add(index as u64 * PAGE_SIZE)
                .ok_or(EFI_LOAD_ERROR)?;

            let mut expected = physical | PRESENT;

            if permission & PAGE_WRITABLE != 0 {
                expected |= WRITABLE;
            }

            if permission & PAGE_EXECUTABLE == 0 {
                expected |= NO_EXECUTE;
            }

            if actual != expected {
                return Err(EFI_LOAD_ERROR);
            }
        }

        Ok(MappingReport {
            pml4_physical: tables_physical,
            virtual_base: KERNEL_VIRTUAL_BASE,
            entry_virtual,
            mapped_pages,
            writable_pages,
            executable_pages,
        })
    })();
    // En cas de succes, conserver les tables.
    // En cas d'echec, liberer leur allocation.
    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            let free_status = unsafe { (services.free_pages)(tables_physical, TABLE_PAGES) };

            if free_status != EFI_SUCCESS {
                return Err(free_status);
            }

            Err(error)
        }
    }
}

pub(super) fn release_kernel_mapping(
    mapping: MappingReport,
    services: &BootServices,
) -> Result<(), EfiStatus> {
    let status = unsafe { (services.free_pages)(mapping.pml4_physical, TABLE_PAGES) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    Ok(())
}
