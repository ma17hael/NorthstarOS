use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::{null_mut, read_unaligned};

use crate::uefi::services::EFI_LOADER_DATA;
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_INVALID_PARAMETER, EFI_SUCCESS, EfiStatus};

const PAGE_SIZE: u64 = 4096;
const INITIAL_CAPACITY: usize = 16 * 1024;
const EXTRA_CAPACITY: usize = 4096;
const MAX_ATTEMPTS: usize = 5;

const EFI_ERROR_BIT: usize = 1usize << (usize::BITS - 1);
const EFI_LOAD_ERROR: EfiStatus = EFI_ERROR_BIT | 1;
const EFI_BUFFER_TOO_SMALL: EfiStatus = EFI_ERROR_BIT | 5;

const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;

const EFI_BOOT_SERVICES_CODE: u32 = 3;
const EFI_BOOT_SERVICES_DATA: u32 = 4;
const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;
const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;
const EFI_ACPI_MEMORY_NVS: u32 = 10;

#[repr(C)]
#[allow(dead_code)]
struct MemoryDescriptor {
    memory_type: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

#[derive(Debug, Default)]
pub struct MemoryMapSummary {
    pub descriptor_count: usize,
    pub descriptor_size: usize,
    pub conventional_pages: u64,
    pub boot_services_pages: u64,
    pub runtime_pages: u64,
    pub acpi_pages: u64,
}

pub fn inspect_memory_map(system_table: *mut SystemTable) -> Result<MemoryMapSummary, EfiStatus> {
    let table = unsafe { system_table.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;

    let services = unsafe { table.boot_services.as_ref() }.ok_or(EFI_INVALID_PARAMETER)?;

    let mut capacity = INITIAL_CAPACITY;

    for _attempt in 0..MAX_ATTEMPTS {
        let mut buffer: *mut c_void = null_mut();
        // Reserver le tampon avec le gestionnaire UEFI.
        let status = unsafe { (services.allocate_pool)(EFI_LOADER_DATA, capacity, &mut buffer) };

        if status != EFI_SUCCESS {
            return Err(status);
        }

        if buffer.is_null() {
            return Err(EFI_LOAD_ERROR);
        }

        let mut map_size = capacity;
        let mut map_key = 0usize;
        let mut descriptor_size = 0usize;
        let mut descriptor_version = 0u32;

        let status = unsafe {
            (services.get_memory_map)(
                &mut map_size,
                buffer,
                &mut map_key,
                &mut descriptor_size,
                &mut descriptor_version,
            )
        };

        if status == EFI_BUFFER_TOO_SMALL {
            // Liberer l'ancien tampon avant de recommencer.
            let free_status = unsafe { (services.free_pool)(buffer) };

            if free_status != EFI_SUCCESS {
                return Err(free_status);
            }

            capacity = map_size
                .max(capacity)
                .checked_add(EXTRA_CAPACITY)
                .ok_or(EFI_LOAD_ERROR)?;

            continue;
        }
        // Analyser les donnees avant de liberer le tampon.
        let result = if status == EFI_SUCCESS {
            summarize_map(
                buffer.cast::<u8>(),
                map_size,
                capacity,
                descriptor_size,
                descriptor_version,
            )
        } else {
            Err(status)
        };

        let free_status = unsafe { (services.free_pool)(buffer) };

        if free_status != EFI_SUCCESS {
            return Err(free_status);
        }
        // La cle map_key est volontairement abandonnee :
        // FreePool peut modifier la carte memoire.
        let _ = map_key;

        return result;
    }

    Err(EFI_BUFFER_TOO_SMALL)
}

fn summarize_map(
    buffer: *const u8,
    map_size: usize,
    capacity: usize,
    descriptor_size: usize,
    descriptor_version: u32,
) -> Result<MemoryMapSummary, EfiStatus> {
    if descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION {
        return Err(EFI_LOAD_ERROR);
    }

    if descriptor_size < size_of::<MemoryDescriptor>()
        || map_size == 0
        || map_size > capacity
        || map_size % descriptor_size != 0
    {
        return Err(EFI_LOAD_ERROR);
    }

    let descriptor_count = map_size / descriptor_size;

    let mut summary = MemoryMapSummary {
        descriptor_count,
        descriptor_size,
        ..Default::default()
    };

    for index in 0..descriptor_count {
        let offset = index.checked_mul(descriptor_size).ok_or(EFI_LOAD_ERROR)?;

        let address = unsafe { buffer.add(offset) };
        // Un descripteur peut etre suivi d'octets
        // supplementaires. Nous lisons uniquement
        // les champs standards des 40 premiers octets.
        let descriptor = unsafe { read_unaligned(address.cast::<MemoryDescriptor>()) };

        let region_size = descriptor
            .number_of_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(EFI_LOAD_ERROR)?;

        descriptor
            .physical_start
            .checked_add(region_size)
            .ok_or(EFI_LOAD_ERROR)?;

        let destination = match descriptor.memory_type {
            EFI_CONVENTIONAL_MEMORY => &mut summary.conventional_pages,

            EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA => &mut summary.boot_services_pages,

            EFI_RUNTIME_SERVICES_CODE | EFI_RUNTIME_SERVICES_DATA => &mut summary.runtime_pages,

            EFI_ACPI_RECLAIM_MEMORY | EFI_ACPI_MEMORY_NVS => &mut summary.acpi_pages,

            _ => continue,
        };

        *destination = destination
            .checked_add(descriptor.number_of_pages)
            .ok_or(EFI_LOAD_ERROR)?;
    }

    Ok(summary)
}
