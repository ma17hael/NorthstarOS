use core::ptr;

use super::EFI_LOAD_ERROR;
use crate::uefi::services::{ALLOCATE_ANY_PAGES, BootServices, EFI_LOADER_DATA};
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

const PAGE_SIZE: usize = 4096;
const MAX_MAP_PAGES: usize = 64;
const EXTRA_DESCRIPTORS: usize = 16;
// EFI_BUFFER_TOO_SMALL = EFIERR(5)
const EFI_BUFFER_TOO_SMALL: EfiStatus = (1usize << (usize::BITS - 1)) | 5;

pub(super) const MEMORY_MAP_VIRTUAL_BASE: u64 = 0xFFFF_8000_0004_0000;

pub(super) struct ReservedMemoryMap {
    pub physical_base: u64,
    pub pages: usize,
    pub capacity_bytes: usize,
}

pub(super) struct MemoryMapSnapshot {
    pub size_bytes: usize,
    pub descriptor_size: usize,
    pub descriptor_version: u32,
    pub map_key: usize,
}

pub(super) fn reserve_memory_map(services: &BootServices) -> Result<ReservedMemoryMap, EfiStatus> {
    let mut required = 0usize;
    let mut map_key = 0usize;
    let mut descriptor_size = 0usize;
    let mut descriptor_version = 0u32;
    // Premier appel: demander la taille necessaire.
    let status = unsafe {
        (services.get_memory_map)(
            &mut required,
            ptr::null_mut(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };

    if status != EFI_BUFFER_TOO_SMALL {
        return Err(if status == EFI_SUCCESS {
            EFI_LOAD_ERROR
        } else {
            status
        });
    }
    // Taille minimal du descripteur UEFI standard.
    if descriptor_size < 40 || required == 0 {
        return Err(EFI_LOAD_ERROR);
    }
    // Les allocations suivantes peuvent augmenter
    // le nombre de descripteurs.
    let extra = descriptor_size
        .checked_mul(EXTRA_DESCRIPTORS)
        .ok_or(EFI_LOAD_ERROR)?;

    let requested_capacity = required
        .checked_add(extra)
        .and_then(|value| value.checked_add(PAGE_SIZE))
        .ok_or(EFI_LOAD_ERROR)?;

    let pages = requested_capacity.div_ceil(PAGE_SIZE);

    if pages == 0 || pages > MAX_MAP_PAGES {
        return Err(EFI_LOAD_ERROR);
    }

    let capacity_bytes = pages.checked_mul(PAGE_SIZE).ok_or(EFI_LOAD_ERROR)?;

    let mut physical_base = 0u64;

    let status = unsafe {
        (services.allocate_pages)(
            ALLOCATE_ANY_PAGES,
            EFI_LOADER_DATA,
            pages,
            &mut physical_base,
        )
    };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let result = (|| -> Result<ReservedMemoryMap, EfiStatus> {
        if physical_base == 0 || !physical_base.is_multiple_of(PAGE_SIZE as u64) {
            return Err(EFI_LOAD_ERROR);
        }

        let address = usize::try_from(physical_base).map_err(|_| EFI_LOAD_ERROR)?;

        address.checked_add(capacity_bytes).ok_or(EFI_LOAD_ERROR)?;
        // Prototype QEMU/EDK II : les pages physiques
        // sont accessibles dans le mapping firmware.
        unsafe {
            ptr::write_bytes(address as *mut u8, 0, capacity_bytes);
        }

        Ok(ReservedMemoryMap {
            physical_base,
            pages,
            capacity_bytes,
        })
    })();

    if result.is_err() {
        let free_status = unsafe { (services.free_pages)(physical_base, pages) };

        if free_status != EFI_SUCCESS {
            return Err(EFI_LOAD_ERROR);
        }
    }

    result
}

pub(super) fn capture_memory_map(
    services: &BootServices,
    reserved: &ReservedMemoryMap,
) -> Result<MemoryMapSnapshot, EfiStatus> {
    let address = usize::try_from(reserved.physical_base).map_err(|_| EFI_LOAD_ERROR)?;

    let mut size_bytes = reserved.capacity_bytes;
    let mut map_key = 0usize;
    let mut descriptor_size = 0usize;
    let mut descriptor_version = 0u32;
    // Aucune allocation n'est effectuee ici.
    // Le buffer est déjà reserve.
    let status = unsafe {
        (services.get_memory_map)(
            &mut size_bytes,
            address as *mut _,
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };

    if status != EFI_SUCCESS {
        return Err(EFI_LOAD_ERROR);
    }

    if descriptor_size < 40
        || size_bytes == 0
        || size_bytes > reserved.capacity_bytes
        || !size_bytes.is_multiple_of(descriptor_size)
    {
        return Err(EFI_LOAD_ERROR);
    }

    Ok(MemoryMapSnapshot {
        size_bytes,
        descriptor_size,
        descriptor_version,
        map_key,
    })
}

pub(super) fn release_memory_map(
    reserved: ReservedMemoryMap,
    services: &BootServices,
) -> Result<(), EfiStatus> {
    let status = unsafe { (services.free_pages)(reserved.physical_base, reserved.pages) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    Ok(())
}
