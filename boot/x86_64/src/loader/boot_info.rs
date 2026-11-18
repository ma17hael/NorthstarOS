use core::mem::size_of;
use core::ptr;

use northstar_boot_protocol::{BootInfo, KernelInfo, PagingInfo, StackInfo};

use super::{
    EFI_LOAD_ERROR,
    mapping::MappingReport,
    stack::{KernelStack, STACK_GUARD_VIRTUAL},
    stage::StageReport,
};

use crate::uefi::services::{ALLOCATE_ANY_PAGES, BootServices, EFI_LOADER_DATA};
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

const PAGE_SIZE: u64 = 4096;
const BOOT_INFO_PAGES: usize = 1;

pub(super) struct BootInfoAllocation {
    pub physical_base: u64,
    pub value: BootInfo,
}

pub(super) fn allocate_boot_info(
    services: &BootServices,
    kernel: &StageReport,
    mapping: &MappingReport,
    stack: &KernelStack,
) -> Result<BootInfoAllocation, EfiStatus> {
    let kernel_size = (kernel.pages as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(EFI_LOAD_ERROR)?;

    let stack_size = (stack.pages as u64)
        .checked_mul(PAGE_SIZE)
        .ok_or(EFI_LOAD_ERROR)?;

    if size_of::<BootInfo>() > PAGE_SIZE as usize
        || kernel.physical_base == 0
        || stack.physical_base == 0
        || mapping.entry_virtual
            != mapping
                .virtual_base
                .checked_add(kernel.entry_offset)
                .ok_or(EFI_LOAD_ERROR)?
        || mapping.stack_top_virtual != stack.top_virtual
    {
        return Err(EFI_LOAD_ERROR);
    }

    let value = BootInfo::new(
        KernelInfo {
            physical_base: kernel.physical_base,
            virtual_base: mapping.virtual_base,
            image_size: kernel_size,
            entry_virtual: mapping.virtual_base,
        },
        StackInfo {
            physical_base: stack.physical_base,
            virtual_base: stack.virtual_base,
            size: stack_size,
            top_virtual: stack.top_virtual,
            guard_virtual: STACK_GUARD_VIRTUAL,
        },
        PagingInfo {
            pml4_physical: mapping.pml4_physical,
        },
    );

    if !value.validate() {
        return Err(EFI_LOAD_ERROR);
    }

    let mut physical_base = 0u64;

    let status = unsafe {
        (services.allocate_pages)(
            ALLOCATE_ANY_PAGES,
            EFI_LOADER_DATA,
            BOOT_INFO_PAGES,
            &mut physical_base,
        )
    };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let result = (|| -> Result<BootInfoAllocation, EfiStatus> {
        if physical_base == 0 || !physical_base.is_multiple_of(PAGE_SIZE) {
            return Err(EFI_LOAD_ERROR);
        }

        let address = usize::try_from(physical_base).map_err(|_| EFI_LOAD_ERROR)?;
        // Prototype QEMU/EDK II :
        // La page physique est accessible a travers
        // le mapping courant du firmware.
        //
        // Cette page n'est pas encore mappee dans
        // l'espace virtuel final du noyau
        let destination = address as *mut BootInfo;

        unsafe {
            ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize);
            ptr::write(destination, value);
        };
        // Verifier le contenu reel de la page.
        let stored = unsafe { ptr::read(destination) };

        if stored != value || !stored.validate() {
            return Err(EFI_LOAD_ERROR);
        }

        Ok(BootInfoAllocation {
            physical_base,
            value,
        })
    })();

    if result.is_err() {
        let free_status = unsafe { (services.free_pages)(physical_base, BOOT_INFO_PAGES) };

        if free_status != EFI_SUCCESS {
            return Err(free_status);
        }
    }

    result
}

pub(super) fn release_boot_info(
    allocation: BootInfoAllocation,
    services: &BootServices,
) -> Result<(), EfiStatus> {
    let status = unsafe { (services.free_pages)(allocation.physical_base, BOOT_INFO_PAGES) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    Ok(())
}
