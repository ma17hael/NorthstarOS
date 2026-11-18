use core::ptr;

use super::EFI_LOAD_ERROR;
use crate::uefi::services::{ALLOCATE_ANY_PAGES, BootServices, EFI_LOADER_DATA};
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

const PAGE_SIZE: u64 = 4096;

pub(super) const STACK_PAGES: usize = 8;
pub(super) const STACK_VIRTUAL_BASE: u64 = 0xFFFF_8000_0001_0000;
pub(super) const STACK_GUARD_VIRTUAL: u64 = STACK_VIRTUAL_BASE - PAGE_SIZE;

pub(super) struct KernelStack {
    pub physical_base: u64,
    pub pages: usize,
    pub virtual_base: u64,
    pub top_virtual: u64,
}

pub(super) fn allocate_stack(services: &BootServices) -> Result<KernelStack, EfiStatus> {
    let mut physical_base = 0u64;

    let status = unsafe {
        (services.allocate_pages)(
            ALLOCATE_ANY_PAGES,
            EFI_LOADER_DATA,
            STACK_PAGES,
            &mut physical_base,
        )
    };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let result = (|| -> Result<KernelStack, EfiStatus> {
        if physical_base == 0 || !physical_base.is_multiple_of(PAGE_SIZE) {
            return Err(EFI_LOAD_ERROR);
        }

        let stack_bytes = STACK_PAGES
            .checked_mul(PAGE_SIZE as usize)
            .ok_or(EFI_LOAD_ERROR)?;

        let address = usize::try_from(physical_base).map_err(|_| EFI_LOAD_ERROR)?;

        address.checked_add(stack_bytes).ok_or(EFI_LOAD_ERROR)?;
        // SAFETY:
        // Prototype EDK II/QEMU x86-64
        // Les pages allouees sont accessibles dans
        // le mapping courant du firmware
        unsafe {
            ptr::write_bytes(address as *mut u8, 0, stack_bytes);
        }

        let top_virtual = STACK_VIRTUAL_BASE
            .checked_add(stack_bytes as u64)
            .ok_or(EFI_LOAD_ERROR)?;

        if top_virtual % 16 != 0 {
            return Err(EFI_LOAD_ERROR);
        }

        Ok(KernelStack {
            physical_base,
            pages: STACK_PAGES,
            virtual_base: STACK_VIRTUAL_BASE,
            top_virtual,
        })
    })();

    if result.is_err() {
        let free_status = unsafe { (services.free_pages)(physical_base, STACK_PAGES) };

        if free_status != EFI_SUCCESS {
            return Err(free_status);
        }
    }

    result
}

pub(super) fn release_stack(stack: KernelStack, services: &BootServices) -> Result<(), EfiStatus> {
    let status = unsafe { (services.free_pages)(stack.physical_base, stack.pages) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    Ok(())
}
