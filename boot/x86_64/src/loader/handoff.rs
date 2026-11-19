use core::hint::black_box;

use northstar_boot_protocol::{
    BOOT_INFO_MAGIC, BOOT_INFO_VIRTUAL_BASE, BootInfo, KERNEL_STACK_ALIGNEMENT,
};

use super::{EFI_LOAD_ERROR, boot_info::BootInfoAllocation, mapping::MappingReport};

use crate::uefi::types::EfiStatus;

#[inline(never)]
unsafe extern "sysv64" fn probe_entry(boot_info: *const BootInfo) -> u64 {
    if boot_info.is_null() || !boot_info.is_aligned() {
        return 0;
    }
    // SAFETY:
    // le pointeur doit designer une structure BootInfo
    // initialisee et accessible dans le mapping courant.
    let info = unsafe { &*boot_info };

    if !info.validate() {
        return 0;
    }

    info.magic
}

pub(super) fn verify_entry_abi(
    mapping: &MappingReport,
    boot_info: &BootInfoAllocation,
    boot_info_virtual: u64,
) -> Result<(), EfiStatus> {
    if boot_info_virtual != BOOT_INFO_VIRTUAL_BASE
        || mapping.entry_virtual == 0
        || !mapping
            .stack_top_virtual
            .is_multiple_of(KERNEL_STACK_ALIGNEMENT)
        || boot_info.physical_base == 0
    {
        return Err(EFI_LOAD_ERROR);
    }

    let address = usize::try_from(boot_info.physical_base).map_err(|_| EFI_LOAD_ERROR)?;

    let pointer = address as *const BootInfo;
    // Forcer un appel de test avec la convention
    // System V AMD64 depuis notre bootloader UEFI
    let entry = black_box(probe_entry as unsafe extern "sysv64" fn(*const BootInfo) -> u64);
    // SAFETY:
    // BootInfo est alloue, initialise et conserve
    // dans le mapping actif du firmware.
    let magic = unsafe { entry(pointer) };

    if magic != BOOT_INFO_MAGIC {
        return Err(EFI_LOAD_ERROR);
    }

    Ok(())
}
