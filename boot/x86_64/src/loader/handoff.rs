use core::arch::asm;
use core::hint::black_box;

use northstar_boot_protocol::{
    BOOT_INFO_MAGIC, BOOT_INFO_VIRTUAL_BASE, BootInfo, KERNEL_STACK_ALIGNEMENT,
};

use super::boot_info;
use super::memory_map::{self, ReservedMemoryMap};
use super::{EFI_LOAD_ERROR, boot_info::BootInfoAllocation, mapping::MappingReport};

use crate::serial;
use crate::uefi::EfiHandle;
use crate::uefi::services::BootServices;
use crate::uefi::types::{EFI_INVALID_PARAMETER, EFI_SUCCESS, EfiStatus};

const MAX_EXIT_ATTEMPTS: usize = 4;

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

fn halt_forever() -> ! {
    // SAFETY:
    // Le bootloader s'execute en Ring 0.
    // Cette fonction ne retourne jamais.
    unsafe {
        asm!("cli", "2:", "hlt", "jmp 2b", options(noreturn, nostack));
    }
}

fn serial_write_hex(value: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut buffer = [b'0'; 18];

    buffer[1] = b'x';

    for index in 0..16 {
        let shift = (15 - index) * 4;
        let digit = ((value >> shift) & 0xF) as usize;

        buffer[index + 2] = HEX[digit];
    }

    if let Ok(text) = core::str::from_utf8(&buffer) {
        serial::write_ascii(text);
    }
}

fn fatal_handoff(message: &str, status: EfiStatus) -> ! {
    serial::write_ascii(message);
    serial_write_hex(status as u64);
    serial::write_ascii("\n");

    halt_forever()
}

pub(super) fn exit_boot_services_test(
    image_handle: EfiHandle,
    services: &BootServices,
    allocation: &mut BootInfoAllocation,
    reserved: &ReservedMemoryMap,
) -> ! {
    serial::write_ascii("[HANDOFF] Entering final UEFI handoff\n");

    let exit_boot_services = services.exit_boot_services;

    for _ in 0..MAX_EXIT_ATTEMPTS {
        // Capturer la carte sans nouvelle allocation.
        let snapshot = match memory_map::capture_memory_map(services, reserved) {
            Ok(snapshot) => snapshot,
            Err(status) => fatal_handoff("[FATAL] Final memory map failed: ", status),
        };
        // Aucun appel UEFI entre GetMemoryMap
        // et ExitBootServices.
        let status = unsafe { exit_boot_services(image_handle, snapshot.map_key) };

        if status == EFI_SUCCESS {
            serial::write_ascii("[HANDOFF] ExitBootServices successful\n");

            // Ne plus utiliser services à partir d'ici.
            if let Err(status) =
                boot_info::publish_final_memory_map(allocation, reserved, &snapshot)
            {
                fatal_handoff("[FATAL] BootInfo publication failed: ", status);
            }

            serial::write_ascii(
                "[HANDOFF] Final memory map published\n\
            [HANDOFF] BootInfo memory map valid\n",
            );

            serial::write_ascii("[HANDOFF] Memory map address: ");
            serial_write_hex(allocation.value.memory_map.virtual_base);

            serial::write_ascii(
                "\n[HANDOFF] UEFI handoff test successful\n\
            [HANDOFF] CPU halted before CR3 switch\n",
            );

            halt_forever();
        }

        if status != EFI_INVALID_PARAMETER {
            fatal_handoff("[FATAL] ExitBootServices failed: ", status)
        }

        serial::write_ascii("[HANDOFF] MapKey rejected, retrying\n");
    }
    fatal_handoff(
        "[FATAL] ExitBootServices retry limit reached: ",
        EFI_INVALID_PARAMETER,
    );
}
