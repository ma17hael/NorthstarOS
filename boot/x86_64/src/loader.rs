mod boot_info;
mod dynamic;
mod handoff;
mod mapping;
mod memory_map;
mod stack;
mod stage;

use core::ffi::c_void;
use core::ptr::null_mut;

use crate::arch::x86_64;
use crate::console::Console;
use crate::elf::{ElfHeader, PT_LOAD, ProgramHeader};
use crate::uefi::file::{
    FileProtocol, LOADED_IMAGE_GUID, LoadedImageProtocol, SIMPLE_FILE_SYSTEM_GUID,
    SimpleFileSystemProtocol,
};
use crate::uefi::services::BootServices;
use crate::uefi::table::SystemTable;
use crate::uefi::types::{EFI_INVALID_PARAMETER, EFI_SUCCESS, EfiHandle, EfiStatus};

const EFI_LOAD_ERROR: EfiStatus = (1usize << (usize::BITS - 1)) | 1;

const EFI_FILE_MODE_READ: u64 = 1;

pub(crate) struct PreparedKernel {
    kernel: stage::StageReport,
    mapping: mapping::MappingReport,
    stack: stack::KernelStack,
    boot_info: boot_info::BootInfoAllocation,
    memory_map: Option<memory_map::ReservedMemoryMap>,
}

impl PreparedKernel {
    // Liberation explicite avant ExitBootServices.
    // Les deux allocations doivent être traitees,
    // meme si la premiere libération echoue.
    pub(crate) fn release(self, services: &BootServices) -> Result<(), EfiStatus> {
        let memory_map_result = match self.memory_map {
            Some(reserved) => memory_map::release_memory_map(reserved, services),
            None => Ok(()),
        };
        let boot_info_result = boot_info::release_boot_info(self.boot_info, services);
        let mapping_result = mapping::release_kernel_mapping(self.mapping, services);
        let stack_result = stack::release_stack(self.stack, services);
        let kernel_result = stage::release_kernel(self.kernel, services);
        // Toutes les liberations sont tentees avant
        // de retourner une eventuelle erreur.
        memory_map_result?;
        boot_info_result?;
        mapping_result?;
        stack_result?;
        kernel_result
    }
}

pub fn prepare_kernel(
    image_handle: EfiHandle,
    system_table: *mut SystemTable,
) -> Result<PreparedKernel, EfiStatus> {
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
    //Analyser le noyau tout en conservant les handles ouverts
    let result = (|| -> Result<PreparedKernel, EfiStatus> {
        // 1. Lire l'en tete ELF64
        let mut header_bytes = [0u8; 64];

        read_exact_at(file, 0, &mut header_bytes)?;

        let elf = ElfHeader::parse(&header_bytes).map_err(|_| EFI_LOAD_ERROR)?;
        // 2. Parcourir la table des Program Headers.
        let mut loadable_segments = 0usize;
        let mut entry_valid = false;

        for index in 0..usize::from(elf.program_header_count) {
            let relative_offset = (index as u64).checked_mul(56).ok_or(EFI_LOAD_ERROR)?;

            let offset = elf
                .program_header_offset
                .checked_add(relative_offset)
                .ok_or(EFI_LOAD_ERROR)?;

            let mut segment_bytes = [0u8; 56];

            read_exact_at(file, offset, &mut segment_bytes)?;

            let segment = ProgramHeader::parse(&segment_bytes).map_err(|_| EFI_LOAD_ERROR)?;

            if segment.segment_type == PT_LOAD {
                loadable_segments += 1;

                if segment.contains_executable_entry(elf.entry) {
                    entry_valid = true;
                }
            }
        }
        // 3. Un executable doit comporter au moins un
        // segment chargeable, et son point d'entree
        // doit appartenir a un segment executable.
        if loadable_segments == 0 || !entry_valid {
            return Err(EFI_LOAD_ERROR);
        }
        // Initialiser la console pour afficher le diagnostic.
        let mut console = unsafe { Console::from_system_table(system_table) }?;

        console.write_ascii("\nInspecting ELF dynamic information...\n")?;

        let report = dynamic::inspect_dynamic(file, &elf)?;

        if report.found {
            console.write_ascii("PT_DYNAMIC found\n")?;
        } else {
            console.write_ascii("No PT_DYNAMIC segment\n")?;
        }

        console.write_ascii("Dynamic entries: ")?;
        console.write_dec_u64(report.dynamic_entries as u64)?;

        console.write_ascii("\nRELA entries: ")?;
        console.write_dec_u64(report.rela_entries as u64)?;

        console.write_ascii("\nR_X86_64_RELATIVE: ")?;
        console.write_dec_u64(report.relative_entries as u64)?;

        console.write_ascii("\nUnsupported relocations: ")?;
        console.write_dec_u64(report.unsupported_entries as u64)?;

        if let Some(kind) = report.first_unsupported_type {
            console.write_ascii("\nFirst unsupported type: ")?;
            console.write_dec_u64(kind as u64)?;
        }

        console.write_ascii("\nRequired external librairies: ")?;
        console.write_dec_u64(report.needed_librairies as u64)?;

        if report.other_relocation_formats {
            console.write_ascii("\nOther relocation formats detected")?;
        }

        if report.text_relocations {
            console.write_ascii("\nText relocations detected")?;
        }

        if report.supported_for_loading() {
            console.write_ascii("\nNo unsupported dynamic relocation requirements detected\n")?;
        } else {
            console.write_ascii("\nWARNING: Kernel relocation support incomplete\n")?;
        }

        console.write_ascii("\nStaging kernel PT_LOAD segments...\n")?;

        let _ = console.write_ascii("[BOOT] Loading kernel segments...\n");
        let kernel = match stage::stage_kernel(file, services, &elf) {
            Ok(kernel) => {
                let _ = console.write_ascii("[BOOT] Kernel segments loaded\n");
                kernel
            }
            Err(status) => {
                let _ = console.write_ascii("[ERROR] Kernel staging failed: ");
                let _ = console.write_hex_u64(status as u64);
                let _ = console.write_ascii("\n");
                return Err(status);
            }
        };

        let _ = console.write_ascii("[BOOT] Allocating kernel stack...\n");
        let stack = match stack::allocate_stack(services) {
            Ok(stack) => {
                let _ = console.write_ascii("[BOOT] Kernel stack allocated\n");
                stack
            }
            Err(status) => {
                let _ = console.write_ascii("[ERROR] Stack allocation failed: ");
                let _ = console.write_hex_u64(status as u64);
                let _ = console.write_ascii("\n");
                stage::release_kernel(kernel, services)?;
                return Err(status);
            }
        };
        // Construire les tables de pagination
        // En cas d'erreur, liberer l'image du noyau.
        let _ = console.write_ascii("[BOOT] Building kernel page tables...\n");
        let mut mapping = match mapping::build_kernel_mapping(file, services, &elf, &kernel, &stack)
        {
            Ok(mapping) => {
                let _ = console.write_ascii("[BOOT] Kernel page tables built\n");
                mapping
            }
            Err(status) => {
                let _ = console.write_ascii("[ERROR] Kernel mapping failed: ");
                let _ = console.write_hex_u64(status as u64);
                let stack_cleanup = stack::release_stack(stack, services);
                let kernel_cleanup = stage::release_kernel(kernel, services);
                stack_cleanup?;
                kernel_cleanup?;
                return Err(status);
            }
        };

        let _ = console.write_ascii("[BOOT] Preparing BootInfo...\n");
        let boot_info = match boot_info::allocate_boot_info(services, &kernel, &mapping, &stack) {
            Ok(boot_info) => boot_info,
            Err(status) => {
                let mapping_cleanup = mapping::release_kernel_mapping(mapping, services);
                let stack_cleanup = stack::release_stack(stack, services);
                let kernel_cleanup = stage::release_kernel(kernel, services);

                mapping_cleanup?;
                stack_cleanup?;
                kernel_cleanup?;

                return Err(status);
            }
        };

        let _ = console.write_ascii("[BOOT] Mapping BootInfo into kernel space...\n");
        let boot_info_virtual = match mapping::map_boot_info(&mapping, boot_info.physical_base) {
            Ok(address) => address,
            Err(status) => {
                let _ = console.write_ascii("[ERROR] BootInfo mapping failed:");
                let _ = console.write_hex_u64(status as u64);
                let _ = console.write_ascii("\n");
                // Les quatres ressources sont deja allouees.
                // Les liberer avant de retourner une erreur.
                let prepared = PreparedKernel {
                    kernel,
                    mapping,
                    stack,
                    boot_info,
                    memory_map: None,
                };

                prepared.release(services)?;

                return Err(status);
            }
        };
        let _ = console.write_ascii("[BOOT] BootInfo virtual mapping verified\n");

        let _ = console.write_ascii("[BOOT] Reserving persistent UEFI memory map...\n");
        let memory_map = match memory_map::reserve_memory_map(services) {
            Ok(reserved) => reserved,
            Err(status) => {
                PreparedKernel {
                    kernel,
                    mapping,
                    stack,
                    boot_info,
                    memory_map: None,
                }
                .release(services)?;

                return Err(status);
            }
        };
        let _ = console.write_ascii("[BOOT] Mapping UEFI memory map...\n");
        let memory_map_virtual = match mapping::map_memory_map(&mapping, &memory_map) {
            Ok(address) => address,
            Err(status) => {
                PreparedKernel {
                    kernel,
                    mapping,
                    stack,
                    boot_info,
                    memory_map: Some(memory_map),
                }
                .release(services)?;

                return Err(status);
            }
        };
        // Capture de verification : elle n'est PAS definitive.
        let memory_map_preview = match memory_map::capture_memory_map(services, &memory_map) {
            Ok(snapshot) => snapshot,
            Err(status) => {
                PreparedKernel {
                    kernel,
                    mapping,
                    stack,
                    boot_info,
                    memory_map: Some(memory_map),
                }
                .release(services)?;

                return Err(status);
            }
        };
        let _ = console.write_ascii("[BOOT] UEFI memory map buffer verified\n");

        // Les deux allocations sont maintenant actives.
        let diagnostic = (|| -> Result<(), EfiStatus> {
            console.write_ascii("\nKernel image and page tables retained\n")?;

            console.write_ascii("Loadable segments: ")?;
            console.write_dec_u64(kernel.segments as u64)?;

            console.write_ascii("\nKernel physical base: ")?;
            console.write_hex_u64(kernel.physical_base)?;

            console.write_ascii("\nKernel allocated pages: ")?;
            console.write_dec_u64(kernel.pages as u64)?;

            console.write_ascii("\nPML4 physical base: ")?;
            console.write_hex_u64(mapping.pml4_physical)?;

            console.write_ascii("\nKernel virtual base: ")?;
            console.write_hex_u64(mapping.virtual_base)?;

            console.write_ascii("\nKernel entry virtual: ")?;
            console.write_hex_u64(mapping.entry_virtual)?;

            console.write_ascii("\nMapped pages: ")?;
            console.write_dec_u64(mapping.mapped_pages as u64)?;

            console.write_ascii("\nWritable pages: ")?;
            console.write_dec_u64(mapping.writable_pages as u64)?;

            console.write_ascii("\nExecutable pages: ")?;
            console.write_dec_u64(mapping.executable_pages as u64)?;

            console.write_ascii("\nStack physical base: ")?;
            console.write_hex_u64(stack.physical_base)?;

            console.write_ascii("\nStack virtual base: ")?;
            console.write_hex_u64(stack.virtual_base)?;

            console.write_ascii("\nStack mapped pages: ")?;
            console.write_dec_u64(mapping.stack_mapped_pages as u64)?;

            console.write_ascii("\nFuture kernel RSP: ")?;
            console.write_hex_u64(mapping.stack_top_virtual)?;

            console.write_ascii(
                "\nKernel stack verified\n\
                Stack guard page verified\n",
            )?;

            console.write_ascii("\nBootInfo physical address: ")?;
            console.write_hex_u64(boot_info.physical_base)?;

            console.write_ascii("\nBootInfo virtual address: ")?;
            console.write_hex_u64(boot_info_virtual)?;

            console.write_ascii("\nBootInfo mapping: read-only, NX\n")?;

            console.write_ascii("\nBootInfo version: ")?;
            console.write_dec_u64(boot_info.value.version as u64)?;

            console.write_ascii("\nBootInfo size: ")?;
            console.write_dec_u64(boot_info.value.size as u64)?;
            console.write_ascii(" bytes\n")?;

            if !boot_info.value.validate() || boot_info.value.has_memory_map() {
                return Err(EFI_LOAD_ERROR);
            }

            console.write_ascii("BootInfo structure validated\n")?;

            console.write_ascii("\nUEFI memory map physical base: ")?;
            console.write_hex_u64(memory_map.physical_base)?;

            console.write_ascii("\nUEFI memory map virtual base: ")?;
            console.write_hex_u64(memory_map_virtual)?;

            console.write_ascii("\nReserved memory map pages: ")?;
            console.write_dec_u64(memory_map.pages as u64)?;

            console.write_ascii("\nMemory map capacity: ")?;
            console.write_dec_u64(memory_map.capacity_bytes as u64)?;
            console.write_ascii(" bytes")?;

            console.write_ascii("\nSnapshot size: ")?;
            console.write_dec_u64(memory_map_preview.size_bytes as u64)?;

            console.write_ascii("\nDescriptor size: ")?;
            console.write_dec_u64(memory_map_preview.descriptor_size as u64)?;

            console.write_ascii("\nDescriptor version: ")?;
            console.write_dec_u64(memory_map_preview.descriptor_version as u64)?;

            console.write_ascii("\nSnapshot MapKey (temporary): ")?;
            console.write_hex_u64(memory_map_preview.map_key as u64)?;

            let descriptors = memory_map_preview.size_bytes / memory_map_preview.descriptor_size;

            console.write_ascii("\nMemory descriptors: ")?;
            console.write_dec_u64(descriptors as u64)?;

            if boot_info.value.has_memory_map() {
                return Err(EFI_LOAD_ERROR);
            }

            console.write_ascii(
                "\nMemory map buffer prepared\n\
                Final memory map handoff pending\n",
            )?;

            console.write_ascii("\nPreparing kernel entry ABI...\n")?;

            handoff::verify_entry_abi(&mapping, &boot_info, boot_info_virtual)?;

            console.write_ascii(
                "Kernel calling convention: System V AMD64\n\
                Kernel entry register: RIP\n\
                BootInfo argument register: RDI\n\
                Kernel stack alignment verified\n\
                System V ABI probe successfully\n\
                Kernel entry ABI verified\n",
            )?;

            console.write_ascii("Future RIP: ")?;
            console.write_hex_u64(mapping.entry_virtual)?;

            console.write_ascii("\nFuture RDI: ")?;
            console.write_hex_u64(boot_info_virtual)?;

            console.write_ascii("\nFuture RSP before CALL: ")?;
            console.write_hex_u64(mapping.stack_top_virtual)?;

            console.write_ascii("\nFuture RSP at kernel entry: ")?;
            console.write_hex_u64(mapping.stack_top_virtual - 8)?;

            console.write_ascii("\n")?;

            console.write_ascii("\nPreparing transition mapping...\n")?;
            // SAFETY:
            // Le bootloader s'execute en Ring 0
            // dans le mapping actif du firmware
            let cpu = unsafe { x86_64::inspect_cpu() }?;

            mapping::map_transition(&mut mapping, services, &cpu)?;

            let transition = mapping.transition.as_ref().ok_or(EFI_LOAD_ERROR)?;

            console.write_ascii("Transition physical address: ")?;
            console.write_hex_u64(transition.code_address)?;

            console.write_ascii("\nTransition virtual address: ")?;
            console.write_hex_u64(transition.code_address)?;

            console.write_ascii("\nTransition tables physical base: ")?;
            console.write_hex_u64(transition.tables_physical)?;

            console.write_ascii(
                "\nTransition mapped pages: 1\n\
                Additional paging tables: 3\n\
                Total paging tables: 7\n\
                Transition permissions: read-only, executable\n\
                Physical address width verified\n\
                Firmware identity mapping verified\n\
                Transition identity mapping verified\n",
            )?;

            console.write_ascii("\nPreparedKernel initialized successfully\n")?;

            Ok(())
        })();
        // Nettoyer les allocations si le diagnostic echoue
        if let Err(status) = diagnostic {
            let prepared = PreparedKernel {
                kernel,
                mapping,
                stack,
                boot_info,
                memory_map: Some(memory_map),
            };

            prepared.release(services)?;
            return Err(status);
        }
        // Transferer la propriete des allocations
        // au reste du processus de demarrage
        Ok(PreparedKernel {
            kernel,
            mapping,
            stack,
            boot_info,
            memory_map: Some(memory_map),
        })
    })();
    // Fermer les handles, meme en cas d'echec du parseur.
    let file_close_status = unsafe { ((*file).close)(file) };

    let root_close_status = unsafe { ((*root).close)(root) };

    let prepared = result?;
    // Les handles on ete fermes.
    // Si une fermeture a echoue, liberer aussi les pages.
    let close_error = if file_close_status != EFI_SUCCESS {
        Some(file_close_status)
    } else if root_close_status != EFI_SUCCESS {
        Some(root_close_status)
    } else {
        None
    };

    if let Some(status) = close_error {
        prepared.release(services)?;
        return Err(status);
    }

    Ok(prepared)
}

fn read_exact_at(file: *mut FileProtocol, offset: u64, buffer: &mut [u8]) -> Result<(), EfiStatus> {
    if file.is_null() {
        return Err(EFI_INVALID_PARAMETER);
    }
    // Placer le curseur de lecture
    let status = unsafe { ((*file).set_position)(file, offset) };

    if status != EFI_SUCCESS {
        return Err(status);
    }

    let mut total_read = 0usize;

    while total_read < buffer.len() {
        let remaining = buffer.len() - total_read;
        let mut bytes_read = remaining;

        let destination = unsafe { buffer.as_mut_ptr().add(total_read) };

        let status = unsafe { ((*file).read)(file, &mut bytes_read, destination.cast()) };

        if status != EFI_SUCCESS {
            return Err(status);
        }
        // Une lecture de zero octet signifie que nous
        // avons atteint la fin du fichier
        if bytes_read == 0 || bytes_read > remaining {
            return Err(EFI_LOAD_ERROR);
        }

        total_read += bytes_read;
    }

    Ok(())
}
