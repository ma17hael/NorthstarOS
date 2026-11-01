use core::slice;

use super::{EFI_LOAD_ERROR, read_exact_at};

use crate::elf::header::ElfHeader;
use crate::elf::program::{PROGRAM_HEADER_SIZE, PT_LOAD, ProgramHeader};
use crate::uefi::file::FileProtocol;
use crate::uefi::services::{ALLOCATE_ANY_PAGES, BootServices, EFI_LOADER_DATA};
use crate::uefi::types::{EFI_SUCCESS, EfiStatus};

const PAGE_SIZE: u64 = 4096;
const MAX_IMAGE_SIZE: u64 = 16 * 1024 * 1024;

pub(super) struct StageReport {
    pub physical_base: u64,
    pub pages: usize,
    pub segments: usize,
}

fn program_header(
    file: *mut FileProtocol,
    elf: &ElfHeader,
    index: usize,
) -> Result<ProgramHeader, EfiStatus> {
    let relative_offset = (index as u64)
        .checked_mul(PROGRAM_HEADER_SIZE as u64)
        .ok_or(EFI_LOAD_ERROR)?;

    let offset = elf
        .program_header_offset
        .checked_add(relative_offset)
        .ok_or(EFI_LOAD_ERROR)?;

    let mut bytes = [0u8; PROGRAM_HEADER_SIZE];

    read_exact_at(file, offset, &mut bytes)?;

    ProgramHeader::parse(&bytes).map_err(|_| EFI_LOAD_ERROR)
}

pub(super) fn stage_kernel(
    file: *mut FileProtocol,
    services: &BootServices,
    elf: &ElfHeader,
) -> Result<StageReport, EfiStatus> {
    // Premiere passe : calculer la region virtuelle
    // et verifier que les segments ne se chevauchent pas.
    let mut min_address = u64::MAX;
    let mut max_address = 0u64;
    let mut previous_end = 0u64;
    let mut segment_count = 0usize;

    for index in 0..usize::from(elf.program_header_count) {
        let segment = program_header(file, elf, index)?;

        if segment.segment_type != PT_LOAD || segment.memory_size == 0 {
            continue;
        }

        let end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or(EFI_LOAD_ERROR)?;
        // Les PT_LOAD doivent etre ordonnes et
        // ne pas partager de plages d'octets.
        if segment.virtual_address < previous_end {
            return Err(EFI_LOAD_ERROR);
        }

        previous_end = end;

        min_address = min_address.min(segment.virtual_address);
        max_address = max_address.max(end);
        segment_count += 1;
    }

    if segment_count == 0 {
        return Err(EFI_LOAD_ERROR);
    }
    // Aligner les bornes sur des pages de 4096 octets.
    let image_start = min_address & !(PAGE_SIZE - 1);

    let image_end = max_address
        .checked_add(PAGE_SIZE - 1)
        .ok_or(EFI_LOAD_ERROR)?
        & !(PAGE_SIZE - 1);

    let image_size = image_end.checked_sub(image_start).ok_or(EFI_LOAD_ERROR)?;

    if image_size == 0 || image_size > MAX_IMAGE_SIZE {
        return Err(EFI_LOAD_ERROR);
    }

    let pages = usize::try_from(image_size / PAGE_SIZE).map_err(|_| EFI_LOAD_ERROR)?;

    let image_len = usize::try_from(image_size).map_err(|_| EFI_LOAD_ERROR)?;
    // Reserver une region de pages physiques contigues.
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
    // Le bloc est temporaire. Toutes les erreurs de
    // chargement doivent conduire a FreePages().
    let result = (|| -> Result<(), EfiStatus> {
        if physical_base == 0 || physical_base % PAGE_SIZE != 0 {
            return Err(EFI_LOAD_ERROR);
        }

        let address = usize::try_from(physical_base).map_err(|_| EFI_LOAD_ERROR)?;
        // SAFETY:
        // Test exclusivement sur EDK II x86_64/QEMU,
        // avant ExitBootServices(), avec une region
        // physique accessible via le mapping courant
        // du firmware
        //
        // Cette hypothese devra etre retiree lors
        // de l'introduction de nos propres page tables.
        let memory = unsafe { slice::from_raw_parts_mut(address as *mut u8, image_len) };
        // Initialiser la region complete, y compris
        // les espaces entre les segments et la BSS
        memory.fill(0);
        // Deuxieme passe : copier les segments ELF.
        for index in 0..usize::from(elf.program_header_count) {
            let segment = program_header(file, elf, index)?;

            if segment.segment_type != PT_LOAD || segment.memory_size == 0 {
                continue;
            }

            let relative_start = segment
                .virtual_address
                .checked_sub(image_start)
                .ok_or(EFI_LOAD_ERROR)?;

            let start = usize::try_from(relative_start).map_err(|_| EFI_LOAD_ERROR)?;

            let file_size = usize::try_from(segment.file_size).map_err(|_| EFI_LOAD_ERROR)?;

            let memory_size = usize::try_from(segment.memory_size).map_err(|_| EFI_LOAD_ERROR)?;

            let file_end = start.checked_add(file_size).ok_or(EFI_LOAD_ERROR)?;

            let memory_end = start.checked_add(memory_size).ok_or(EFI_LOAD_ERROR)?;

            if memory_end > memory.len() || file_end > memory_end {
                return Err(EFI_LOAD_ERROR);
            }
            // Copier uniquement les octets presents
            // dans KERNEL.ELF
            if file_size > 0 {
                read_exact_at(file, segment.offset, &mut memory[start..file_end])?;
            }
            // Verifier la copie par une seconde lecture.
            let mut check = [0u8; 256];
            let mut verified = 0usize;

            while verified < file_size {
                let chunk = (file_size - verified).min(check.len());

                let offset = segment
                    .offset
                    .checked_add(verified as u64)
                    .ok_or(EFI_LOAD_ERROR)?;

                read_exact_at(file, offset, &mut check[..chunk])?;

                let begin = start + verified;
                let end = begin + chunk;

                if memory[begin..end] != check[..chunk] {
                    return Err(EFI_LOAD_ERROR);
                }

                verified += chunk;
            }
            // Verifier que les octets non intialises
            // du segment sont bien nuls.
            if memory[file_end..memory_end].iter().any(|byte| *byte != 0) {
                return Err(EFI_LOAD_ERROR);
            }
        }

        Ok(())
    })();
    // Toujours liberer les pages apres le test.
    let free_status = unsafe { (services.free_pages)(physical_base, pages) };

    if free_status != EFI_SUCCESS {
        return Err(free_status);
    }

    result?;

    Ok(StageReport {
        physical_base,
        pages,
        segments: segment_count,
    })
}
