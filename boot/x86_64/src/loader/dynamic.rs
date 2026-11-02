use super::{EFI_LOAD_ERROR, read_exact_at};

use crate::elf::dynamic::{DynamicEntry, Rela};
use crate::elf::header::ElfHeader;
use crate::elf::program::{PROGRAM_HEADER_SIZE, PT_LOAD, ProgramHeader};
use crate::uefi::file::FileProtocol;
use crate::uefi::types::EfiStatus;

const PT_DYNAMIC: u32 = 2;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_REL: i64 = 17;
const DT_TEXTREL: i64 = 22;
const DT_JMPREL: i64 = 23;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;

const R_X86_64_NONE: u32 = 0;
const R_X86_64_RELATIVE: u32 = 8;

const MAX_DYNAMIC_BYTES: u64 = 64 * 1024;
const MAX_RELOCATIONS: usize = 4096;

#[derive(Default)]
pub(super) struct DynamicReport {
    pub found: bool,
    pub dynamic_entries: usize,
    pub rela_entries: usize,
    pub relative_entries: usize,
    pub unsupported_entries: usize,
    pub first_unsupported_type: Option<u32>,
    pub needed_librairies: usize,
    pub other_relocation_formats: bool,
    pub text_relocations: bool,
}

impl DynamicReport {
    pub fn supported_for_loading(&self) -> bool {
        self.unsupported_entries == 0
            && self.needed_librairies == 0
            && !self.other_relocation_formats
            && !self.text_relocations
    }
}

fn read_program_header(
    file: *mut FileProtocol,
    elf: &ElfHeader,
    index: usize,
) -> Result<ProgramHeader, EfiStatus> {
    let relative = (index as u64)
        .checked_add(PROGRAM_HEADER_SIZE as u64)
        .ok_or(EFI_LOAD_ERROR)?;

    let offset = elf
        .program_header_offset
        .checked_add(relative)
        .ok_or(EFI_LOAD_ERROR)?;

    let mut bytes = [0u8; PROGRAM_HEADER_SIZE];
    read_exact_at(file, offset, &mut bytes)?;

    ProgramHeader::parse(&bytes).map_err(|_| EFI_LOAD_ERROR)
}
// Convertir une adresse virtuelle ELF en offset fichier.
// Toute la plage demandee doit etre presente dans un PT_LOAD.
fn virtual_to_file(
    file: *mut FileProtocol,
    elf: &ElfHeader,
    address: u64,
    length: u64,
) -> Result<u64, EfiStatus> {
    for index in 0..usize::from(elf.program_header_count) {
        let segment = read_program_header(file, elf, index)?;

        if segment.segment_type != PT_LOAD {
            continue;
        }

        let Some(relative) = address.checked_sub(segment.virtual_address) else {
            continue;
        };

        if relative > segment.file_size {
            continue;
        }

        if length > segment.file_size - relative {
            continue;
        }

        return segment.offset.checked_add(relative).ok_or(EFI_LOAD_ERROR);
    }

    Err(EFI_LOAD_ERROR)
}
// Verifier que l'emplacement a modifier est contenu
// entierement dans un segment chargeable du noyau.
fn valid_target(file: *mut FileProtocol, elf: &ElfHeader, address: u64) -> Result<bool, EfiStatus> {
    for index in 0..usize::from(elf.program_header_count) {
        let segment = read_program_header(file, elf, index)?;

        if segment.segment_type != PT_LOAD {
            continue;
        }

        if let Some(relative) = address.checked_sub(segment.virtual_address) {
            if relative <= segment.memory_size && 8 <= segment.memory_size - relative {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn set_once(slot: &mut Option<u64>, value: u64) -> Result<(), EfiStatus> {
    if slot.replace(value).is_some() {
        return Err(EFI_LOAD_ERROR);
    }

    Ok(())
}

pub(super) fn inspect_dynamic(
    file: *mut FileProtocol,
    elf: &ElfHeader,
) -> Result<DynamicReport, EfiStatus> {
    let mut report = DynamicReport::default();
    let mut dynamic_segment = None;
    // 1. Retrouver PT_DYNAMIC.
    for index in 0..usize::from(elf.program_header_count) {
        let segment = read_program_header(file, elf, index)?;

        if segment.segment_type == PT_DYNAMIC {
            if dynamic_segment.replace(segment).is_some() {
                return Err(EFI_LOAD_ERROR);
            }
        }
    }

    let Some(dynamic) = dynamic_segment else {
        return Ok(report);
    };

    report.found = true;

    if dynamic.file_size == 0
        || dynamic.file_size > MAX_DYNAMIC_BYTES
        || dynamic.file_size % 16 != 0
        || dynamic.file_size > dynamic.memory_size
    {
        return Err(EFI_LOAD_ERROR);
    }

    let mut rela_address = None;
    let mut rela_size = None;
    let mut rela_entry_size = None;
    let mut terminated = false;
    // 2. Lire les entrees de PT_DYNAMIC
    for index in 0..(dynamic.file_size / 16) {
        let offset = dynamic
            .offset
            .checked_add(index * 16)
            .ok_or(EFI_LOAD_ERROR)?;

        let mut bytes = [0u8; 16];
        read_exact_at(file, offset, &mut bytes)?;

        let entry = DynamicEntry::parse(&bytes);

        if entry.tag == DT_NULL {
            terminated = true;
            break;
        }

        report.dynamic_entries += 1;

        match entry.tag {
            DT_RELA => {
                set_once(&mut rela_address, entry.value)?;
            }
            DT_RELASZ => {
                set_once(&mut rela_size, entry.value)?;
            }
            DT_RELAENT => {
                set_once(&mut rela_entry_size, entry.value)?;
            }
            DT_NEEDED => {
                report.needed_librairies += 1;
            }
            DT_REL | DT_JMPREL | DT_RELR => {
                report.other_relocation_formats = true;
            }
            DT_PLTRELSZ | DT_RELRSZ | DT_RELRENT => {
                if entry.value != 0 {
                    report.other_relocation_formats = true;
                }
            }
            DT_TEXTREL => {
                report.text_relocations = true;
            }
            _ => {}
        }
    }

    if !terminated {
        return Err(EFI_LOAD_ERROR);
    }
    // 3. Verifier les parametres de la table RELA.
    let size = rela_size.unwrap_or(0);

    if size == 0 {
        return Ok(report);
    }

    let address = rela_address.ok_or(EFI_LOAD_ERROR)?;
    let entry_size = rela_entry_size.ok_or(EFI_LOAD_ERROR)?;

    if entry_size != 24 || size % 24 != 0 {
        return Err(EFI_LOAD_ERROR);
    }

    let count = usize::try_from(size / 24).map_err(|_| EFI_LOAD_ERROR)?;

    if count > MAX_RELOCATIONS {
        return Err(EFI_LOAD_ERROR);
    }
    // DT_RELA contient une adresse virtuelle, pas
    // un offset directement utilisable dans le fichier.
    let file_offset = virtual_to_file(file, elf, address, size)?;

    report.rela_entries = count;
    // 4. Examiner chaque relocation sans s'appliquer.
    for index in 0..count {
        let relative = (index as u64).checked_mul(24).ok_or(EFI_LOAD_ERROR)?;

        let offset = file_offset.checked_add(relative).ok_or(EFI_LOAD_ERROR)?;

        let mut bytes = [0u8; 24];
        read_exact_at(file, offset, &mut bytes)?;

        let relocation = Rela::parse(&bytes);
        let kind = relocation.relocation_type();

        match kind {
            R_X86_64_NONE => {}

            R_X86_64_RELATIVE if relocation.symbol_index() == 0 => {
                if !valid_target(file, elf, relocation.offset)? {
                    return Err(EFI_LOAD_ERROR);
                }

                report.relative_entries += 1;
            }

            _ => {
                report.unsupported_entries += 1;

                if report.first_unsupported_type.is_none() {
                    report.first_unsupported_type = Some(kind);
                }
            }
        }
    }

    Ok(report)
}
