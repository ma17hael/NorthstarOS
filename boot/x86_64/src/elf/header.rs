use super::ElfError;

pub const ELF_HEADER_SIZE: usize = 64;
pub const PROGRAM_HEADER_SIZE: u16 = 56;

const MAX_PROGRAM_HEADERS: u16 = 128;

// Types d'executables ELF pris en charge pour l'analyse
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const EM_X86_64: u16 = 62;

#[derive(Debug, Clone, Copy)]
pub struct ElfHeader {
    pub entry: u64,
    pub program_header_offset: u64,
    pub program_header_count: u16,
}

impl ElfHeader {
    pub fn parse(data: &[u8; ELF_HEADER_SIZE]) -> Result<Self, ElfError> {
        //Signature ELF
        if &data[0..4] != b"\x7FELF" {
            return Err(ElfError::InvalidMagic);
        }
        // ELF64, little-endian, version 1
        if data[4] != 2 || data[5] != 1 || data[6] != 1 {
            return Err(ElfError::UnsupportedFormat);
        }

        let elf_type = read_u16(data, 16);

        if elf_type != ET_EXEC && elf_type != ET_DYN {
            return Err(ElfError::UnsupportedFormat);
        }
        // EM_X86_64 = 62
        if read_u16(data, 18) != EM_X86_64 {
            return Err(ElfError::UnsupportedFormat);
        }
        // Version ELF courant
        if read_u32(data, 20) != 1 {
            return Err(ElfError::UnsupportedFormat);
        }

        let entry = read_u64(data, 24);
        let program_header_offset = read_u64(data, 32);

        let header_size = read_u16(data, 52);
        let program_header_size = read_u16(data, 54);
        let program_header_count = read_u16(data, 56);

        if header_size != ELF_HEADER_SIZE as u16 {
            return Err(ElfError::InvalidHeader);
        }

        if program_header_size != PROGRAM_HEADER_SIZE {
            return Err(ElfError::InvalidHeader);
        }

        if program_header_count == 0
            || program_header_count > MAX_PROGRAM_HEADERS
            || program_header_offset < ELF_HEADER_SIZE as u64
            || entry == 0
        {
            return Err(ElfError::InvalidHeader);
        }

        let table_size = u64::from(program_header_count) * u64::from(PROGRAM_HEADER_SIZE);

        program_header_offset
            .checked_add(table_size)
            .ok_or(ElfError::ArithmeticOverflow)?;

        Ok(Self {
            entry,
            program_header_offset,
            program_header_count,
        })
    }
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}
