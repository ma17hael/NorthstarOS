use super::ElfError;

pub const PT_LOAD: u32 = 1;

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

pub const PROGRAM_HEADER_SIZE: usize = 56;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct ProgramHeader {
    pub segment_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

impl ProgramHeader {
    pub fn parse(data: &[u8; PROGRAM_HEADER_SIZE]) -> Result<Self, ElfError> {
        let header = Self {
            segment_type: read_u32(data, 0),
            flags: read_u32(data, 4),
            offset: read_u64(data, 8),
            virtual_address: read_u64(data, 16),
            physical_address: read_u64(data, 24),
            file_size: read_u64(data, 32),
            memory_size: read_u64(data, 40),
            alignment: read_u64(data, 48),
        };

        if header.segment_type == PT_LOAD {
            header.validate_load_segment()?;
        }

        Ok(header)
    }

    fn validate_load_segment(&self) -> Result<(), ElfError> {
        // Le segment ne peut pas contenir plus d'octets
        // dans le fichier qu'il n'en occupe en mémoire.
        if self.file_size > self.memory_size {
            return Err(ElfError::InvalidSegment);
        }
        // Les permissions doivent appartenir a R, W, X.
        if self.flags & !(PF_R | PF_W | PF_X) != 0 {
            return Err(ElfError::InvalidSegment);
        }
        // Controle des debordements arithmetiques
        self.offset
            .checked_add(self.file_size)
            .ok_or(ElfError::ArithmeticOverflow)?;

        self.virtual_address
            .checked_add(self.memory_size)
            .ok_or(ElfError::ArithmeticOverflow)?;
        // L'alignement doit etre nul, egal a 1
        // ou une puissance de deux
        if self.alignment > 1 {
            if !self.alignment.is_power_of_two() {
                return Err(ElfError::InvalidSegment);
            }
            //Les adresses virtuelles et offsets doivent
            // etre congruents modulo l'alignement
            if self.virtual_address % self.alignment != self.offset % self.alignment {
                return Err(ElfError::InvalidSegment);
            }
        }

        Ok(())
    }

    pub fn contains_executable_entry(&self, entry: u64) -> bool {
        if self.segment_type != PT_LOAD || self.flags & PF_X == 0 {
            return false;
        }

        let Some(end) = self.virtual_address.checked_add(self.memory_size) else {
            return false;
        };

        entry >= self.virtual_address && entry < end
    }
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
