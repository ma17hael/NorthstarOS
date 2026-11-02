#[derive(Debug, Clone, Copy)]
pub struct DynamicEntry {
    pub tag: i64,
    pub value: u64,
}

impl DynamicEntry {
    pub fn parse(bytes: &[u8; 16]) -> Self {
        Self {
            tag: i64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            value: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Rela {
    pub offset: u64,
    pub info: u64,
    // Sera utilise lors de l'application des relocations.
    #[allow(dead_code)]
    pub addend: i64,
}

impl Rela {
    pub fn parse(bytes: &[u8; 24]) -> Self {
        Self {
            offset: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            info: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            addend: i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        }
    }

    pub fn relocation_type(&self) -> u32 {
        self.info as u32
    }

    pub fn symbol_index(&self) -> u32 {
        (self.info >> 32) as u32
    }
}
