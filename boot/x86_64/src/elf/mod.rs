pub mod header;
pub mod program;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    InvalidMagic,
    UnsupportedFormat,
    InvalidHeader,
    InvalidSegment,
    ArithmeticOverflow,
}

pub use header::ElfHeader;
pub use program::{PT_LOAD, ProgramHeader};
