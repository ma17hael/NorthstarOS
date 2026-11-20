use core::arch::{asm, x86_64::__cpuid};

use crate::console::Console;
use crate::uefi::types::EfiStatus;

const EFI_UNSUPPORTED: EfiStatus = (1usize << (usize::BITS - 1)) | 3;
const IA32_EFER: u32 = 0xC000_0080;
// CR0
const CR0_PE: u64 = 1 << 0;
const CR0_WP: u64 = 1 << 16;
const CR0_PG: u64 = 1 << 31;
// CR4
const CR4_PAE: u64 = 1 << 5;
const CR4_PGE: u64 = 1 << 7;
const CR4_LA57: u64 = 1 << 12;
const CR4_PCIDE: u64 = 1 << 17;
const CR4_CET: u64 = 1 << 23;
// IA32_EFER
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const EFER_NXE: u64 = 1 << 11;

pub(crate) struct CpuState {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,

    pub physical_address_bits: u8,
    pub virtual_address_bits: u8,

    pub long_mode_supported: bool,
    pub nx_supported: bool,
}

impl CpuState {
    pub fn validate(&self) -> bool {
        self.long_mode_supported
            && self.nx_supported
            && self.cr0 & CR0_PE != 0
            && self.cr0 & CR0_PG != 0
            && self.cr4 & CR4_PAE != 0
            && self.cr4 & CR4_LA57 == 0
            && self.cr4 & CR4_PCIDE == 0
            && self.cr4 & CR4_CET == 0
            && self.efer & EFER_LME != 0
            && self.efer & EFER_LMA != 0
            && (32..=52).contains(&self.physical_address_bits)
            && (48..=57).contains(&self.virtual_address_bits)
    }

    pub fn nx_enabled(&self) -> bool {
        self.efer & EFER_NXE != 0
    }

    pub fn write_protect_enabled(&self) -> bool {
        self.cr0 & CR0_WP != 0
    }

    pub fn global_pages_enabled(&self) -> bool {
        self.cr4 & CR4_PGE != 0
    }

    pub fn physical_address_mask(&self) -> u64 {
        ((1u64 << self.physical_address_bits) - 1) & !0xFFF
    }
}

/// Inspecte les capacites et l'etat du processeur.
///
/// # Safety
/// Cette fonction doit etre executee depuis
/// un environnement x86_64 privilegie.
pub(crate) unsafe fn inspect_cpu() -> Result<CpuState, EfiStatus> {
    let cs: u16;

    unsafe {
        asm!(
            "mov {cs:x}, cs",
            cs = out(reg) cs,
            options(nomem, nostack, preserves_flags)
        );
    }
    // Verification du niveau de privilege.
    if cs & 3 != 0 {
        return Err(EFI_UNSUPPORTED);
    }

    let max_basic = __cpuid(0).eax;

    let max_extended = __cpuid(0x8000_0000).eax;

    if max_basic < 1 || max_extended < 0x8000_0008 {
        return Err(EFI_UNSUPPORTED);
    }

    let features = __cpuid(1);
    // Support des MSR et de PAE.
    if features.edx & (1 << 5) == 0 || features.edx & (1 << 6) == 0 {
        return Err(EFI_UNSUPPORTED);
    }

    let extended = __cpuid(0x8000_0001);

    let long_mode_supported = extended.edx & (1 << 29) != 0;

    let nx_supported = extended.edx & (1 << 20) != 0;

    if !long_mode_supported || !nx_supported {
        return Err(EFI_UNSUPPORTED);
    }

    let address_sizes = __cpuid(0x8000_0008);

    let physical_address_bits = (address_sizes.eax & 0xFF) as u8;

    let virtual_address_bits = ((address_sizes.eax >> 8) & 0xFF) as u8;

    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    // SAFETY:
    // Nous sommes en Ring 0
    // Ces instructions lisent les registres
    // sans modifier leur contenu.
    unsafe {
        asm!(
            "mov {cr0}, cr0",
            "mov {cr3}, cr3",
            "mov {cr4}, cr4",
            cr0 = out(reg) cr0,
            cr3 = out(reg) cr3,
            cr4 = out(reg) cr4,
            options(nomem, nostack, preserves_flags)
        );
    }

    let efer_low: u32;
    let efer_high: u32;
    // Lecture du Model-Specific Register IA32_EFER.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") IA32_EFER,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags)
        );
    }

    let efer = ((efer_high as u64) << 32) | efer_low as u64;

    Ok(CpuState {
        cr0,
        cr3,
        cr4,
        efer,
        physical_address_bits,
        virtual_address_bits,
        long_mode_supported,
        nx_supported,
    })
}

pub(crate) fn report_cpu(console: &mut Console, cpu: &CpuState) -> Result<(), EfiStatus> {
    for (label, value) in [
        ("CR0: ", cpu.cr0),
        ("CR3: ", cpu.cr3),
        ("CR4: ", cpu.cr4),
        ("IA32_EFER: ", cpu.efer),
    ] {
        console.write_ascii(label)?;
        console.write_hex_u64(value)?;
        console.write_ascii("\n")?;
    }

    console.write_ascii("Physical address width: ")?;
    console.write_dec_u64(cpu.physical_address_bits as u64)?;
    console.write_ascii(" bits\n")?;

    console.write_ascii("Virtual address width: ")?;
    console.write_dec_u64(cpu.virtual_address_bits as u64)?;
    console.write_ascii(" bits\n")?;

    for (label, enabled) in [
        ("Long Mode supported: ", cpu.long_mode_supported),
        ("NX supported: ", cpu.nx_supported),
        ("Long Mod active: ", cpu.efer & EFER_LMA != 0),
        ("Paging enabled: ", cpu.cr0 & CR0_PG != 0),
        ("PAE enabled: ", cpu.cr4 & CR4_PAE != 0),
        ("LA57 enabled: ", cpu.cr4 & CR4_LA57 != 0),
        ("PCID enabled: ", cpu.cr4 & CR4_PCIDE != 0),
        ("CET enabled: ", cpu.cr4 & CR4_CET != 0),
        ("NXE enabled: ", cpu.nx_enabled()),
        ("Write protect enabled: ", cpu.write_protect_enabled()),
        ("Global pages enabled: ", cpu.global_pages_enabled()),
    ] {
        console.write_ascii(label)?;
        console.write_ascii(if enabled { "Yes\n" } else { "No\n" })?;
    }

    if !cpu.validate() {
        console.write_ascii("ERROR: Unsupported CPU configuration\n")?;
        return Err(EFI_UNSUPPORTED);
    }

    console.write_ascii("Physical address mask: ")?;
    console.write_hex_u64(cpu.physical_address_mask())?;

    console.write_ascii("\nCurrent PML4 physical base: ")?;
    console.write_hex_u64(cpu.cr3 & cpu.physical_address_mask())?;

    console.write_ascii("\nCPU compatibility verified\n")?;

    Ok(())
}

/// Verifie qu'une adresse est actuellement mappee
/// en identite et executable.
///
/// # Safety
///
/// Les tables physiques du firmware doivent etre
/// accessibles dans le mapping UEFI courant.
pub(crate) unsafe fn verify_identity_executable(cpu: &CpuState, address: u64) -> bool {
    const PRESENT: u64 = 1 << 0;
    const HUGE_PAGE: u64 = 1 << 7;
    const NO_EXECUTE: u64 = 1 << 63;

    if !cpu.validate() || address >= (1u64 << 47) {
        return false;
    }

    let mask = cpu.physical_address_mask();

    let mut table_physical = cpu.cr3 & mask;
    // PML4 -> PDPT -> PD -> PT
    for shift in [39u32, 30, 21, 12] {
        if table_physical == 0 {
            return false;
        }

        let index = ((address >> shift) & 0x1FF) as usize;

        let table = table_physical as *const u64;
        // SAFETY:
        // Les tables physiques du firmware sont
        // accessibles dans notre prototype QEMU.
        let entry = unsafe { core::ptr::read_volatile(table.add(index)) };

        if entry & PRESENT == 0 || entry & NO_EXECUTE != 0 {
            return false;
        }
        // Pages de 1 Gio ou 2 Mio
        if (shift == 30 || shift == 21) && entry & HUGE_PAGE != 0 {
            let offset_mask = (1u64 << shift) - 1;

            let physical = (entry & mask & !offset_mask) | (address & offset_mask);

            return physical == address;
        }
        // Page standard de 4 Kio.
        if shift == 12 {
            let physical = (entry & mask) | (address & 0xFFF);

            return physical == address;
        }

        table_physical = entry & mask;
    }

    false
}
