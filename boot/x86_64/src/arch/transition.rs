use core::arch::global_asm;

global_asm!(
    ".text",
    ".p2align 12, 0xcc",
    ".global northstar_transition_stub",
    "northstar_transition_stub:",
    // Instruction temporaire
    "ud2",
    ".p2align 12, 0xcc",
    ".global northstar_transition_end",
    "northstar_transition_end:"
);

unsafe extern "C" {
    fn northstar_transition_stub();
    static northstar_transition_end: u8;
}

pub(crate) fn code_range() -> (u64, u64) {
    let start = northstar_transition_stub as *const () as u64;

    let end = &raw const northstar_transition_end as u64;

    (start, end)
}
