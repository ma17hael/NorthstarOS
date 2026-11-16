
from pathlib import Path
import struct

TARGET = Path("target")
UEFI_DIR = TARGET / "x86_64-unknown-uefi" / "release"
KERNEL_DIR = TARGET / "x86_64-unknown-none" / "release"


def verify_uefi(path: Path) -> None:
    data = path.read_bytes()

    assert len(data) >= 0x40, "Fichier PE trop petit"
    assert data[:2] == b"MZ", "Signature DOS absente"

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    assert pe_offset + 96 <= len(data), "En-tête PE invalide"

    assert data[pe_offset:pe_offset + 4] == b"PE\0\0"

    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    assert machine == 0x8664, "Architecture PE non x86-64"

    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    assert magic == 0x20B, "PE32+ attendu"

    subsystem = struct.unpack_from("<H", data, optional + 68)[0]
    assert subsystem == 10, "Application UEFI attendue"

    print(f"[OK] UEFI x86-64 : {path}")


def verify_kernel(path: Path) -> None:
    data = path.read_bytes()

    assert len(data) >= 64, "Fichier ELF trop petit"
    assert data[:4] == b"\x7fELF", "Signature ELF absente"
    assert data[4] == 2, "ELF64 attendu"
    assert data[5] == 1, "Little-endian attendu"

    elf_type, machine = struct.unpack_from("<HH", data, 16)
    assert elf_type in (2, 3), "ELF exécutable attendu"
    assert machine == 0x3E, "Architecture ELF non x86-64"

    entry = struct.unpack_from("<Q", data, 24)[0]
    assert entry != 0, "Point d'entrée absent"

    ph_offset = struct.unpack_from("<Q", data, 32)[0]
    ph_size = struct.unpack_from("<H", data, 54)[0]
    ph_count = struct.unpack_from("<H", data, 56)[0]

    assert ph_size >= 56, "Taille des program headers invalide"
    assert ph_count > 0, "Aucun program header"
    assert ph_offset + ph_size * ph_count <= len(data)

    loadable = False

    for index in range(ph_count):
        offset = ph_offset + index * ph_size
        segment_type = struct.unpack_from("<I", data, offset)[0]

        if segment_type == 1:
            file_size = struct.unpack_from("<Q", data, offset + 32)[0]
            mem_size = struct.unpack_from("<Q", data, offset + 40)[0]
            assert file_size <= mem_size, "Segment PT_LOAD invalide"
            loadable = True

    assert loadable, "Aucun segment PT_LOAD"

    print(f"[OK] ELF64 x86-64 : {path}")


def main() -> None:
    assert UEFI_DIR.is_dir(), "Compilation UEFI absente"
    assert KERNEL_DIR.is_dir(), "Compilation noyau absente"

    uefi_files = list(UEFI_DIR.glob("*.efi"))
    assert uefi_files, "Aucun fichier .efi produit"

    for path in uefi_files:
        verify_uefi(path)

    elf_files = [
        path for path in KERNEL_DIR.iterdir()
        if path.is_file()
        and path.read_bytes()[:4] == b"\x7fELF"
    ]

    assert elf_files, "Aucun noyau ELF produit"

    for path in elf_files:
        verify_kernel(path)

    print("\n[OK] Validation des binaires terminée")


if __name__ == "__main__":
    main()
