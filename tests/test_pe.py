"""Unit tests for PE machine parsing."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from gargoyle_acceptance.errors import AcceptanceError
from gargoyle_acceptance.pe import machine_name, read_pe_machine, validate_pe_machine


def test_read_pe_machine_reads_coff_header(tmp_path: Path) -> None:
    """PE parser reads the IMAGE_FILE_MACHINE value from an executable."""
    executable = _write_minimal_pe(tmp_path / "GargoyleArm64.exe", 0xAA64)

    machine = read_pe_machine(executable)

    assert machine.value == 0xAA64
    assert machine.name == "ARM64"


def test_validate_pe_machine_accepts_matching_platform(tmp_path: Path) -> None:
    """PE validation accepts the expected platform machine."""
    executable = _write_minimal_pe(tmp_path / "GargoyleArm64EC.exe", 0xA641)

    machine = validate_pe_machine(executable, "arm64ec")

    assert machine.name == "ARM64EC"


def test_validate_pe_machine_accepts_arm64ec_final_image_machine(tmp_path: Path) -> None:
    """ARM64EC validation accepts final image machine headers used by MSVC."""
    executable = _write_minimal_pe(tmp_path / "GargoyleArm64EC.exe", 0x8664)

    machine = validate_pe_machine(executable, "arm64ec")

    assert machine.name == "AMD64"


def test_validate_pe_machine_rejects_mismatch(tmp_path: Path) -> None:
    """PE validation rejects an executable built for a different platform."""
    executable = _write_minimal_pe(tmp_path / "Gargoyle.exe", 0x014C)

    with pytest.raises(AcceptanceError, match="PE machine mismatch"):
        validate_pe_machine(executable, "x64")


def test_read_pe_machine_rejects_invalid_image(tmp_path: Path) -> None:
    """PE parser rejects files without PE headers."""
    executable = tmp_path / "not-pe.exe"
    executable.write_bytes(b"nope")

    with pytest.raises(AcceptanceError, match="Invalid PE image"):
        read_pe_machine(executable)


def test_machine_name_falls_back_for_unknown_values() -> None:
    """Unknown PE machines render with a hexadecimal fallback."""
    assert machine_name(0x1234) == "UNKNOWN_0x1234"


def _write_minimal_pe(path: Path, machine: int) -> Path:
    """Write a minimal PE-shaped file.

    Args:
        path: Output path.
        machine: IMAGE_FILE_MACHINE value.

    Returns:
        Output path.
    """
    content = bytearray(0x100)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", content, 0x84, machine)
    path.write_bytes(content)
    return path
