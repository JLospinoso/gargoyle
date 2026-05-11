"""Portable Executable machine validation for Gargoyle artifacts."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from gargoyle_acceptance.environment import Platform
from gargoyle_acceptance.errors import AcceptanceError

EXPECTED_MACHINE_BY_PLATFORM: dict[Platform, int] = {
    "x86": 0x014C,
    "x64": 0x8664,
    "arm64": 0xAA64,
    "arm64ec": 0xA641,
}
EXPECTED_PE_MACHINES_BY_PLATFORM: dict[Platform, tuple[int, ...]] = {
    "x86": (0x014C,),
    "x64": (0x8664,),
    "arm64": (0xAA64,),
    "arm64ec": (0x8664, 0xAA64, 0xA64E, 0xA641),
}
MACHINE_NAMES: dict[int, str] = {
    0x014C: "I386",
    0x8664: "AMD64",
    0xAA64: "ARM64",
    0xA64E: "ARM64X",
    0xA641: "ARM64EC",
}
_DOS_HEADER_MIN_SIZE = 0x40
_PE_OFFSET_OFFSET = 0x3C
_PE_SIGNATURE_SIZE = 4
_COFF_MACHINE_SIZE = 2
_COFF_MACHINE_OFFSET = _PE_SIGNATURE_SIZE
_PE_HEADER_MIN_SIZE = _PE_SIGNATURE_SIZE + _COFF_MACHINE_SIZE


@dataclass(frozen=True, slots=True)
class PEMachine:
    """PE/COFF machine evidence parsed from an executable.

    Attributes:
        value: Numeric IMAGE_FILE_MACHINE value.
        name: Friendly machine name.
    """

    value: int
    name: str


def read_pe_machine(executable: Path) -> PEMachine:
    """Read the COFF machine value from a PE executable.

    Args:
        executable: PE image path.

    Returns:
        Parsed PE machine evidence.

    Raises:
        AcceptanceError: If the file cannot be read or is not a valid PE image.
    """
    try:
        with executable.open("rb") as stream:
            mz_header = stream.read(_DOS_HEADER_MIN_SIZE)
            if len(mz_header) < _DOS_HEADER_MIN_SIZE or mz_header[:2] != b"MZ":
                raise AcceptanceError(
                    "Invalid PE image",
                    _pe_format_detail(executable, "missing DOS MZ header"),
                    "Rebuild the executable before running acceptance validation.",
                )
            pe_offset = struct.unpack_from("<I", mz_header, _PE_OFFSET_OFFSET)[0]
            stream.seek(pe_offset)
            pe_header = stream.read(_PE_HEADER_MIN_SIZE)
    except OSError as exc:
        raise AcceptanceError(
            "PE machine read failed",
            f"Could not read {executable}: {exc}",
            "Build the executable first or pass the expected output directory.",
        ) from exc

    if len(pe_header) < _PE_HEADER_MIN_SIZE or pe_header[:_PE_SIGNATURE_SIZE] != b"PE\0\0":
        raise AcceptanceError(
            "Invalid PE image",
            _pe_format_detail(executable, "missing PE signature"),
            "Rebuild the executable before running acceptance validation.",
        )
    machine = struct.unpack_from("<H", pe_header, _COFF_MACHINE_OFFSET)[0]
    return PEMachine(value=machine, name=machine_name(machine))


def validate_pe_machine(executable: Path, platform: Platform) -> PEMachine:
    """Require an executable's PE machine to match the requested platform.

    Args:
        executable: PE image path.
        platform: Expected Gargoyle platform.

    Returns:
        Parsed PE machine evidence.

    Raises:
        AcceptanceError: If the image machine does not match the platform.
    """
    machine = read_pe_machine(executable)
    if not machine_matches_platform(machine.value, platform):
        raise AcceptanceError(
            "PE machine mismatch",
            (
                f"{executable} is {machine.name} (0x{machine.value:04X}), "
                f"expected {expected_machine_names(platform)} for {platform}."
            ),
            "Confirm the selected --platform matches the native build output.",
        )
    return machine


def machine_name(machine: int) -> str:
    """Return a friendly PE machine name.

    Args:
        machine: Numeric IMAGE_FILE_MACHINE value.

    Returns:
        Known PE machine name or a hexadecimal fallback.
    """
    return MACHINE_NAMES.get(machine, f"UNKNOWN_0x{machine:04X}")


def platform_for_machine(machine: int) -> Platform | None:
    """Return the canonical platform for a PE machine value.

    Args:
        machine: Numeric IMAGE_FILE_MACHINE value.

    Returns:
        Matching platform, or `None` for an unknown machine.
    """
    for platform, expected_machines in EXPECTED_PE_MACHINES_BY_PLATFORM.items():
        if machine in expected_machines:
            return platform
    return None


def machine_matches_platform(machine: int, platform: Platform) -> bool:
    """Return whether a PE machine value is compatible with a platform.

    Args:
        machine: Numeric IMAGE_FILE_MACHINE value.
        platform: Expected Gargoyle platform.

    Returns:
        `True` when the machine can represent the platform's final image.
    """
    return machine in EXPECTED_PE_MACHINES_BY_PLATFORM[platform]


def expected_machine_names(platform: Platform) -> str:
    """Return a friendly list of expected PE machine names.

    Args:
        platform: Expected Gargoyle platform.

    Returns:
        Human-readable PE machine list.
    """
    return ", ".join(
        f"{machine_name(machine)} (0x{machine:04X})"
        for machine in EXPECTED_PE_MACHINES_BY_PLATFORM[platform]
    )


def _pe_format_detail(executable: Path, problem: str) -> str:
    """Create a consistent PE format detail.

    Args:
        executable: PE image path.
        problem: Short format problem.

    Returns:
        Error detail describing the invalid PE file.
    """
    return f"{executable} is not a valid PE image: {problem}."
