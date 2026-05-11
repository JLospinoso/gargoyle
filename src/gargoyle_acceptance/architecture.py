"""Architecture report parsing for headless Gargoyle acceptance checks."""

from __future__ import annotations

import re
from dataclasses import dataclass

from gargoyle_acceptance.environment import Platform, parse_platform, platform_pointer_bits
from gargoyle_acceptance.errors import AcceptanceError
from gargoyle_acceptance.pe import (
    EXPECTED_MACHINE_BY_PLATFORM,
    expected_machine_names,
    machine_matches_platform,
    machine_name,
    platform_for_machine,
)

_FIELD_PATTERN = re.compile(
    r"^\s*(?:\[[^\]]+\]\s*)?(?P<key>[A-Za-z0-9 _.-]+)\s*[:=]\s*(?P<value>.+?)\s*$"
)
_MACHINE_KEYS = {
    "machine",
    "pemachine",
    "pe machine",
    "image machine",
    "imagefilemachine",
    "image file machine",
}
_PLATFORM_KEYS = {"platform", "architecture", "arch", "target", "solution platform"}
_POINTER_BITS_KEYS = {"pointerbits", "pointer bits", "pointer size", "pointersize", "bits"}


@dataclass(frozen=True, slots=True)
class ArchitectureReport:
    """Architecture evidence emitted by a Gargoyle headless smoke command.

    Attributes:
        platform: Canonical platform reported by the executable.
        machine: Numeric IMAGE_FILE_MACHINE value reported by the executable.
        machine_name: Friendly machine name.
        pointer_bits: Native pointer width in bits.
        fields: Normalized raw report fields.
    """

    platform: Platform
    machine: int
    machine_name: str
    pointer_bits: int
    fields: tuple[tuple[str, str], ...]


def parse_architecture_report(
    lines: list[str] | tuple[str, ...],
    expected_platform: Platform | None = None,
) -> ArchitectureReport:
    """Parse a text architecture report.

    Args:
        lines: Captured report lines.
        expected_platform: Optional platform to use when the report omits a platform field.

    Returns:
        Parsed architecture report.

    Raises:
        AcceptanceError: If required architecture evidence is missing or malformed.
    """
    fields = _parse_fields(lines)
    platform_value = _first_field(fields, _PLATFORM_KEYS)
    machine_value = _first_field(fields, _MACHINE_KEYS)
    pointer_bits_value = _first_field(fields, _POINTER_BITS_KEYS)

    machine = _parse_machine(machine_value) if machine_value is not None else None
    if machine_value is not None and machine is None:
        raise AcceptanceError(
            "Architecture report invalid",
            f"PE machine was not recognized: {machine_value!r}.",
            "Emit machine=I386, AMD64, ARM64, ARM64EC, or the matching hexadecimal value.",
        )
    platform = _parse_platform_field(platform_value) if platform_value is not None else None
    if platform is None and machine is not None:
        platform = platform_for_machine(machine)
    if platform is None:
        platform = expected_platform
    if platform is None:
        raise AcceptanceError(
            "Architecture report incomplete",
            "The report did not include a supported platform or PE machine.",
            "Emit lines such as 'platform=arm64' and 'machine=ARM64'.",
        )
    if machine is None:
        machine = EXPECTED_MACHINE_BY_PLATFORM[platform]
    pointer_bits = (
        _parse_pointer_bits(pointer_bits_value)
        if pointer_bits_value is not None
        else platform_pointer_bits(platform)
    )
    return ArchitectureReport(
        platform=platform,
        machine=machine,
        machine_name=machine_name(machine),
        pointer_bits=pointer_bits,
        fields=tuple(sorted(fields.items())),
    )


def validate_architecture_report(
    report: ArchitectureReport,
    expected_platform: Platform,
) -> ArchitectureReport:
    """Require an architecture report to match the requested platform.

    Args:
        report: Parsed architecture report.
        expected_platform: Expected Gargoyle platform.

    Returns:
        The validated report.

    Raises:
        AcceptanceError: If the report does not match the requested platform.
    """
    expected_pointer_bits = platform_pointer_bits(expected_platform)
    problems = []
    if report.platform != expected_platform:
        problems.append(f"platform {report.platform!r} != {expected_platform!r}")
    if not machine_matches_platform(report.machine, expected_platform):
        problems.append(
            f"machine {report.machine_name} (0x{report.machine:04X}) "
            f"not in {expected_machine_names(expected_platform)}"
        )
    if report.pointer_bits != expected_pointer_bits:
        problems.append(f"pointer bits {report.pointer_bits} != {expected_pointer_bits}")
    if problems:
        raise AcceptanceError(
            "Architecture report mismatch",
            "; ".join(problems),
            "Confirm the executable and --platform argument describe the same native target.",
        )
    return report


def architecture_report_complete(
    lines: list[str] | tuple[str, ...],
    expected_platform: Platform | None = None,
) -> bool:
    """Return whether captured lines contain a usable architecture report.

    Args:
        lines: Captured report lines.
        expected_platform: Optional expected platform.

    Returns:
        `True` when the report parses and validates successfully.
    """
    try:
        report = parse_architecture_report(lines, expected_platform)
        if expected_platform is not None:
            validate_architecture_report(report, expected_platform)
    except AcceptanceError:
        return False
    return True


def _parse_fields(lines: list[str] | tuple[str, ...]) -> dict[str, str]:
    """Parse key-value fields from report lines.

    Args:
        lines: Captured report lines.

    Returns:
        Normalized report fields.
    """
    fields: dict[str, str] = {}
    for line in lines:
        match = _FIELD_PATTERN.match(line)
        if match is None:
            continue
        fields[_normalize_key(match.group("key"))] = match.group("value").strip()
    return fields


def _first_field(fields: dict[str, str], keys: set[str]) -> str | None:
    """Return the first matching field value.

    Args:
        fields: Normalized report fields.
        keys: Accepted normalized keys.

    Returns:
        Matching field value, or `None`.
    """
    for key in keys:
        if key in fields:
            return fields[key]
    return None


def _normalize_key(value: str) -> str:
    """Normalize a report key for loose matching.

    Args:
        value: Raw report key.

    Returns:
        Lowercase key with common separators collapsed.
    """
    return re.sub(r"[\s_.-]+", " ", value.strip().lower()).strip()


def _parse_platform_field(value: str) -> Platform | None:
    """Parse a platform field.

    Args:
        value: Raw field value.

    Returns:
        Parsed platform, or `None` when unsupported.
    """
    try:
        return parse_platform(value)
    except AcceptanceError:
        return None


def _parse_machine(value: str) -> int | None:
    """Parse a PE machine token.

    Args:
        value: Raw machine token.

    Returns:
        Numeric machine value, or `None` when unsupported.
    """
    token = value.strip().upper()
    token = token.removeprefix("IMAGE_FILE_MACHINE_")
    if token.startswith("0X"):
        try:
            return int(token, 16)
        except ValueError:
            return None
    if re.fullmatch(r"[0-9A-F]{3,4}", token):
        return int(token, 16)
    for machine, name in (
        (0x014C, "I386"),
        (0x014C, "X86"),
        (0x8664, "AMD64"),
        (0x8664, "X64"),
        (0xAA64, "ARM64"),
        (0xA64E, "ARM64X"),
        (0xA641, "ARM64EC"),
    ):
        if token == name:
            return machine
    return None


def _parse_pointer_bits(value: str) -> int:
    """Parse a pointer-size field.

    Args:
        value: Raw pointer-size token.

    Returns:
        Pointer width in bits.

    Raises:
        AcceptanceError: If the pointer-size token is not an integer.
    """
    token = value.strip().lower().removesuffix("bits").removesuffix("bit").strip()
    try:
        return int(token)
    except ValueError as exc:
        raise AcceptanceError(
            "Architecture report invalid",
            f"Pointer width was not an integer: {value!r}.",
            "Emit pointer_bits=32 or pointer_bits=64.",
        ) from exc
