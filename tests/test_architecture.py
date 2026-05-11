"""Unit tests for architecture report parsing."""

from __future__ import annotations

import pytest

from gargoyle_acceptance.architecture import (
    architecture_report_complete,
    parse_architecture_report,
    validate_architecture_report,
)
from gargoyle_acceptance.errors import AcceptanceError


def test_parse_architecture_report_accepts_key_value_lines() -> None:
    """Architecture parsing accepts prefixed key-value report lines."""
    report = parse_architecture_report(
        (
            "[architecture] platform=arm64",
            "[architecture] machine=ARM64",
            "[architecture] pointer_bits=64",
        )
    )

    assert report.platform == "arm64"
    assert report.machine == 0xAA64
    assert report.pointer_bits == 64


def test_parse_architecture_report_accepts_hex_machine_and_infers_platform() -> None:
    """Architecture parsing accepts hexadecimal machine values."""
    report = parse_architecture_report(("PE machine: 0xA641",))

    assert report.platform == "arm64ec"
    assert report.machine_name == "ARM64EC"
    assert report.pointer_bits == 64


def test_parse_architecture_report_accepts_arm64x_machine() -> None:
    """Architecture parsing accepts ARM64X report machine values for ARM64EC."""
    report = parse_architecture_report(("PE machine: ARM64X",), expected_platform="arm64ec")

    assert report.platform == "arm64ec"
    assert report.machine_name == "ARM64X"


def test_parse_architecture_report_uses_expected_platform_when_omitted() -> None:
    """Architecture parsing can use the requested platform as fallback context."""
    report = parse_architecture_report(("pointer size: 32",), expected_platform="x86")

    assert report.platform == "x86"
    assert report.machine == 0x014C
    assert report.pointer_bits == 32


def test_parse_architecture_report_rejects_unknown_machine() -> None:
    """Architecture parsing rejects unrecognized machine tokens."""
    with pytest.raises(AcceptanceError, match="PE machine was not recognized"):
        parse_architecture_report(("machine=SPARC",))


def test_parse_architecture_report_rejects_missing_platform_context() -> None:
    """Architecture parsing needs either platform, machine, or expected platform."""
    with pytest.raises(AcceptanceError, match="Architecture report incomplete"):
        parse_architecture_report(("pointer_bits=64",))


def test_validate_architecture_report_rejects_mismatch() -> None:
    """Architecture validation rejects reports for the wrong requested platform."""
    report = parse_architecture_report(("platform=x64", "machine=AMD64", "pointer_bits=64"))

    with pytest.raises(AcceptanceError, match="Architecture report mismatch"):
        validate_architecture_report(report, "arm64")


def test_architecture_report_complete_returns_boolean() -> None:
    """Report completeness helper returns boolean parse status."""
    assert architecture_report_complete(("machine=ARM64EC",), expected_platform="arm64ec")
    assert not architecture_report_complete(("machine=ARM64",), expected_platform="x64")
