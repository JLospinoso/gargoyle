"""Unit tests for MSBuild integration."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from gargoyle_acceptance import build
from gargoyle_acceptance.environment import Toolchain
from gargoyle_acceptance.errors import AcceptanceError


def test_build_solution_uses_expected_msbuild_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The build command stays narrow: configuration, platform, and parallel build."""
    seen: dict[str, object] = {}

    def fake_run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen["command"] = command
        seen["cwd"] = kwargs["cwd"]
        return subprocess.CompletedProcess(command, 0, stdout="Build succeeded.")

    monkeypatch.setattr(build.subprocess, "run", fake_run)
    toolchain = Toolchain(msbuild=Path("MSBuild.exe"), nasm=Path("nasm.exe"))

    result = build.build_solution(tmp_path, "Debug", "x86", toolchain)

    assert result.command == (
        "MSBuild.exe",
        "Gargoyle.sln",
        "/p:Configuration=Debug",
        "/p:Platform=x86",
        "/m",
    )
    assert seen["cwd"] == tmp_path
    assert "Build succeeded" in result.output


def test_build_environment_prepends_nasm_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    """MSBuild receives a PATH where the resolved NASM directory comes first."""
    monkeypatch.setattr(build, "environ", {"PATH": "existing"})
    monkeypatch.setattr(build, "pathsep", ";")
    toolchain = Toolchain(msbuild=Path("MSBuild.exe"), nasm=Path("C:/Tools/NASM/nasm.exe"))

    env = build._build_environment(toolchain)

    assert env["PATH"] == "C:\\Tools\\NASM;existing"


def test_build_solution_raises_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MSBuild failures become actionable acceptance errors."""

    def fake_run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="fatal build problem")

    monkeypatch.setattr(build.subprocess, "run", fake_run)
    toolchain = Toolchain(msbuild=Path("MSBuild.exe"), nasm=Path("nasm.exe"))

    with pytest.raises(AcceptanceError, match="Build failed"):
        build.build_solution(tmp_path, "Release", "x64", toolchain)


def test_build_solution_raises_on_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MSBuild timeouts become actionable acceptance errors."""

    def fake_run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, timeout=1)

    monkeypatch.setattr(build.subprocess, "run", fake_run)
    toolchain = Toolchain(msbuild=Path("MSBuild.exe"), nasm=Path("nasm.exe"))

    with pytest.raises(AcceptanceError, match="Build timed out"):
        build.build_solution(tmp_path, "Debug", "x86", toolchain, timeout_seconds=1)
