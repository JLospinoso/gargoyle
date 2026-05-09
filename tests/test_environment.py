"""Unit tests for environment discovery helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

import gargoyle_acceptance.environment as env
from gargoyle_acceptance.environment import (
    artifacts_for,
    coerce_optional_path,
    parse_configuration,
    parse_platform,
    require_windows,
    resolve_msbuild,
    resolve_nasm,
    resolve_repo_root,
    resolve_toolchain,
    verify_artifacts,
)
from gargoyle_acceptance.errors import AcceptanceError


def test_parse_configuration_accepts_supported_values() -> None:
    """Configuration parsing accepts the two supported Visual Studio names."""
    assert parse_configuration("Debug") == "Debug"
    assert parse_configuration("release") == "Release"


def test_parse_configuration_rejects_unknown_value() -> None:
    """Configuration parsing gives a clear error for unsupported names."""
    with pytest.raises(AcceptanceError, match="Unsupported configuration"):
        parse_configuration("x64")


def test_parse_platform_accepts_supported_values() -> None:
    """Platform parsing accepts the two supported Visual Studio solution platforms."""
    assert parse_platform("x86") == "x86"
    assert parse_platform("X64") == "x64"


def test_parse_platform_rejects_unknown_value() -> None:
    """Platform parsing gives a clear error for unsupported names."""
    with pytest.raises(AcceptanceError, match="Unsupported platform"):
        parse_platform("arm64")


def test_require_windows_rejects_non_windows() -> None:
    """Platform validation rejects non-Windows systems."""
    with pytest.raises(AcceptanceError, match="Windows required"):
        require_windows("Linux")


def test_require_windows_accepts_windows() -> None:
    """Platform validation accepts Windows."""
    require_windows("Windows")


def test_resolve_repo_root_walks_upward(tmp_path: Path) -> None:
    """Repository root discovery walks up from nested directories."""
    (tmp_path / "Gargoyle.sln").write_text("")
    (tmp_path / "Gargoyle.vcxproj").write_text("")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)

    assert resolve_repo_root(nested) == tmp_path


def test_resolve_repo_root_accepts_file_start(tmp_path: Path) -> None:
    """Repository root discovery accepts a file path as the start point."""
    (tmp_path / "Gargoyle.sln").write_text("")
    (tmp_path / "Gargoyle.vcxproj").write_text("")
    source = tmp_path / "main.cpp"
    source.write_text("")

    assert resolve_repo_root(source) == tmp_path


def test_resolve_repo_root_fails_with_hint(tmp_path: Path) -> None:
    """Repository root discovery reports a missing checkout clearly."""
    with pytest.raises(AcceptanceError, match="Repository root not found"):
        resolve_repo_root(tmp_path)


def test_verify_artifacts_reports_missing_files(tmp_path: Path) -> None:
    """Artifact validation identifies incomplete build outputs."""
    artifacts = artifacts_for(tmp_path, "Debug")

    with pytest.raises(AcceptanceError, match="Build artifacts missing"):
        verify_artifacts(artifacts)


def test_verify_artifacts_accepts_complete_outputs(tmp_path: Path) -> None:
    """Artifact validation accepts the expected executable and PIC blobs."""
    artifacts = artifacts_for(tmp_path, "Release")
    artifacts.output_dir.mkdir()
    artifacts.executable.write_text("")
    artifacts.setup_pic.write_text("")
    artifacts.gadget_pic.write_text("")

    verify_artifacts(artifacts)


def test_artifacts_for_uses_configuration_output_directory(tmp_path: Path) -> None:
    """Artifact paths match the Visual Studio output directory convention."""
    artifacts = artifacts_for(tmp_path, "Debug")

    assert artifacts.output_dir == tmp_path / "Debug"
    assert artifacts.platform == "x86"
    assert artifacts.executable == tmp_path / "Debug" / "Gargoyle.exe"


def test_artifacts_for_uses_x64_default_output_directory(tmp_path: Path) -> None:
    """x64 artifact paths match the root solution's Visual Studio default output."""
    artifacts = artifacts_for(tmp_path, "Release", "x64")

    assert artifacts.output_dir == tmp_path / "x64" / "Release"
    assert artifacts.platform == "x64"
    assert artifacts.executable == tmp_path / "x64" / "Release" / "GargoyleX64.exe"
    assert artifacts.setup_pic == tmp_path / "x64" / "Release" / "setup_x64.pic"
    assert artifacts.reentry_pic == tmp_path / "x64" / "Release" / "reentry_x64.pic"


def test_artifacts_for_selects_existing_candidate(tmp_path: Path) -> None:
    """Artifact discovery accepts an alternate VS output candidate when files exist there."""
    output_dir = tmp_path / "GargoyleX64" / "Debug"
    output_dir.mkdir(parents=True)
    (output_dir / "GargoyleX64.exe").write_text("")
    (output_dir / "setup_x64.pic").write_text("")
    (output_dir / "reentry_x64.pic").write_text("")

    artifacts = artifacts_for(tmp_path, "Debug", "x64")

    assert artifacts.output_dir == output_dir


def test_resolve_msbuild_accepts_explicit_path(tmp_path: Path) -> None:
    """MSBuild resolution accepts an explicit executable path."""
    msbuild = tmp_path / "MSBuild.exe"
    msbuild.write_text("")

    assert resolve_msbuild(msbuild) == msbuild


def test_resolve_msbuild_rejects_bad_explicit_path(tmp_path: Path) -> None:
    """MSBuild resolution reports a bad explicit path."""
    with pytest.raises(AcceptanceError, match="MSBuild not found"):
        resolve_msbuild(tmp_path / "missing.exe")


def test_resolve_msbuild_uses_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """MSBuild resolution checks PATH before common install locations."""
    msbuild = tmp_path / "MSBuild.exe"
    msbuild.write_text("")
    monkeypatch.setattr(
        env.shutil, "which", lambda name: str(msbuild) if name == "msbuild" else None
    )

    assert resolve_msbuild() == msbuild


def test_resolve_msbuild_uses_common_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """MSBuild resolution checks common Visual Studio paths."""
    msbuild = tmp_path / "MSBuild.exe"
    msbuild.write_text("")
    monkeypatch.setattr(env.shutil, "which", lambda _name: None)
    monkeypatch.setattr(env, "_msbuild_candidates", lambda: (msbuild,))

    assert resolve_msbuild() == msbuild


def test_resolve_msbuild_uses_vswhere(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """MSBuild resolution falls back to vswhere."""
    vswhere = tmp_path / "vswhere.exe"
    vswhere.write_text("")
    msbuild = tmp_path / "MSBuild.exe"
    msbuild.write_text("")
    monkeypatch.setattr(env.shutil, "which", lambda _name: None)
    monkeypatch.setattr(env, "_msbuild_candidates", lambda: ())
    monkeypatch.setattr(env, "_vswhere_path", lambda: vswhere)
    monkeypatch.setattr(env, "_msbuild_from_vswhere", lambda value: msbuild)

    assert resolve_msbuild() == msbuild


def test_resolve_msbuild_reports_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """MSBuild resolution reports a fully missing toolchain."""
    monkeypatch.setattr(env.shutil, "which", lambda _name: None)
    monkeypatch.setattr(env, "_msbuild_candidates", lambda: ())
    monkeypatch.setattr(env, "_vswhere_path", lambda: None)

    with pytest.raises(AcceptanceError, match="MSBuild not found"):
        resolve_msbuild()


def test_resolve_nasm_uses_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """NASM resolution checks PATH."""
    nasm = tmp_path / "nasm.exe"
    nasm.write_text("")
    monkeypatch.setattr(env.shutil, "which", lambda name: str(nasm) if name == "nasm" else None)

    assert resolve_nasm() == nasm


def test_resolve_nasm_uses_winget_install_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """NASM resolution checks the standard winget install location."""
    nasm = tmp_path / "AppData" / "Local" / "bin" / "NASM" / "nasm.exe"
    nasm.parent.mkdir(parents=True)
    nasm.write_text("")
    monkeypatch.setattr(env.shutil, "which", lambda _name: None)
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)

    assert resolve_nasm() == nasm


def test_resolve_nasm_reports_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """NASM resolution reports a missing assembler clearly."""
    monkeypatch.setattr(env.shutil, "which", lambda _name: None)
    monkeypatch.setattr(env.Path, "home", lambda: tmp_path)

    with pytest.raises(AcceptanceError, match="NASM not found"):
        resolve_nasm()


def test_resolve_toolchain_combines_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Toolchain resolution returns both MSBuild and NASM."""
    msbuild = tmp_path / "MSBuild.exe"
    nasm = tmp_path / "nasm.exe"
    msbuild.write_text("")
    nasm.write_text("")
    monkeypatch.setattr(env, "resolve_msbuild", lambda value=None: msbuild)
    monkeypatch.setattr(env, "resolve_nasm", lambda: nasm)

    toolchain = resolve_toolchain()

    assert toolchain.msbuild == msbuild
    assert toolchain.nasm == nasm


def test_coerce_optional_path(tmp_path: Path) -> None:
    """Optional Typer paths are resolved only when present."""
    assert coerce_optional_path(None) is None
    assert coerce_optional_path(tmp_path) == tmp_path.resolve()


def test_msbuild_candidates_uses_program_files_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Common MSBuild candidates are generated from Program Files environment values."""
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "PF"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "PFX86"))

    candidates = env._msbuild_candidates()

    assert candidates
    assert candidates[0].parts[-4:] == ("MSBuild", "Current", "Bin", "MSBuild.exe")


def test_vswhere_path_finds_installer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """vswhere discovery checks common Visual Studio installer locations."""
    installer = tmp_path / "PF" / "Microsoft Visual Studio" / "Installer"
    installer.mkdir(parents=True)
    vswhere = installer / "vswhere.exe"
    vswhere.write_text("")
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "PF"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "missing"))

    assert env._vswhere_path() == vswhere


def test_msbuild_from_vswhere_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """vswhere output is converted into an MSBuild path."""
    install = tmp_path / "VS"
    msbuild = install / "MSBuild" / "Current" / "Bin" / "MSBuild.exe"
    msbuild.parent.mkdir(parents=True)
    msbuild.write_text("")
    monkeypatch.setattr(env.subprocess, "check_output", lambda *args, **kwargs: str(install))

    assert env._msbuild_from_vswhere(tmp_path / "vswhere.exe") == msbuild


def test_msbuild_from_vswhere_empty_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Empty vswhere output is treated as no discovery."""
    monkeypatch.setattr(env.subprocess, "check_output", lambda *args, **kwargs: "")

    assert env._msbuild_from_vswhere(tmp_path / "vswhere.exe") is None


def test_msbuild_from_vswhere_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """vswhere execution errors are treated as no discovery."""

    def fail(*_args: object, **_kwargs: object) -> str:
        raise OSError("nope")

    monkeypatch.setattr(env.subprocess, "check_output", fail)

    assert env._msbuild_from_vswhere(tmp_path / "vswhere.exe") is None
