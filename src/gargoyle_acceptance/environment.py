"""Environment and artifact discovery for Gargoyle acceptance checks."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from gargoyle_acceptance.errors import AcceptanceError

Configuration = Literal["Debug", "Release"]
VALID_CONFIGURATIONS: tuple[Configuration, ...] = ("Debug", "Release")


@dataclass(frozen=True, slots=True)
class GargoyleArtifacts:
    """Paths produced by a Gargoyle Win32 build.

    Attributes:
        repo_root: Repository root containing `Gargoyle.sln`.
        configuration: Visual Studio configuration name.
        output_dir: Directory containing the executable and PIC blobs.
        executable: Built `Gargoyle.exe`.
        setup_pic: Built `setup.pic`.
        gadget_pic: Built `gadget.pic`.
    """

    repo_root: Path
    configuration: Configuration
    output_dir: Path
    executable: Path
    setup_pic: Path
    gadget_pic: Path


@dataclass(frozen=True, slots=True)
class Toolchain:
    """Resolved external tools needed for the one-click acceptance path.

    Attributes:
        msbuild: Path to MSBuild.
        nasm: Path to NASM.
    """

    msbuild: Path
    nasm: Path


def parse_configuration(value: str) -> Configuration:
    """Normalize a Visual Studio configuration option.

    Args:
        value: User-provided configuration name.

    Returns:
        A supported configuration literal.

    Raises:
        AcceptanceError: If the configuration is not supported.
    """
    normalized = value.strip()
    for configuration in VALID_CONFIGURATIONS:
        if normalized.lower() == configuration.lower():
            return configuration
    raise AcceptanceError(
        "Unsupported configuration",
        f"Expected one of {', '.join(VALID_CONFIGURATIONS)}, got {value!r}.",
        "Use --configuration Debug or --configuration Release.",
    )


def require_windows(system_name: str | None = None) -> None:
    """Require the current platform to be Windows.

    Args:
        system_name: Optional platform override for tests.

    Raises:
        AcceptanceError: If the platform is not Windows.
    """
    detected = system_name or platform.system()
    if detected != "Windows":
        raise AcceptanceError(
            "Windows required",
            f"Detected {detected!r}, but Gargoyle acceptance launches a Win32 executable.",
            "Run this harness from a Windows desktop session.",
        )


def resolve_repo_root(start: Path | None = None) -> Path:
    """Find the repository root by walking upward from a path.

    Args:
        start: Directory or file path to start from. Defaults to the current directory.

    Returns:
        The directory containing the Gargoyle solution and project files.

    Raises:
        AcceptanceError: If the root cannot be found.
    """
    candidate = (start or Path.cwd()).resolve()
    if candidate.is_file():
        candidate = candidate.parent
    for directory in (candidate, *candidate.parents):
        if (directory / "Gargoyle.sln").is_file() and (directory / "Gargoyle.vcxproj").is_file():
            return directory
    raise AcceptanceError(
        "Repository root not found",
        f"Could not find Gargoyle.sln above {candidate}.",
        "Run from the Gargoyle checkout or pass --repo-root.",
    )


def artifacts_for(repo_root: Path, configuration: Configuration) -> GargoyleArtifacts:
    """Compute expected build outputs for a configuration.

    Args:
        repo_root: Repository root.
        configuration: Visual Studio configuration.

    Returns:
        Expected artifact paths.
    """
    output_dir = repo_root / configuration
    return GargoyleArtifacts(
        repo_root=repo_root,
        configuration=configuration,
        output_dir=output_dir,
        executable=output_dir / "Gargoyle.exe",
        setup_pic=output_dir / "setup.pic",
        gadget_pic=output_dir / "gadget.pic",
    )


def verify_artifacts(artifacts: GargoyleArtifacts) -> None:
    """Require the executable and PIC blobs to exist.

    Args:
        artifacts: Expected build outputs.

    Raises:
        AcceptanceError: If any expected artifact is missing.
    """
    missing = [
        path
        for path in (artifacts.executable, artifacts.setup_pic, artifacts.gadget_pic)
        if not path.is_file()
    ]
    if missing:
        formatted = "\n".join(f"- {path}" for path in missing)
        raise AcceptanceError(
            "Build artifacts missing",
            f"The {artifacts.configuration}|x86 output is incomplete:\n{formatted}",
            "Build the configuration first or run without --skip-build.",
        )


def resolve_msbuild(explicit: Path | None = None) -> Path:
    """Resolve MSBuild from an explicit path, PATH, or common Visual Studio installs.

    Args:
        explicit: Optional user-provided MSBuild path.

    Returns:
        Path to MSBuild.

    Raises:
        AcceptanceError: If MSBuild cannot be found.
    """
    if explicit is not None:
        resolved = explicit.expanduser().resolve()
        if resolved.is_file():
            return resolved
        raise AcceptanceError(
            "MSBuild not found",
            f"The --msbuild path does not exist: {resolved}",
            "Pass the full path to MSBuild.exe.",
        )

    from_path = shutil.which("msbuild")
    if from_path:
        return Path(from_path).resolve()

    for candidate in _msbuild_candidates():
        if candidate.is_file():
            return candidate

    vswhere = _vswhere_path()
    if vswhere and vswhere.is_file():
        discovered = _msbuild_from_vswhere(vswhere)
        if discovered:
            return discovered

    raise AcceptanceError(
        "MSBuild not found",
        "Could not find MSBuild on PATH or under the common Visual Studio install paths.",
        "Install Visual Studio C++ tools or pass --msbuild C:\\path\\to\\MSBuild.exe.",
    )


def resolve_nasm() -> Path:
    """Resolve NASM from PATH or the standard winget install directory.

    Returns:
        Path to `nasm.exe`.

    Raises:
        AcceptanceError: If NASM cannot be found.
    """
    from_path = shutil.which("nasm")
    if from_path:
        return Path(from_path).resolve()
    winget_install = Path.home() / "AppData" / "Local" / "bin" / "NASM" / "nasm.exe"
    if winget_install.is_file():
        return winget_install
    raise AcceptanceError(
        "NASM not found",
        "nasm.exe is not available on PATH or in the standard winget install directory.",
        (
            "Install it with: winget install --id NASM.NASM --source winget "
            "--accept-package-agreements --accept-source-agreements"
        ),
    )


def resolve_toolchain(msbuild: Path | None = None) -> Toolchain:
    """Resolve all external build tools.

    Args:
        msbuild: Optional explicit MSBuild path.

    Returns:
        Resolved toolchain paths.
    """
    return Toolchain(msbuild=resolve_msbuild(msbuild), nasm=resolve_nasm())


def _msbuild_candidates() -> tuple[Path, ...]:
    """Return common MSBuild install paths for current Visual Studio releases.

    Returns:
        Candidate `MSBuild.exe` paths.
    """
    program_files = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
    program_files_x86 = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
    versions = ("18", "2022", "2019")
    editions = ("Community", "Professional", "Enterprise", "BuildTools")
    candidates: list[Path] = []
    for base in (program_files, program_files_x86):
        for version in versions:
            for edition in editions:
                candidates.append(
                    base
                    / "Microsoft Visual Studio"
                    / version
                    / edition
                    / "MSBuild"
                    / "Current"
                    / "Bin"
                    / "MSBuild.exe"
                )
    return tuple(candidates)


def _vswhere_path() -> Path | None:
    """Find `vswhere.exe` if Visual Studio installed it.

    Returns:
        Path to `vswhere.exe`, or `None`.
    """
    for base in (
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")),
    ):
        candidate = base / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
        if candidate.is_file():
            return candidate
    return None


def _msbuild_from_vswhere(vswhere: Path) -> Path | None:
    """Ask `vswhere.exe` for the latest MSBuild-capable Visual Studio install.

    Args:
        vswhere: Path to `vswhere.exe`.

    Returns:
        Path to `MSBuild.exe`, or `None`.
    """
    try:
        install = subprocess.check_output(
            [
                str(vswhere),
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.Component.MSBuild",
                "-property",
                "installationPath",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    if not install:
        return None
    candidate = Path(install) / "MSBuild" / "Current" / "Bin" / "MSBuild.exe"
    return candidate if candidate.is_file() else None


def coerce_optional_path(value: Path | None) -> Path | None:
    """Convert Typer's optional path value into a resolved path when present.

    Args:
        value: Optional CLI path.

    Returns:
        A resolved path or `None`.
    """
    if value is None:
        return None
    return value.expanduser().resolve()
