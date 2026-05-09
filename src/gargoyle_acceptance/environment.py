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
Platform = Literal["x86", "x64"]
VALID_PLATFORMS: tuple[Platform, ...] = ("x86", "x64")


@dataclass(frozen=True, slots=True)
class GargoyleArtifacts:
    """Paths produced by a Gargoyle native build.

    Attributes:
        repo_root: Repository root containing `Gargoyle.sln`.
        configuration: Visual Studio configuration name.
        platform: Visual Studio solution platform.
        output_dir: Directory containing the executable and PIC blobs.
        executable: Built executable.
        setup_pic: Built setup PIC.
        gadget_pic: Optional Win32 stack-pivot gadget PIC.
        reentry_pic: Optional x64 wait/re-entry PIC.
    """

    repo_root: Path
    configuration: Configuration
    platform: Platform
    output_dir: Path
    executable: Path
    setup_pic: Path
    gadget_pic: Path | None = None
    reentry_pic: Path | None = None


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


def parse_platform(value: str) -> Platform:
    """Normalize a Visual Studio solution platform option.

    Args:
        value: User-provided platform name.

    Returns:
        A supported platform literal.

    Raises:
        AcceptanceError: If the platform is not supported.
    """
    normalized = value.strip()
    for platform_name in VALID_PLATFORMS:
        if normalized.lower() == platform_name.lower():
            return platform_name
    raise AcceptanceError(
        "Unsupported platform",
        f"Expected one of {', '.join(VALID_PLATFORMS)}, got {value!r}.",
        "Use --platform x86 or --platform x64.",
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


def artifacts_for(
    repo_root: Path,
    configuration: Configuration,
    platform_name: Platform = "x86",
) -> GargoyleArtifacts:
    """Compute expected build outputs for a configuration.

    Args:
        repo_root: Repository root.
        configuration: Visual Studio configuration.
        platform_name: Visual Studio solution platform.

    Returns:
        Expected artifact paths.
    """
    candidates = _artifact_candidates(repo_root, configuration, platform_name)
    for candidate in candidates:
        if all(path.is_file() for path in _required_artifact_paths(candidate)):
            return candidate
    return candidates[0]


def verify_artifacts(artifacts: GargoyleArtifacts) -> None:
    """Require the executable and PIC blobs to exist.

    Args:
        artifacts: Expected build outputs.

    Raises:
        AcceptanceError: If any expected artifact is missing.
    """
    missing = [path for path in _required_artifact_paths(artifacts) if not path.is_file()]
    if missing:
        formatted = "\n".join(f"- {path}" for path in missing)
        raise AcceptanceError(
            "Build artifacts missing",
            (
                f"The {artifacts.configuration}|{artifacts.platform} output is incomplete:\n"
                f"{formatted}"
            ),
            "Build the configuration first or run without --skip-build.",
        )


def _artifact_candidates(
    repo_root: Path,
    configuration: Configuration,
    platform_name: Platform,
) -> tuple[GargoyleArtifacts, ...]:
    """Return likely Visual Studio output locations.

    Args:
        repo_root: Repository root.
        configuration: Visual Studio configuration.
        platform_name: Visual Studio solution platform.

    Returns:
        Candidate artifact layouts in preference order.
    """
    if platform_name == "x86":
        return (
            _x86_artifacts(repo_root, configuration, repo_root / configuration),
            _x86_artifacts(repo_root, configuration, repo_root / "Win32" / configuration),
            _x86_artifacts(repo_root, configuration, repo_root / "x86" / configuration),
        )
    return (
        _x64_artifacts(repo_root, configuration, repo_root / "x64" / configuration),
        _x64_artifacts(repo_root, configuration, repo_root / "GargoyleX64" / "x64" / configuration),
        _x64_artifacts(repo_root, configuration, repo_root / "GargoyleX64" / configuration),
    )


def _x86_artifacts(
    repo_root: Path, configuration: Configuration, output_dir: Path
) -> GargoyleArtifacts:
    """Create a Win32 artifact layout.

    Args:
        repo_root: Repository root.
        configuration: Visual Studio configuration.
        output_dir: Candidate output directory.

    Returns:
        Win32 artifact paths.
    """
    return GargoyleArtifacts(
        repo_root=repo_root,
        configuration=configuration,
        platform="x86",
        output_dir=output_dir,
        executable=output_dir / "Gargoyle.exe",
        setup_pic=output_dir / "setup.pic",
        gadget_pic=output_dir / "gadget.pic",
    )


def _x64_artifacts(
    repo_root: Path, configuration: Configuration, output_dir: Path
) -> GargoyleArtifacts:
    """Create an x64 artifact layout.

    Args:
        repo_root: Repository root.
        configuration: Visual Studio configuration.
        output_dir: Candidate output directory.

    Returns:
        x64 artifact paths.
    """
    return GargoyleArtifacts(
        repo_root=repo_root,
        configuration=configuration,
        platform="x64",
        output_dir=output_dir,
        executable=output_dir / "GargoyleX64.exe",
        setup_pic=output_dir / "setup_x64.pic",
        reentry_pic=output_dir / "reentry_x64.pic",
    )


def _required_artifact_paths(artifacts: GargoyleArtifacts) -> tuple[Path, ...]:
    """Return non-optional artifact paths for a build.

    Args:
        artifacts: Candidate artifact layout.

    Returns:
        Required paths.
    """
    paths = [artifacts.executable, artifacts.setup_pic]
    if artifacts.gadget_pic is not None:
        paths.append(artifacts.gadget_pic)
    if artifacts.reentry_pic is not None:
        paths.append(artifacts.reentry_pic)
    return tuple(paths)


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
