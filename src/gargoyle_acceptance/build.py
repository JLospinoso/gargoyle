"""MSBuild integration for the Gargoyle acceptance harness."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from os import environ, pathsep
from pathlib import Path

from gargoyle_acceptance.environment import Configuration, Platform, Toolchain
from gargoyle_acceptance.errors import AcceptanceError


@dataclass(frozen=True, slots=True)
class BuildResult:
    """Captured result from building Gargoyle.

    Attributes:
        command: Command line used to invoke MSBuild.
        output: Combined stdout and stderr from MSBuild.
    """

    command: tuple[str, ...]
    output: str


def build_solution(
    repo_root: Path,
    configuration: Configuration,
    platform: Platform,
    toolchain: Toolchain,
    *,
    timeout_seconds: float = 120.0,
) -> BuildResult:
    """Build `Gargoyle.sln` for the requested configuration.

    Args:
        repo_root: Repository root containing `Gargoyle.sln`.
        configuration: Visual Studio configuration to build.
        platform: Visual Studio solution platform to build.
        toolchain: Resolved toolchain paths.
        timeout_seconds: Maximum time allowed for MSBuild.

    Returns:
        Captured MSBuild output.

    Raises:
        AcceptanceError: If MSBuild fails or times out.
    """
    command = (
        str(toolchain.msbuild),
        "Gargoyle.sln",
        f"/p:Configuration={configuration}",
        f"/p:Platform={platform}",
        "/m",
    )
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=_build_environment(toolchain),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcceptanceError(
            "Build timed out",
            f"MSBuild did not finish within {timeout_seconds:.0f} seconds.",
            f"Command: {' '.join(command)}",
        ) from exc
    output = completed.stdout or ""
    if completed.returncode != 0:
        raise AcceptanceError(
            "Build failed",
            f"MSBuild exited with code {completed.returncode}.\n{_tail(output)}",
            "Fix the build error above, then rerun the acceptance harness.",
        )
    return BuildResult(command=command, output=output)


def _build_environment(toolchain: Toolchain) -> dict[str, str]:
    """Build an environment where MSBuild can find NASM.

    Args:
        toolchain: Resolved toolchain paths.

    Returns:
        Environment variables for the MSBuild subprocess.
    """
    env = dict(environ)
    path = env.get("PATH", "")
    nasm_dir = str(toolchain.nasm.parent)
    env["PATH"] = nasm_dir + pathsep + path if path else nasm_dir
    return env


def _tail(text: str, *, lines: int = 30) -> str:
    """Return a compact tail of command output.

    Args:
        text: Complete command output.
        lines: Number of trailing lines to keep.

    Returns:
        The trailing output lines.
    """
    return "\n".join(text.splitlines()[-lines:])
