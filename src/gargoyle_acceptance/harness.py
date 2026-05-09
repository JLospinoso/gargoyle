"""High-level Gargoyle acceptance runner."""

from __future__ import annotations

import queue
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from gargoyle_acceptance.build import BuildResult, build_solution
from gargoyle_acceptance.environment import (
    Configuration,
    GargoyleArtifacts,
    Platform,
    artifacts_for,
    require_windows,
    resolve_repo_root,
    resolve_toolchain,
    verify_artifacts,
)
from gargoyle_acceptance.errors import AcceptanceError
from gargoyle_acceptance.windows import MessageBoxController

EXPECTED_MARKERS = (
    "[+] Allocated 149 bytes for PIC.",
    "[+] ROP gadget configured.",
    "[+] Stack trampoline built.",
    "[+] Configuration built.",
    "[+] Success!",
)
ADDRESS_LABELS = (
    "Gargoyle PIC",
    "ROP gadget",
    "Configuration",
    "Top of stack",
    "Bottom of stack",
    "Stack trampoline",
)
X64_EXPECTED_MARKERS = (
    "[+] x64 timer/APC prototype configured.",
    "[ ] Entering benign x64 PIC payload loop.",
)
X64_ADDRESS_LABELS = (
    "Gargoyle x64 PIC",
    "x64 re-entry PIC",
    "x64 APC callback",
    "Configuration",
    "VirtualProtectEx",
    "WaitForSingleObjectEx",
    "CreateWaitableTimerW",
    "SetWaitableTimer",
    "MessageBoxA",
)
MESSAGE_BOX_TITLES: dict[Platform, str] = {
    "x86": "gargoyle",
    "x64": "gargoyle x64",
}


@dataclass(frozen=True, slots=True)
class SetupObservation:
    """Parsed evidence from Gargoyle's setup banner.

    Attributes:
        lines: Captured setup output.
        addresses: Non-zero address values parsed from the setup banner.
    """

    lines: tuple[str, ...]
    addresses: dict[str, int]


@dataclass(frozen=True, slots=True)
class AcceptanceReport:
    """Result of a successful Gargoyle acceptance run.

    Attributes:
        artifacts: Executable and PIC paths used for the run.
        setup: Parsed setup banner.
        message_box_rounds: Number of benign MessageBox payload windows closed.
        build: Optional build result when the harness built first.
    """

    artifacts: GargoyleArtifacts
    setup: SetupObservation
    message_box_rounds: int
    build: BuildResult | None


class LineReader:
    """Background line reader for a live Gargoyle process."""

    def __init__(self, stream: IO[str]) -> None:
        """Start consuming text lines from a process stream.

        Args:
            stream: Text stream returned by `subprocess.Popen`.
        """
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._thread = threading.Thread(target=self._read, args=(stream,), daemon=True)
        self._thread.start()

    def get(self, timeout_seconds: float) -> str | None:
        """Get the next line, or `None` if the stream ended.

        Args:
            timeout_seconds: Maximum time to wait.

        Returns:
            A line of output, or `None` when the process stream is closed.
        """
        return self._lines.get(timeout=timeout_seconds)

    def _read(self, stream: IO[str]) -> None:
        """Read stream lines until EOF and signal completion.

        Args:
            stream: Text stream returned by `subprocess.Popen`.
        """
        for raw_line in stream:
            self._lines.put(str(raw_line).rstrip("\r\n"))
        self._lines.put(None)


def run_acceptance(
    *,
    configuration: Configuration,
    platform: Platform = "x86",
    repo_root: Path | None = None,
    msbuild: Path | None = None,
    skip_build: bool = False,
    rounds: int = 2,
    timeout_seconds: float = 45.0,
) -> AcceptanceReport:
    """Run the one-click Gargoyle acceptance check.

    Args:
        configuration: Visual Studio configuration to build and run.
        platform: Visual Studio solution platform to build and run.
        repo_root: Optional repository root. Defaults to upward discovery.
        msbuild: Optional explicit MSBuild path.
        skip_build: Whether to skip the MSBuild step.
        rounds: Number of benign MessageBox payload windows to close.
        timeout_seconds: Overall timeout for setup and window validation.

    Returns:
        Acceptance report with parsed setup evidence.

    Raises:
        AcceptanceError: If any validation step fails.
    """
    require_windows()
    if rounds < 1:
        raise AcceptanceError(
            "Invalid rounds",
            f"Expected at least one MessageBox round, got {rounds}.",
            "Use --rounds 1 for initial PIC handoff or --rounds 2 for timer re-entry.",
        )

    root = resolve_repo_root(repo_root)
    toolchain = resolve_toolchain(msbuild)
    build = None if skip_build else build_solution(root, configuration, platform, toolchain)
    artifacts = artifacts_for(root, configuration, platform)
    verify_artifacts(artifacts)

    process = _start_gargoyle(artifacts)
    controller = MessageBoxController()
    try:
        setup = _wait_for_setup(process, platform=platform, timeout_seconds=timeout_seconds)
        closed_rounds = _close_message_boxes(
            process=process,
            controller=controller,
            rounds=rounds,
            title=MESSAGE_BOX_TITLES[platform],
            timeout_seconds=timeout_seconds,
        )
    finally:
        _terminate_process(process)
    return AcceptanceReport(
        artifacts=artifacts,
        setup=setup,
        message_box_rounds=closed_rounds,
        build=build,
    )


def parse_setup_output(
    lines: list[str] | tuple[str, ...],
    platform: Platform = "x86",
) -> SetupObservation:
    """Parse and validate Gargoyle's setup banner.

    Args:
        lines: Captured process output.
        platform: Platform-specific banner format.

    Returns:
        Parsed setup evidence.

    Raises:
        AcceptanceError: If required markers or addresses are missing.
    """
    expected_markers = X64_EXPECTED_MARKERS if platform == "x64" else EXPECTED_MARKERS
    address_labels = X64_ADDRESS_LABELS if platform == "x64" else ADDRESS_LABELS
    missing_markers = [marker for marker in expected_markers if marker not in lines]
    addresses = _parse_addresses(lines, address_labels)
    missing_addresses = [label for label in address_labels if label not in addresses]
    if missing_markers or missing_addresses:
        problems = []
        if missing_markers:
            problems.append("missing markers: " + ", ".join(missing_markers))
        if missing_addresses:
            problems.append("missing addresses: " + ", ".join(missing_addresses))
        raise AcceptanceError(
            "Setup banner incomplete",
            "; ".join(problems),
            "Check that Gargoyle.exe is running from the output directory with setup.pic present.",
        )
    zero_addresses = [label for label, address in addresses.items() if address == 0]
    if zero_addresses:
        raise AcceptanceError(
            "Setup banner contained null addresses",
            "The following addresses were zero: " + ", ".join(zero_addresses),
            "Debug gadget search and workspace allocation before trusting the run.",
        )
    return SetupObservation(lines=tuple(lines), addresses=addresses)


def setup_banner_complete(lines: list[str], platform: Platform = "x86") -> bool:
    """Return whether captured lines contain a complete setup banner.

    Args:
        lines: Captured process output.
        platform: Platform-specific banner format.

    Returns:
        `True` when the setup banner can be parsed successfully.
    """
    try:
        parse_setup_output(lines, platform)
    except AcceptanceError:
        return False
    return True


def _start_gargoyle(artifacts: GargoyleArtifacts) -> subprocess.Popen[str]:
    """Start Gargoyle from the output directory.

    Args:
        artifacts: Resolved executable and PIC paths.

    Returns:
        Running Gargoyle process.

    Raises:
        AcceptanceError: If process creation fails.
    """
    try:
        return subprocess.Popen(
            [str(artifacts.executable)],
            cwd=artifacts.output_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
    except OSError as exc:
        raise AcceptanceError(
            "Gargoyle launch failed",
            f"Could not start {artifacts.executable}: {exc}",
            "Confirm the executable exists and is not blocked by endpoint controls.",
        ) from exc


def _wait_for_setup(
    process: subprocess.Popen[str],
    *,
    platform: Platform,
    timeout_seconds: float,
) -> SetupObservation:
    """Wait for Gargoyle to print a complete setup banner.

    Args:
        process: Running Gargoyle process.
        platform: Platform-specific banner format.
        timeout_seconds: Maximum time to wait.

    Returns:
        Parsed setup evidence.

    Raises:
        AcceptanceError: If stdout cannot be captured, the process exits, or setup times out.
    """
    if process.stdout is None:
        raise AcceptanceError(
            "Gargoyle stdout unavailable",
            "The harness could not capture Gargoyle stdout.",
            "This is an internal harness error; rerun with a fresh shell.",
        )
    reader = LineReader(process.stdout)
    lines: list[str] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AcceptanceError(
                "Gargoyle exited early",
                f"Gargoyle exited with code {process.returncode} before setup completed.\n"
                + "\n".join(lines[-20:]),
                "Check for missing PIC files, gadget search failures, or allocation failures.",
            )
        try:
            line = reader.get(timeout_seconds=min(0.2, max(0.01, deadline - time.monotonic())))
        except queue.Empty:
            continue
        if line is None:
            continue
        lines.append(line)
        if setup_banner_complete(lines, platform):
            return parse_setup_output(lines, platform)
    raise AcceptanceError(
        "Setup timed out",
        f"Gargoyle did not print a complete setup banner within {timeout_seconds:.0f} seconds.\n"
        + "\n".join(lines[-20:]),
        "Confirm stdout is unbuffered and the process is not blocked before setup completes.",
    )


def _close_message_boxes(
    *,
    process: subprocess.Popen[str],
    controller: MessageBoxController,
    rounds: int,
    title: str,
    timeout_seconds: float,
) -> int:
    """Close the benign MessageBox payload for a number of rounds.

    Args:
        process: Running Gargoyle process.
        controller: Window controller used to find and close windows.
        rounds: Number of payload windows to close.
        title: MessageBox title to wait for.
        timeout_seconds: Maximum wait per round.

    Returns:
        Number of MessageBox windows closed.

    Raises:
        AcceptanceError: If Gargoyle exits before a round completes.
    """
    closed = 0
    for index in range(rounds):
        if process.poll() is not None:
            raise AcceptanceError(
                "Gargoyle exited before re-entry",
                (
                    f"Gargoyle exited with code {process.returncode} before "
                    f"MessageBox round {index + 1}."
                ),
                "This often points to a bad gadget, stack pivot, or timer callback path.",
            )
        hwnd = controller.wait_for_message_box(
            pid=process.pid,
            title=title,
            timeout_seconds=timeout_seconds,
        )
        controller.close_window(hwnd)
        controller.wait_until_closed(hwnd)
        closed += 1
    return closed


def _terminate_process(process: subprocess.Popen[str]) -> None:
    """Terminate a still-running Gargoyle process.

    Args:
        process: Running Gargoyle process.
    """
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _parse_addresses(
    lines: list[str] | tuple[str, ...],
    address_labels: tuple[str, ...],
) -> dict[str, int]:
    """Parse address lines from Gargoyle's setup banner.

    Args:
        lines: Captured process output.
        address_labels: Address labels expected for the platform.

    Returns:
        Address values keyed by banner label.
    """
    addresses: dict[str, int] = {}
    for line in lines:
        for label in address_labels:
            prefix = f"{label} @"
            if line.strip().startswith(prefix) and "0x" in line:
                raw_address = line.rsplit("0x", maxsplit=1)[-1].strip()
                try:
                    addresses[label] = int(raw_address, 16)
                except ValueError:
                    continue
    return addresses
