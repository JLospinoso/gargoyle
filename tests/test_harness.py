"""Unit tests for high-level Gargoyle acceptance logic."""

from __future__ import annotations

import subprocess
from io import StringIO
from pathlib import Path

import pytest

from gargoyle_acceptance import harness
from gargoyle_acceptance.build import BuildResult
from gargoyle_acceptance.environment import GargoyleArtifacts, Toolchain
from gargoyle_acceptance.errors import AcceptanceError

VALID_OUTPUT = [
    '[ ] Allocating executable memory for "setup.pic".',
    "[+] Allocated 149 bytes for PIC.",
    "[ ] Configuring ROP gadget.",
    "[+] ROP gadget configured.",
    "[+] Stack trampoline built.",
    "[+] Configuration built.",
    "[+] Success!",
    "    Gargoyle PIC @ -----> 0x00A00000",
    "    ROP gadget @ -------> 0x6AE93472",
    "    Configuration @ ----> 0x00A70000",
    "    Top of stack @ -----> 0x00A70038",
    "    Bottom of stack @ --> 0x00A80037",
    "    Stack trampoline @ -> 0x00A80038",
]
VALID_X64_OUTPUT = [
    '[ ] Loading x64 setup PIC from "setup_x64.pic".',
    "[+] Loaded 113 bytes of x64 PIC.",
    '[ ] Loading x64 re-entry PIC from "reentry_x64.pic".',
    "[+] Loaded 144 bytes of x64 re-entry PIC.",
    "[+] x64 timer/APC prototype configured.",
    "    Gargoyle x64 PIC @ ----> 0x000001827D9B0000",
    "    x64 re-entry PIC @ ----> 0x000001827D9C0000",
    "    x64 APC callback @ ---> 0x000001827D9C0010",
    "    Configuration @ -------> 0x00000057D1DAF658",
    "    VirtualProtectEx @ ----> 0x00007FFD49A72340",
    "    WaitForSingleObjectEx @ 0x00007FFD49A71230",
    "    CreateWaitableTimerW @  0x00007FFD49A70000",
    "    SetWaitableTimer @ ---> 0x00007FFD49A71111",
    "    MessageBoxA @ --------> 0x00007FFD4B30CAC0",
    "    Timer period @ -------> 15000 ms",
    "[ ] Entering benign x64 PIC payload loop.",
]


class FakeProcess:
    """Minimal process double for harness orchestration tests."""

    pid = 1234
    returncode: int | None = None

    def poll(self) -> int | None:
        """Return the fake process status."""
        return self.returncode

    def terminate(self) -> None:
        """Mark the fake process as terminated."""
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        """Return the fake process exit code.

        Args:
            timeout: Ignored timeout.

        Returns:
            Fake process exit code.
        """
        return self.returncode or 0


class FakeLiveProcess(FakeProcess):
    """Fake live process with stdout for setup parsing."""

    def __init__(self, stdout: StringIO) -> None:
        """Store fake stdout.

        Args:
            stdout: Stream to expose as process stdout.
        """
        self.stdout = stdout


def test_parse_setup_output_accepts_complete_banner() -> None:
    """Setup parsing accepts all required markers and non-zero addresses."""
    parsed = harness.parse_setup_output(VALID_OUTPUT)

    assert parsed.addresses["Gargoyle PIC"] == 0x00A00000
    assert parsed.addresses["ROP gadget"] == 0x6AE93472


def test_parse_setup_output_accepts_x64_complete_banner() -> None:
    """Setup parsing accepts the x64 timer/APC banner."""
    parsed = harness.parse_setup_output(VALID_X64_OUTPUT, "x64")

    assert parsed.addresses["Gargoyle x64 PIC"] == 0x000001827D9B0000
    assert parsed.addresses["x64 APC callback"] == 0x000001827D9C0010


def test_parse_setup_output_rejects_missing_marker() -> None:
    """Setup parsing identifies an incomplete setup chain."""
    with pytest.raises(AcceptanceError, match="Setup banner incomplete"):
        harness.parse_setup_output(VALID_OUTPUT[:-1])


def test_parse_setup_output_rejects_null_address() -> None:
    """Setup parsing rejects null addresses in the banner."""
    output = [line.replace("0x00A00000", "0x00000000") for line in VALID_OUTPUT]

    with pytest.raises(AcceptanceError, match="null addresses"):
        harness.parse_setup_output(output)


def test_parse_setup_output_ignores_malformed_address() -> None:
    """Malformed address lines are treated as missing evidence."""
    output = [line.replace("0x00A00000", "0xNOTHEX") for line in VALID_OUTPUT]

    with pytest.raises(AcceptanceError, match="missing addresses"):
        harness.parse_setup_output(output)


def test_setup_banner_complete_returns_boolean() -> None:
    """The completeness helper is convenient for streaming output."""
    assert harness.setup_banner_complete(VALID_OUTPUT)
    assert not harness.setup_banner_complete([])


def test_run_acceptance_orchestrates_build_and_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The high-level runner wires environment, build, setup, windows, and cleanup."""
    artifacts = GargoyleArtifacts(
        repo_root=tmp_path,
        configuration="Debug",
        platform="x86",
        output_dir=tmp_path / "Debug",
        executable=tmp_path / "Debug" / "Gargoyle.exe",
        setup_pic=tmp_path / "Debug" / "setup.pic",
        gadget_pic=tmp_path / "Debug" / "gadget.pic",
    )
    process = FakeProcess()
    calls: list[str] = []

    monkeypatch.setattr(harness, "require_windows", lambda: calls.append("windows"))
    monkeypatch.setattr(harness, "resolve_repo_root", lambda root: tmp_path)
    monkeypatch.setattr(
        harness,
        "resolve_toolchain",
        lambda msbuild: Toolchain(msbuild=Path("MSBuild.exe"), nasm=Path("nasm.exe")),
    )
    monkeypatch.setattr(
        harness,
        "build_solution",
        lambda root, configuration, platform, toolchain: BuildResult(
            command=("MSBuild.exe",),
            output="ok",
        ),
    )
    monkeypatch.setattr(harness, "artifacts_for", lambda root, configuration, platform: artifacts)
    monkeypatch.setattr(harness, "verify_artifacts", lambda value: calls.append("artifacts"))
    monkeypatch.setattr(harness, "_start_gargoyle", lambda value: process)
    monkeypatch.setattr(harness, "MessageBoxController", object)
    monkeypatch.setattr(
        harness,
        "_wait_for_setup",
        lambda proc, platform, timeout_seconds: harness.parse_setup_output(VALID_OUTPUT),
    )
    monkeypatch.setattr(
        harness,
        "_close_message_boxes",
        lambda **kwargs: 2,
    )
    monkeypatch.setattr(harness, "_terminate_process", lambda proc: calls.append("terminated"))

    report = harness.run_acceptance(configuration="Debug", repo_root=tmp_path)

    assert report.message_box_rounds == 2
    assert report.build is not None
    assert calls == ["windows", "artifacts", "terminated"]


def test_run_acceptance_rejects_zero_rounds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The runner rejects nonsensical MessageBox round counts."""
    monkeypatch.setattr(harness, "require_windows", lambda: None)

    with pytest.raises(AcceptanceError, match="Invalid rounds"):
        harness.run_acceptance(configuration="Debug", rounds=0)


def test_wait_for_setup_reads_complete_banner() -> None:
    """The setup waiter parses complete stdout from a live process."""
    process = FakeLiveProcess(StringIO("\n".join(VALID_OUTPUT) + "\n"))

    setup = harness._wait_for_setup(process, platform="x86", timeout_seconds=1)  # type: ignore[arg-type]

    assert setup.addresses["Stack trampoline"] == 0x00A80038


def test_wait_for_setup_reports_early_exit() -> None:
    """The setup waiter reports a process that exits too early."""
    process = FakeLiveProcess(StringIO("partial\n"))
    process.returncode = 1

    with pytest.raises(AcceptanceError, match="exited early"):
        harness._wait_for_setup(process, platform="x86", timeout_seconds=1)  # type: ignore[arg-type]


def test_wait_for_setup_reports_missing_stdout() -> None:
    """The setup waiter reports an impossible missing stdout pipe."""
    process = FakeProcess()
    process.stdout = None

    with pytest.raises(AcceptanceError, match="stdout unavailable"):
        harness._wait_for_setup(process, platform="x86", timeout_seconds=1)  # type: ignore[arg-type]


def test_wait_for_setup_reports_timeout() -> None:
    """The setup waiter reports incomplete long-running output."""
    process = FakeLiveProcess(StringIO("partial\n"))

    with pytest.raises(AcceptanceError, match="Setup timed out"):
        harness._wait_for_setup(process, platform="x86", timeout_seconds=0.01)  # type: ignore[arg-type]


def test_start_gargoyle_reports_launch_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Launch failures become actionable errors."""
    artifacts = GargoyleArtifacts(
        repo_root=tmp_path,
        configuration="Debug",
        platform="x86",
        output_dir=tmp_path,
        executable=tmp_path / "Gargoyle.exe",
        setup_pic=tmp_path / "setup.pic",
        gadget_pic=tmp_path / "gadget.pic",
    )

    def fail(*_args: object, **_kwargs: object) -> subprocess.Popen[str]:
        raise OSError("blocked")

    monkeypatch.setattr(harness.subprocess, "Popen", fail)

    with pytest.raises(AcceptanceError, match="launch failed"):
        harness._start_gargoyle(artifacts)


def test_close_message_boxes_closes_requested_rounds() -> None:
    """The MessageBox closer waits for and closes each requested round."""

    class Controller:
        closed: list[int]

        def __init__(self) -> None:
            self.closed = []

        def wait_for_message_box(self, **_kwargs: object) -> int:
            """Return a fake window handle."""
            return 100 + len(self.closed)

        def close_window(self, hwnd: int) -> None:
            """Record a closed fake window."""
            self.closed.append(hwnd)

        def wait_until_closed(self, hwnd: int) -> None:
            """Accept the fake close."""

    controller = Controller()

    closed = harness._close_message_boxes(
        process=FakeProcess(),  # type: ignore[arg-type]
        controller=controller,  # type: ignore[arg-type]
        rounds=2,
        title="gargoyle",
        timeout_seconds=1,
    )

    assert closed == 2
    assert controller.closed == [100, 101]


def test_terminate_process_ignores_already_exited_process() -> None:
    """Process cleanup is a no-op when Gargoyle already exited."""
    process = FakeProcess()
    process.returncode = 0

    harness._terminate_process(process)  # type: ignore[arg-type]

    assert process.returncode == 0


def test_terminate_process_kills_stubborn_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Process cleanup escalates to kill when terminate does not finish."""

    class StubbornProcess(FakeProcess):
        killed = False

        def wait(self, timeout: float | None = None) -> int:
            """Pretend graceful termination timed out once."""
            if not self.killed:
                raise subprocess.TimeoutExpired("Gargoyle.exe", timeout=timeout)
            return 0

        def kill(self) -> None:
            """Mark the process as force-killed."""
            self.killed = True
            self.returncode = -9

    process = StubbornProcess()

    harness._terminate_process(process)  # type: ignore[arg-type]

    assert process.killed


def test_close_message_boxes_reports_early_exit() -> None:
    """The MessageBox closer reports a crash before payload validation."""
    process = FakeProcess()
    process.returncode = 7

    with pytest.raises(AcceptanceError, match="exited before re-entry"):
        harness._close_message_boxes(
            process=process,  # type: ignore[arg-type]
            controller=object(),  # type: ignore[arg-type]
            rounds=1,
            title="gargoyle",
            timeout_seconds=1,
        )
