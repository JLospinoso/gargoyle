"""Unit tests for the Typer command line interface."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from gargoyle_acceptance import cli
from gargoyle_acceptance.environment import GargoyleArtifacts
from gargoyle_acceptance.errors import AcceptanceError
from gargoyle_acceptance.harness import AcceptanceReport, SetupObservation


def _report(tmp_path: Path) -> AcceptanceReport:
    artifacts = GargoyleArtifacts(
        repo_root=tmp_path,
        configuration="Debug",
        platform="x86",
        output_dir=tmp_path / "Debug",
        executable=tmp_path / "Debug" / "Gargoyle.exe",
        setup_pic=tmp_path / "Debug" / "setup.pic",
        gadget_pic=tmp_path / "Debug" / "gadget.pic",
    )
    return AcceptanceReport(
        artifacts=artifacts,
        setup=SetupObservation(lines=("ok",), addresses={"Gargoyle PIC": 0x1000}),
        message_box_rounds=2,
        build=None,
    )


def test_cli_success(monkeypatch, tmp_path: Path) -> None:
    """The CLI renders a passing report."""
    monkeypatch.setattr(cli, "run_acceptance", lambda **kwargs: _report(tmp_path))

    result = CliRunner().invoke(cli.app, ["--configuration", "Debug", "--skip-build"])

    assert result.exit_code == 0
    assert "Passed" in result.stdout
    assert "MessageBox rounds" in result.stdout


def test_cli_failure(monkeypatch) -> None:
    """The CLI renders actionable acceptance errors."""

    def fail(**_kwargs):
        raise AcceptanceError("Nope", "Something failed.", "Try again.")

    monkeypatch.setattr(cli, "run_acceptance", fail)

    result = CliRunner().invoke(cli.app, ["--configuration", "Debug"])

    assert result.exit_code == 1
    assert "Gargoyle acceptance failed" in result.stdout
    assert "Try again" in result.stdout
