"""Typer command line interface for Gargoyle acceptance checks."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from gargoyle_acceptance.environment import (
    coerce_optional_path,
    parse_configuration,
    parse_platform,
)
from gargoyle_acceptance.errors import AcceptanceError
from gargoyle_acceptance.harness import AcceptanceReport, run_acceptance

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="Build and validate the Gargoyle proof-of-concept binary.",
)
console = Console()


@app.callback(invoke_without_command=True)
def acceptance(
    configuration: Annotated[
        str,
        typer.Option(
            "--configuration",
            "-c",
            help="Visual Studio configuration to build and run.",
        ),
    ] = "Debug",
    repo_root: Annotated[
        Path | None,
        typer.Option(
            "--repo-root",
            help="Repository root. Defaults to upward discovery from the current directory.",
        ),
    ] = None,
    platform: Annotated[
        str,
        typer.Option(
            "--platform",
            "-p",
            help="Visual Studio solution platform to build and run.",
        ),
    ] = "x86",
    msbuild: Annotated[
        Path | None,
        typer.Option("--msbuild", help="Optional full path to MSBuild.exe."),
    ] = None,
    skip_build: Annotated[
        bool,
        typer.Option("--skip-build", help="Validate existing outputs without invoking MSBuild."),
    ] = False,
    rounds: Annotated[
        int,
        typer.Option(
            "--rounds",
            help="MessageBox payload rounds to close. Use 2 to confirm timer re-entry.",
        ),
    ] = 2,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Timeout in seconds for setup and each MessageBox round."),
    ] = 45.0,
) -> None:
    """Run Gargoyle's Windows-only acceptance validation.

    Args:
        configuration: Visual Studio configuration to build and run.
        repo_root: Optional repository root.
        platform: Visual Studio solution platform to build and run.
        msbuild: Optional MSBuild path.
        skip_build: Whether to skip the build step.
        rounds: Number of MessageBox rounds to validate.
        timeout: Timeout in seconds.

    Raises:
        typer.Exit: If the acceptance check fails.
    """
    try:
        report = run_acceptance(
            configuration=parse_configuration(configuration),
            platform=parse_platform(platform),
            repo_root=coerce_optional_path(repo_root),
            msbuild=coerce_optional_path(msbuild),
            skip_build=skip_build,
            rounds=rounds,
            timeout_seconds=timeout,
        )
    except AcceptanceError as exc:
        _render_error(exc)
        raise typer.Exit(1) from exc
    _render_success(report)


def _render_error(error: AcceptanceError) -> None:
    """Render a user-actionable failure panel.

    Args:
        error: Acceptance failure to display.
    """
    detail = f"[bold red]{error.title}[/]\n\n{error.detail}"
    if error.hint:
        detail += f"\n\n[bold]Next step:[/] {error.hint}"
    console.print(Panel(detail, title="Gargoyle acceptance failed", border_style="red"))


def _render_success(report: AcceptanceReport) -> None:
    """Render a successful acceptance report.

    Args:
        report: Completed acceptance report.
    """
    table = Table(title="Gargoyle Acceptance")
    table.add_column("Check", style="bold")
    table.add_column("Value")
    table.add_row("Configuration", report.artifacts.configuration)
    table.add_row("Platform", report.artifacts.platform)
    table.add_row("Executable", str(report.artifacts.executable))
    table.add_row("MessageBox rounds", str(report.message_box_rounds))
    table.add_row("Setup lines", str(len(report.setup.lines)))
    for label, address in report.setup.addresses.items():
        table.add_row(label, f"0x{address:08X}")
    console.print(Panel(table, title="[green]Passed[/]", border_style="green"))


def main() -> None:
    """Run the Typer app."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
