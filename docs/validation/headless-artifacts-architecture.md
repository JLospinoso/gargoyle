# Headless, Artifacts, And Architecture

Non-interactive modes make CI and remote validation practical. They are useful
because they state exactly what they prove.

## Artifact Mode

`--mode artifacts` builds unless `--skip-build` is supplied, verifies expected
PIC and executable files, and validates the executable PE machine.

## Architecture Mode

`--mode architecture` runs `--architecture-report` and parses key-value output
such as platform, machine, pointer width, process architecture, and native
machine facts.

## Headless Mode

`--mode headless` runs a short non-GUI setup/re-entry path and parses setup
banner evidence. The hosted ARM job uses this for ARM64 and ARM64EC smoke
validation.

## CI Suitability

Artifact and architecture modes avoid live UI automation. Headless mode avoids
MessageBoxes while still running a benign timer/APC path for supported
executables. None of these modes proves live desktop behavior.

See [Acceptance Harness](../implementation/acceptance-harness.md) and
[Tests And CI](../implementation/tests-and-ci.md).
