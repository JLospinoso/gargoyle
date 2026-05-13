# Headless, Artifacts, And Architecture

Non-interactive modes make CI and remote validation practical. They are useful
because they state exactly what evidence they collect.

## Artifact Mode

`--mode artifacts` builds unless `--skip-build` is supplied, verifies expected
PIC and executable files, and validates executable PE-machine compatibility.

For ARM64EC, PE-machine validation checks compatibility with the expected
ARM64EC image family rather than requiring one simplistic machine value. The
accepted family is `AMD64`, `ARM64`, `ARM64X`, or `ARM64EC`, matching the values
the MSVC toolchain can emit for compatible final images.

## Architecture Mode

`--mode architecture` runs `--architecture-report` and parses key-value output
such as platform, machine, pointer width, process architecture, and native
machine facts.

## Headless Mode

`--mode headless` runs a short non-GUI setup/re-entry path and parses setup
banner evidence. The hosted ARM job uses this for ARM64 and ARM64EC smoke
validation. On ARM64 and ARM64EC, the native runtime also checks that the
requested completed rounds finished and that callback rounds reached the
expected minimum.

## Platform And Mode Support

| Platform | Artifacts | Architecture Report | Headless | Live MessageBox |
| --- | --- | --- | --- | --- |
| x86 | Yes | Yes | No; not meaningful unless implemented in the native runtime | Yes |
| x64 | Yes | Yes | No; not meaningful unless implemented in the native runtime | Yes |
| ARM64 | Yes | Yes | Yes; checks completed and callback rounds | Yes, on a suitable ARM64 desktop lab |
| ARM64EC | Yes | Yes | Yes; checks completed and callback rounds | Yes, on a suitable ARM64EC-capable desktop lab |

## CI Suitability

Artifact and architecture modes avoid live UI automation. Headless mode avoids
MessageBoxes while still running a benign timer/APC path for supported
executables. None of these modes proves live desktop behavior.

See [Acceptance Harness](../implementation/acceptance-harness.md) and
[Tests And CI](../implementation/tests-and-ci.md).
