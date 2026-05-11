# Acceptance Harness

The acceptance harness is a Python CLI that builds and launches the existing
Gargoyle binary, validates the setup banner, and closes the benign MessageBox
payload windows. It defaults to the Win32 baseline and can also validate the
x64, ARM64, and ARM64EC sibling examples.

```powershell
uv run gargoyle-acceptance --configuration Debug
uv run gargoyle-acceptance --configuration Release
uv run gargoyle-acceptance --configuration Debug --platform x64
uv run gargoyle-acceptance --configuration Debug --platform arm64 --mode artifacts
```

By default the harness:

- requires Windows;
- verifies `nasm.exe` is available on `PATH`;
- discovers MSBuild or uses the `--msbuild` path;
- builds `Gargoyle.sln` for the requested platform;
- checks that the expected executable and PIC files exist;
- launches from the configuration output directory;
- waits for a complete platform-specific setup banner with non-zero addresses;
- closes two platform-specific MessageBox windows to confirm the first payload
  run and timer/APC re-entry.

Use `--rounds 1` for a shorter check that only confirms the initial PIC handoff.
Use `--skip-build` when you want to validate already-built outputs.

## Modes

`--mode live` is the default and preserves the historical behavior: build,
verify artifacts, validate the executable PE machine, launch the demo, parse the
setup banner, and close MessageBox windows.

`--mode artifacts` is CI-safe. It builds unless `--skip-build` is supplied,
discovers expected outputs, verifies the required PIC files, and validates the
executable's PE machine without launching it.

`--mode architecture` runs the executable with `--architecture-report` and
parses key-value output such as `platform=arm64`, `machine=ARM64`, and
`pointer_bits=64`. This mode is intended for non-interactive smoke checks once a
native project exposes that report command.

`--mode headless` runs the executable with `--mode headless` and parses setup-banner
evidence without MessageBox automation. This is a runtime smoke hook for
platforms where an interactive desktop check is not appropriate.

## Platforms

`--platform x86` validates the original Win32 path:

- builds `Debug|x86` or `Release|x86`;
- expects `Gargoyle.exe`, `setup.pic`, and `gadget.pic`;
- parses the Win32 PIC, gadget, configuration, stack, and trampoline addresses;
- closes MessageBox windows titled `gargoyle`.

`--platform x64` validates the sibling x64 path:

- builds `Debug|x64` or `Release|x64`;
- expects `GargoyleX64.exe`, `setup_x64.pic`, and `reentry_x64.pic`;
- parses the setup PIC, re-entry PIC, APC callback, configuration, and API
  addresses;
- closes MessageBox windows titled `gargoyle x64`.

`--platform arm64` and `--platform arm64ec` coordinate with expected native
project names `GargoyleArm64` and `GargoyleArm64EC`:

- builds `Debug|ARM64`, `Release|ARM64`, `Debug|ARM64EC`, or `Release|ARM64EC`;
- expects `GargoyleArm64.exe`, `setup_arm64.pic`, and `reentry_arm64.pic` for
  ARM64;
- expects `GargoyleArm64EC.exe`, `setup_arm64ec.pic`, and `reentry_arm64ec.pic`
  for ARM64EC;
- validates PE machines `ARM64` for ARM64 and `ARM64EC` for ARM64EC;
- supports artifact, architecture-report, and headless smoke checks before live
  desktop validation is practical.
