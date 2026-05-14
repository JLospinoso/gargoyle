# Build System

The build system is intentionally conventional Windows tooling wrapped by
`just` recipes for reproducibility.

## Solution Structure

- `Gargoyle.sln` contains Win32, x64, ARM64, and ARM64EC projects.
- `Gargoyle.vcxproj` is the Win32 reference project.
- `GargoyleX64/GargoyleX64.vcxproj` builds the x64 sibling.
- `GargoyleArm64/GargoyleArm64.vcxproj` and
  `GargoyleArm64EC/GargoyleArm64EC.vcxproj` build the Windows-on-Arm siblings.

## Shared Properties

`build/Gargoyle.Configuration.props` centralizes the Windows SDK and default
toolset. `build/Gargoyle.Cpp.props` centralizes warning level, code analysis,
debugger working directory, and optional AddressSanitizer settings.

## PIC Targets

- `build/NasmPic.targets` assembles flat NASM PIC.
- `build/ArmPic.targets` runs `armasm64` and `extract_pic.py`.
- `build/extract_pic.py` extracts relocation-free raw bytes from a COFF section.

| Target File | Inputs | Outputs | Maintainer Notes |
| --- | --- | --- | --- |
| `build/NasmPic.targets` | `@(NasmPic)` items | `$(OutDir)%(Filename).pic` | Invokes `nasm -f bin`; output names follow the source stem. |
| `build/ArmPic.targets` | `@(ArmPic)` items, `build/extract_pic.py` | `$(OutDir)%(OutputFileName)` | Invokes `armasm64`, then extracts the configured section from the COFF object. |
| `build/extract_pic.py` | COFF object and section name | Raw `.pic` bytes | Rejects relocations unless `--allow-relocations` is passed explicitly. |

## Just Recipes

`just ci` is the canonical gate. It syncs dependencies, checks the lock file,
builds x86/x64, runs native analysis and ASan builds, then runs Python and docs
checks. `just windows-arm-smoke` is intended for hosted Windows-on-Arm CI.

| Recipe | Purpose | Notes |
| --- | --- | --- |
| `just docs` | Strict MkDocs build. | Fastest docs-only gate. |
| `just check` | Python format, lint, docs, types, tests, and coverage. | Does not build native binaries. |
| `just ci` | Canonical x64-hosted gate. | Adds dependency sync, lock check, x86/x64 native builds, code analysis, and ASan builds. |
| `just build-all` | Debug/Release x86 plus Debug/Release x64 builds. | Does not include ARM siblings. |
| `just native-check` | MSVC code analysis and ASan builds for x86/x64. | Run when native code or project settings change. |
| `just windows-arm-smoke` | Hosted Windows-on-Arm build and smoke path. | Builds ARM64/ARM64EC and runs architecture/headless checks without GUI automation. |

See [Tests And CI](tests-and-ci.md) for the validation pipeline.
