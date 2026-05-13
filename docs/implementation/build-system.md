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

## Just Recipes

`just ci` is the canonical gate. It syncs dependencies, checks the lock file,
builds x86/x64, runs native analysis and ASan builds, then runs Python and docs
checks. `just windows-arm-smoke` is intended for hosted Windows-on-Arm CI.

See [Tests And CI](tests-and-ci.md) for the validation pipeline.
