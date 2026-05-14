# ARM64 Sibling

`GargoyleArm64` is a native Windows-on-Arm sibling demonstration. It exists to
make the temporal memory-state idea testable on ARM64 Windows without expanding
the benign demo behavior.

## Files

- `GargoyleArm64/main_arm64.cpp`
- `GargoyleArm64/arm_runtime.hpp`
- `GargoyleArm64/setup_arm64.asm`
- `GargoyleArm64/reentry_arm64.asm`
- `GargoyleArm64/GargoyleArm64.vcxproj`

## Design

The C++ entry point delegates to the shared ARM runtime. The runtime loads
`setup_arm64.pic` and `reentry_arm64.pic`, prepares an ARM64 configuration
block, resolves the required Windows APIs, and supports live, headless, and
architecture-report modes.

The assembly uses ARM64 register calling conventions. The re-entry path restores
execute permission and uses `SleepEx(INFINITE, TRUE)` for alertable APC
semantics.

## Validation

Hosted `windows-11-arm` CI builds Debug and Release, validates PE-machine
compatibility, runs architecture reports, and runs headless rounds without GUI
automation. The headless runtime records completed-round and callback-round
counters, so CI checks callback delivery more directly than the x86/x64 live
MessageBox path. Local live validation is possible only when an ARM64 Windows
desktop lab is available.

See [Headless, Artifacts, And Architecture](../validation/headless-artifacts-architecture.md)
and [Responsible Use](../responsible-use.md).
