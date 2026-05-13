# ARM64EC Sibling

`GargoyleArm64EC` is an ARM64EC sibling demonstration. It proves build identity,
runtime identity, EC dynamic-code allocation, and benign timer/APC semantics in
an ARM64EC process.

## Files

- `GargoyleArm64EC/main_arm64ec.cpp`
- `GargoyleArm64/arm_runtime.hpp`
- `GargoyleArm64EC/setup_arm64ec.asm`
- `GargoyleArm64EC/reentry_arm64ec.asm`
- `GargoyleArm64EC/GargoyleArm64EC.vcxproj`

## Dynamic-Code Caveat

ARM64EC processes distinguish EC dynamic code from ordinary x64 dynamic code.
The runtime reserves EC-code address space with `VirtualAlloc2` and
`MEM_EXTENDED_PARAMETER_EC_CODE`, then commits writable storage inside that
reservation before applying executable protection.

## ABI Boundaries

The v1 ARM64EC demonstration uses C++ wrappers for imported Windows APIs so the
PIC path can cross the expected thunk/checker boundaries. It does not demonstrate
mixed x64 DLL interop.

## Validation

Hosted `windows-11-arm` CI validates ARM64EC-compatible image identity,
architecture reports, and headless timer/APC rounds. Those checks prove the
benign smoke path, not a general mixed-ABI design.

See [Architecture Comparison](comparison.md),
[Build System](../implementation/build-system.md), and
[Responsible Use](../responsible-use.md).
