# ARM64EC Sibling

`GargoyleArm64EC` is an ARM64EC sibling demonstration. It validates build
identity, runtime identity, the EC-code allocation path used by this demo, and
benign timer/APC semantics in an ARM64EC process.

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

This exercises the ARM64EC dynamic-code allocation path used here. It is not a
general proof of every ARM64EC dynamic-code pattern.

## ABI Boundaries

The v1 ARM64EC demonstration uses C++ wrappers for imported Windows APIs so the
PIC path can cross the expected thunk/checker boundaries. It does not demonstrate
mixed x64 DLL interop.

## Validation

Hosted `windows-11-arm` CI validates ARM64EC-compatible image-family identity,
architecture reports, and headless timer/APC rounds. PE-machine validation
checks compatibility with the expected ARM64EC image family rather than
requiring one simplistic machine value. The headless runtime records
completed-round and callback-round counters, so CI checks callback delivery
more directly than the x86/x64 live MessageBox path. Those checks validate the
benign smoke path, not a general mixed-ABI design.

See [Architecture Comparison](comparison.md),
[Build System](../implementation/build-system.md), and
[Responsible Use](../responsible-use.md).
