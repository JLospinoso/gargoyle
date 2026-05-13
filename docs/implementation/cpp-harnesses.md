# C++ Harnesses

The C++ harnesses prepare memory, load PIC artifacts, resolve Windows APIs, and
emit setup banners that the acceptance harness can parse.

## Common Responsibilities

- Resolve artifact paths relative to the output directory.
- Load `.pic` files into committed memory.
- Apply initial executable protection.
- Build an architecture-specific configuration block.
- Resolve imported Windows APIs.
- Print non-zero addresses for validation.
- Dispatch live, architecture-report, or headless modes when supported.

## Win32

`main.cpp` owns the original proof-of-concept setup: `setup.pic`, fallback
`gadget.pic`, configuration, scratch stack, and stack trampoline. Its
`SetupConfiguration` and `StackTrampoline` layouts must remain paired with
`setup.nasm`.

## x64

`GargoyleX64/main_x64.cpp` loads both `setup_x64.pic` and `reentry_x64.pic`.
The configuration block carries pointer-sized fields for the setup PIC, re-entry
PIC, timer, imported APIs, and saved protection state.

## ARM64 And ARM64EC

`GargoyleArm64/arm_runtime.hpp` is shared by the ARM64 and ARM64EC entry points.
It handles option parsing, PIC loading, architecture reports, headless runs, EC
dynamic-code allocation, and wrapper functions needed by the ARM64EC path.

See [Responsible Use](../responsible-use.md) before changing runtime behavior.
