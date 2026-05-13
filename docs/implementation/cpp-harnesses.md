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

## Source Responsibilities

| File | Responsibility |
| --- | --- |
| `main.cpp` | Win32 artifact loading, gadget/trampoline setup, configuration layout, architecture report, and live MessageBox demo. |
| `GargoyleX64/main_x64.cpp` | x64 setup/re-entry PIC loading, Win64 configuration layout, architecture report, and live MessageBox demo. |
| `GargoyleArm64/main_arm64.cpp` | ARM64 entry point and trait wiring into the shared ARM runtime. |
| `GargoyleArm64EC/main_arm64ec.cpp` | ARM64EC entry point, EC-specific traits, and shared ARM runtime wiring. |
| `GargoyleArm64/arm_runtime.hpp` | ARM-family option parsing, architecture reports, live/headless dispatch, callback counters, and ARM64EC EC-code allocation helpers. |

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

In headless mode, the shared ARM runtime verifies `completed_rounds` and
`callback_rounds` after the PIC returns. That makes ARM-family headless
validation stronger callback-delivery evidence than the x86/x64 live MessageBox
check, which observes windows rather than counters.

## Runtime Evidence

| Architecture | Live evidence | Headless evidence |
| --- | --- | --- |
| x86 | Harness closes benign `gargoyle` MessageBoxes after setup output. | Not implemented in the native runtime. |
| x64 | Harness closes benign `gargoyle x64` MessageBoxes after setup output. | Not implemented in the native runtime. |
| ARM64 | Optional desktop MessageBox path on ARM64 Windows. | Completed-round and callback-round counters. |
| ARM64EC | Optional desktop MessageBox path on ARM64EC-capable Windows. | Completed-round and callback-round counters plus EC-code allocation path. |

See [Responsible Use](../responsible-use.md) before changing runtime behavior.
