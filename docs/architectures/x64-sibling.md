# x64 Sibling

`GargoyleX64` is a sibling demonstration. It uses x64 calling conventions and a
separate re-entry PIC instead of copying the original Win32 stack-pivot chain.

## Files

- `GargoyleX64/main_x64.cpp`
- `GargoyleX64/setup_x64.nasm`
- `GargoyleX64/reentry_x64.nasm`
- `GargoyleX64/GargoyleX64.vcxproj`

## Design

The C++ harness loads `setup_x64.pic` and `reentry_x64.pic`. The setup PIC shows
the benign `gargoyle x64` MessageBox, then calls into the re-entry PIC. The
re-entry PIC parks the setup PIC as read-only, enters `SleepEx(INFINITE, TRUE)`,
and restores execute permission when the timer APC path runs.

## Why It Is A Sibling

x64 changes the ABI: register arguments, stack alignment, shadow space,
nonvolatile registers, and mitigation behavior all differ from Win32. The
checked-in example proves a comparable timer/APC protection-cycle demonstration,
not a one-for-one x64 rewrite of the old gadget chain.

## Validation

Live x64 acceptance proves initial handoff and one timer/APC re-entry by closing
two benign `gargoyle x64` MessageBoxes. Artifact and architecture modes prove
file layout and binary identity, not runtime re-entry.

See [Architecture Comparison](comparison.md),
[Assembly And PIC](../implementation/assembly-pic.md), and
[Responsible Use](../responsible-use.md).
