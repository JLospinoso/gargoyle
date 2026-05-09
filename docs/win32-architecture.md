# Win32 Architecture

Gargoyle's current runtime is a small 32-bit Windows proof of concept. The
supported path is the Win32 build produced by `Gargoyle.sln` with `Platform=x86`,
NASM on `PATH`, and a current Visual Studio C++ toolchain targeting Windows SDK
`10.0`.

The demo intentionally keeps the payload benign: each invocation displays a
`gargoyle` MessageBox. The interesting behavior is the setup around that payload,
not the payload itself.

## Runtime Layout

`main.cpp` allocates three executable or mutable regions:

- `setup.pic`, assembled from `setup.nasm`, contains the position-independent
  setup and re-entry code.
- A ROP gadget is selected from an executable section of `mshtml.dll` when
  possible. If that search fails, `gadget.pic` provides a tiny fallback gadget.
- A read/write workspace contains the configuration block, scratch stack, and
  trampoline frame consumed by the setup PIC.

The C++ `SetupConfiguration` and `StackTrampoline` structures mirror the NASM
layout in `setup.nasm`. Keep those layouts paired: the setup PIC reads fields by
offset rather than by symbol names.

## Control Flow

1. `main.cpp` loads `setup.pic` as executable memory, then searches for a
   stack-pivot gadget.
2. The workspace is zeroed and populated with Win32 API addresses, the timer
   interval, the selected gadget, the scratch stack, and the trampoline frame.
3. The setup PIC receives the configuration pointer, pivots to the scratch stack,
   creates a waitable timer, and registers the gadget as the APC completion
   callback. The callback argument points at the trampoline frame.
4. Before waiting, the setup PIC tail-calls `VirtualProtectEx` to mark the PIC
   region `PAGE_READONLY`, then enters an alertable wait through
   `WaitForSingleObjectEx`.
5. On timer delivery, the APC callback enters the gadget. The gadget pivots the
   stack to the trampoline frame, which restores the PIC to `PAGE_EXECUTE_READ`
   and returns to `setup.pic`.
6. The benign MessageBox payload runs again, and the cycle repeats.

The console banner logs the selected gadget source, timer/APC setup, stack-pivot
target, and protection cycle so a failing run can be diagnosed from stdout before
using a debugger.

## Validation Notes

The acceptance harness can validate the observable behavior in an interactive
Windows desktop session:

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug
uv run --all-groups gargoyle-acceptance --configuration Release
```

A healthy run prints non-zero addresses for the PIC, gadget, configuration,
scratch stack, and trampoline. It then shows and closes two benign `gargoyle`
MessageBox windows: the initial handoff and the timer/APC re-entry.

Manual validation can additionally confirm:

- the selected gadget source is either `system DLL: mshtml.dll` or
  `allocated fallback PIC: gadget.pic`;
- the timer period is 15000 ms;
- the logged protection cycle is `PAGE_EXECUTE_READ -> PAGE_READONLY ->
  PAGE_EXECUTE_READ`;
- a debugger or VMMap-style view agrees that the PIC is not left writable after
  setup.

The old Windows 7 x64 NULL-jump report is treated as unsupported legacy behavior
for this Win32 refresh. The current issue to watch is whether the fallback gadget
is selected on a supported Win32 run; that path is logged explicitly so it can be
reproduced and debugged without broadening the proof of concept.
