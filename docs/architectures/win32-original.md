# Win32 Original

The Win32 path is the canonical Gargoyle proof of concept. It builds from the
root solution with `Platform=x86` and keeps the original stack-pivot story
visible.

## Files

- `main.cpp`
- `setup.nasm`
- `gadget.nasm`
- `Gargoyle.vcxproj`

## Lifecycle

```mermaid
flowchart TD
    A[C++ harness loads setup.pic] --> B[Allocate config, scratch stack, trampoline]
    B --> C[Find system gadget or use gadget.pic]
    C --> D[Call setup.pic]
    D --> E[Show benign MessageBox]
    E --> F[Mark setup.pic non-executable]
    F --> G[SleepEx alertable wait]
    G --> H[Timer APC enters gadget]
    H --> I[Stack pivots to trampoline]
    I --> J[VirtualProtectEx restores executable state]
    J --> E
```

## What It Proves

The live harness proves initial PIC handoff and timer/APC-backed re-entry when
it closes two benign `gargoyle` MessageBoxes. Manual memory-map observation can
suggest the temporal protection cycle by showing the setup PIC executable while
active and non-executable while dormant.

## Caveats

- This is the historical 32-bit design.
- Gadget availability can vary by Windows version and installed modules.
- The fallback gadget path is logged for reproducibility.
- The demo does not prove stealth, endpoint bypass, or every transient memory
  state.

See [Live MessageBox](../validation/live-messagebox.md) and
[Responsible Use](../responsible-use.md).
