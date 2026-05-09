# x64 Architecture

`GargoyleX64` is a sibling Windows x64 example, not a transparent port of the
Win32 stack-pivot design. It keeps the payload benign and visible while proving
the x64-specific mechanics needed for a timer/APC re-entry loop.

## Runtime Layout

The x64 build emits three files beside each other in the Visual Studio output
directory:

- `GargoyleX64.exe`, the C++ harness that loads raw PIC blobs and prepares the
  configuration block.
- `setup_x64.pic`, the main x64 setup and payload loop.
- `reentry_x64.pic`, a small executable wait/re-entry surface used while
  `setup_x64.pic` is parked read-only.

The C++ `X64Configuration` layout mirrors the NASM layout consumed by both PIC
files. It stores pointer-sized fields for the setup PIC, re-entry wait function,
APC callback, imported Windows APIs, timer handle, relative due time, timer
period, and saved protection value.

## Control Flow

1. `main_x64.cpp` loads `setup_x64.pic` and `reentry_x64.pic` as executable raw
   PIC and fills the shared configuration block.
2. `setup_x64.pic` receives the configuration pointer in `rcx`, creates a
   waitable timer, and arms it with the callback entry inside `reentry_x64.pic`.
3. The benign payload displays a `gargoyle x64` MessageBox.
4. After the MessageBox closes, `setup_x64.pic` calls the wait entry in
   `reentry_x64.pic`.
5. The wait entry marks `setup_x64.pic` `PAGE_READONLY` and enters an alertable
   `WaitForSingleObjectEx`.
6. Timer re-entry restores `setup_x64.pic` to `PAGE_EXECUTE_READ` through the
   re-entry PIC, then control returns to the setup loop and the benign payload
   appears again.

The wait path also reapplies `PAGE_EXECUTE_READ` before returning to the setup
PIC. That restore is idempotent when the APC callback has already run, and it
keeps unexpected waitable-timer return modes from jumping back into a read-only
setup page.

## Validation Notes

Run the x64 acceptance harness from a Windows desktop session:

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64
uv run --all-groups gargoyle-acceptance --configuration Release --platform x64
```

A healthy run prints non-zero addresses for the setup PIC, re-entry PIC, APC
callback, configuration block, and imported APIs. The harness then closes two
`gargoyle x64` MessageBox windows: the initial handoff and one timer/APC
re-entry.

The x64 example intentionally avoids the Win32 `pop reg; pop esp; ret` gadget
assumption. The separate re-entry PIC is the stable executable surface for the
x64 demonstration, while the setup PIC is the region whose idle protection state
is meant to be inspected.
