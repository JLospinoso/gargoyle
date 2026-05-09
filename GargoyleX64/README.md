# Gargoyle x64 Example

This directory contains a sibling x64 example for issue #2. It does not replace
the historical Win32 proof of concept in the repository root.

The example is intentionally small and benign:

- `GargoyleX64.vcxproj` builds only `Platform=x64` through the root
  `Gargoyle.sln`.
- `setup_x64.nasm` is the main raw x64 PIC entry point.
- `reentry_x64.nasm` is the executable wait/APC re-entry PIC.
- `main_x64.cpp` loads both PIC blobs, prepares a pointer-sized configuration
  block, resolves the Windows APIs the PIC needs, and invokes the setup PIC.
- The payload is a repeating `MessageBoxA` with the caption/text
  `gargoyle x64`.

## Build

From the repository root:

```powershell
$nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'
if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }
MSBuild.exe Gargoyle.sln /p:Configuration=Debug /p:Platform=x64 /m
MSBuild.exe Gargoyle.sln /p:Configuration=Release /p:Platform=x64 /m
```

With the current Visual Studio defaults, the root solution emits the x64 outputs
under `x64\Debug\` or `x64\Release\`. Run the executable from its output
directory so it can find `setup_x64.pic` and `reentry_x64.pic`:

```powershell
Push-Location x64\Debug
.\GargoyleX64.exe
Pop-Location
```

## Design Notes

The x64 path is a sibling design rather than a direct port of `setup.nasm`. The
Win32 PIC depends on stack arguments and an `esp`-based stack pivot. The x64
example instead uses two PIC blobs:

- `setup_x64.pic` owns the setup state and benign payload loop.
- `reentry_x64.pic` remains executable while `setup_x64.pic` is parked
  read-only during alertable waits.

The setup PIC creates a waitable timer, registers the callback entry inside the
re-entry PIC, displays the benign MessageBox payload, and then calls the re-entry
PIC's wait entry. The wait entry marks `setup_x64.pic` `PAGE_READONLY` and enters
`WaitForSingleObjectEx(..., TRUE)`. Timer re-entry restores
`setup_x64.pic` to `PAGE_EXECUTE_READ`, returns to the setup loop, and displays
the benign payload again.

The implementation follows the Win64 ABI requirements that must be correct
before larger designs are considered:

- the configuration block uses pointer-sized fields;
- the setup PIC receives its configuration pointer in `rcx`;
- API calls place the first four arguments in `rcx`, `rdx`, `r8`, and `r9`;
- every call reserves the required 32-byte shadow space;
- the stack is kept 16-byte aligned across calls;
- fifth and sixth arguments are passed on the stack; and
- nonvolatile registers used by the PIC are preserved.

## Validation

Run the platform-aware acceptance harness from a Windows desktop session:

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64
uv run --all-groups gargoyle-acceptance --configuration Release --platform x64
```

The harness validates the x64 setup banner and closes two benign `gargoyle x64`
MessageBox rounds. The first window proves the initial PIC handoff; the second
window proves timer/APC re-entry.
