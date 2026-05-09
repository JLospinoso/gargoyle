# Gargoyle x64 Prototype

This directory contains a minimal, sibling x64 prototype for issue #2. It does
not replace the historical Win32 proof of concept in the repository root.

The prototype is intentionally small and benign:

- `GargoyleX64.vcxproj` builds only `Platform=x64`.
- `setup_x64.nasm` is a raw x64 PIC entry point assembled by NASM.
- `main_x64.cpp` loads the PIC, prepares a pointer-sized configuration block,
  resolves the two Windows APIs the PIC needs, and invokes the PIC.
- The payload is a single `MessageBoxA` with the caption/text `gargoyle x64`.

## Build

From the repository root:

```powershell
$nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'
if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }
MSBuild.exe Gargoyle.sln /p:Configuration=Debug /p:Platform=x64 /m
MSBuild.exe Gargoyle.sln /p:Configuration=Release /p:Platform=x64 /m
```

Run the executable from its output directory so it can find `setup_x64.pic`:

```powershell
Push-Location GargoyleX64\Debug
.\GargoyleX64.exe
Pop-Location
```

## Design Notes

The x64 path is a sibling design rather than a direct port of `setup.nasm`.
The Win32 PIC depends on stack arguments and an `esp`-based stack pivot. The x64
prototype instead demonstrates the mechanics that must be correct before any
larger Gargoyle chain is attempted:

- the configuration block uses pointer-sized fields;
- the PIC receives its configuration pointer in `rcx`;
- API calls place the first four arguments in `rcx`, `rdx`, `r8`, and `r9`;
- every call reserves the required 32-byte shadow space;
- the stack is kept 16-byte aligned across calls;
- the fifth `VirtualProtectEx` argument is passed on the stack; and
- the PIC preserves the nonvolatile `rbx` register that it uses for the
  configuration pointer.

The PIC calls `VirtualProtectEx(GetCurrentProcess(), setup_addr, setup_length,
PAGE_EXECUTE_READ, &old_protection)` and then calls `MessageBoxA`. This proves
the raw x64 PIC can consume the shared configuration and make Win64 ABI calls,
but it deliberately stops before adding a timer re-entry chain or a replacement
control-transfer strategy.

## Remaining Blockers

This is the documented minimal x64 prototype requested by issue #2, not the
complete x64 Gargoyle chain.

Before treating x64 as equivalent to the Win32 demonstration, the project still
needs:

- an x64-safe re-entry mechanism for `WaitForSingleObjectEx` /
  `SetWaitableTimer`;
- a replacement for the x86 `pop reg; pop esp; ret` stack-pivot assumption;
- a mitigation review for CFG, CET shadow stacks, and the consequences of
  executing raw PIC outside normal image/unwind metadata;
- explicit failure diagnostics for systems where policy blocks dynamically
  generated executable memory; and
- acceptance-harness support for an x64 run that can close the benign
  `MessageBoxA` payload without disturbing the Win32 checks.

The current prototype keeps those items visible as design work instead of
embedding a fragile or unsafe half-port in the main Win32 proof of concept.
