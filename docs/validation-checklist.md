# Validation Checklist

Use this checklist alongside the automated acceptance harness in
[Acceptance Harness](acceptance.md). It is intentionally short and benign: the
goal is to confirm that the Win32 proof of concept still demonstrates the
documented memory-state transition without turning runtime validation into an
operational playbook.

## Prerequisites

- Windows desktop session where visible MessageBox windows are acceptable.
- Current Visual Studio C++ toolchain and Windows 10 SDK.
- NASM available on `PATH`.
- `uv` and Python 3.13 available for the acceptance harness.
- Optional: [Sysinternals VMMap](https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap)
  for process memory inspection.
- Optional: debugger or tracing tool for local research observations.

## Automated Checks

Run these before manual runtime validation:

```powershell
uv sync --all-groups
just build-all
just native-check
just check
```

For the live acceptance path, run:

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug
uv run --all-groups gargoyle-acceptance --configuration Release
uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64
uv run --all-groups gargoyle-acceptance --configuration Release --platform x64
```

Expected automated evidence:

- `Gargoyle.exe`, `setup.pic`, and `gadget.pic` exist in each configuration
  output directory.
- `GargoyleX64.exe`, `setup_x64.pic`, and `reentry_x64.pic` exist in each x64
  output directory.
- MSVC code analysis completes for Debug/Release on x86 and x64 with warnings as
  errors.
- AddressSanitizer Debug builds complete for x86 and x64 under `asan\`.
- The setup banner includes non-zero addresses for the Gargoyle PIC, ROP gadget,
  configuration, stack bounds, and stack trampoline.
- The x64 setup banner includes non-zero addresses for the setup PIC, re-entry
  PIC, APC callback, configuration, and imported APIs.
- The harness closes at least two benign `gargoyle` MessageBox rounds when run
  with its default settings, confirming the initial handoff and one timer/APC
  re-entry.
- The x64 harness closes at least two benign `gargoyle x64` MessageBox rounds,
  confirming the initial handoff and one timer/APC re-entry.

## Manual Runtime Checklist

1. Build `Debug|x86` or `Release|x86`.

2. Start `Gargoyle.exe` from the matching output directory so `setup.pic` and
   `gadget.pic` are beside the executable.

3. Save the console banner. Confirm the printed addresses are non-zero and that
   the PIC, configuration, stack, and trampoline are distinct regions.

4. When the first `gargoyle` MessageBox appears, inspect the process in VMMap or
   a comparable local tool. The setup PIC address from the banner should be in a
   committed region that is executable while the payload is active.

5. Dismiss the MessageBox. During the idle interval, refresh the memory view. The
   setup PIC region should remain committed but should no longer be executable.

6. Wait for the next MessageBox. The default interval is approximately 15
   seconds. A second window confirms timer/APC re-entry.

7. Dismiss the second MessageBox and close the process after collecting evidence.
   The demo should not create files, network connections, persistence, or
   non-benign payload effects.

## x64 Manual Runtime Checklist

1. Build `Debug|x64` or `Release|x64`.

2. Start `GargoyleX64.exe` from the matching output directory so `setup_x64.pic`
   and `reentry_x64.pic` are beside the executable.

3. Save the console banner. Confirm the setup PIC, re-entry PIC, APC callback,
   configuration, and imported API addresses are non-zero.

4. When the first `gargoyle x64` MessageBox appears, inspect the setup PIC
   address from the banner. It should be executable while the payload is active.

5. Dismiss the MessageBox. During the idle interval, the setup PIC should be
   parked as read-only while the separate re-entry PIC remains executable.

6. Wait for the next `gargoyle x64` MessageBox. The default interval is
   approximately 15 seconds. A second window confirms timer/APC re-entry.

7. Dismiss the second MessageBox and close the process after collecting
   evidence.

## Optional Diagnostic Observations

- Watch for `VirtualProtectEx` calls that make the setup PIC executable before
  payload execution and non-executable afterward.

- Watch for `SetWaitableTimer` and alertable `WaitForSingleObjectEx` behavior
  that explains why the timer completion routine runs on re-entry.

- Compare the fallback `gadget.pic` path with the system-DLL gadget path when
  `mshtml.dll` is absent or lacks a compatible pivot sequence.

- Record Windows version, Visual Studio toolset, NASM version, configuration,
  and whether the process ran under WOW64.

## CI-Safe Versus Desktop-Only

CI-safe:

- NASM assembly and Visual Studio compilation.
- Python formatting, linting, typing, unit tests, and documentation builds.
- Static checks that do not launch the interactive demo.

Desktop-only:

- MessageBox automation.
- VMMap inspection.
- Debugger or live process tracing.
- Any observation that depends on a visible interactive session.

## Failure Clues

- Missing `setup.pic` or `gadget.pic`: launch from the configuration output
  directory or rebuild the project.

- Setup banner timeout: inspect the console output, artifact paths, and whether
  the process started from the expected working directory.

- Exit before the second MessageBox: suspect gadget selection, stack pivot,
  timer setup, or protection-restoration behavior.

- Memory remains executable while idle: inspect the `VirtualProtectEx` tail-call
  path and confirm the observed region matches the banner's PIC address.

## Issue Coverage

This page contributes to:

- #13 by making the refreshed artifact easier to verify.
- #18 by capturing reproducible automated and manual validation steps.
- #17 by keeping live validation tied to benign, observable behavior.
