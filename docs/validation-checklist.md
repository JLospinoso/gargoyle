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
just build-debug
just build-release
just check
```

For the live acceptance path, run:

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug
uv run --all-groups gargoyle-acceptance --configuration Release
```

Expected automated evidence:

- `Gargoyle.exe`, `setup.pic`, and `gadget.pic` exist in each configuration
  output directory.
- The setup banner includes non-zero addresses for the Gargoyle PIC, ROP gadget,
  configuration, stack bounds, and stack trampoline.
- The harness closes at least two benign `gargoyle` MessageBox rounds when run
  with its default settings, confirming the initial handoff and one timer/APC
  re-entry.

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

