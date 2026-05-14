# Quickstart

This page gives the shortest safe path from a fresh checkout to reproducible
validation evidence. Read [Responsible Use](responsible-use.md) first if you are
new to the repository.

## Prerequisites

- Windows desktop session for live MessageBox validation.
- Visual Studio C++ toolchain with MSBuild and a Windows 10/11 SDK.
- NASM on `PATH` for Win32 and x64 PIC builds.
- Python 3.13, `uv`, and `just`.
- ARM64 and ARM64EC toolchains only when building the Windows-on-Arm siblings.

## Clone And Sync

```powershell
git clone https://github.com/JLospinoso/gargoyle.git
cd gargoyle
uv sync --all-groups
```

## Build And Check

The canonical repository gate is:

```powershell
just ci
```

That builds x86 and x64, runs native analysis and AddressSanitizer builds, then
runs Python format, lint, type, test, coverage, and docs checks.

For a faster docs-and-Python pass:

```powershell
just check
```

## Run The Canonical Demo

The default acceptance run builds `Debug|x86`, starts `Gargoyle.exe` from the
output directory, parses the setup banner, and closes two benign `gargoyle`
MessageBoxes:

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug
```

The first MessageBox validates initial PIC handoff. The second validates later
re-entry into the benign demo path after an alertable wait. That is consistent
with the intended timer/APC path, but the x86/x64 live MessageBox check does
not independently prove callback identity or observe every memory-protection
transition. It also does not prove product evasion, invisibility, or broad
defensive failure.

## Non-Interactive Checks

Use artifact mode when a build or CI environment should not launch the live
MessageBox path:

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64 --mode artifacts
uv run --all-groups gargoyle-acceptance --configuration Debug --platform arm64 --mode artifacts
```

See [Headless, Artifacts, And Architecture](validation/headless-artifacts-architecture.md)
for what each non-interactive mode validates. ARM64 and ARM64EC headless runs add
completed-round and callback-round counters, which makes their non-interactive
evidence stronger for callback delivery than the x86/x64 MessageBox check.

## Next Steps

- [Lab Setup](lab-setup.md) for toolchain and desktop expectations.
- [Win32 Original](architectures/win32-original.md) for the canonical control
  flow.
- [Acceptance Harness](implementation/acceptance-harness.md) for CLI internals.
- [Validation Overview](validation/overview.md) for evidence language.
