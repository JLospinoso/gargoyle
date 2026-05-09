# Acceptance Harness

The acceptance harness is a Python CLI that builds and launches the existing
Win32 Gargoyle binary, validates the setup banner, and closes the benign
MessageBox payload windows.

```powershell
uv run gargoyle-acceptance --configuration Debug
uv run gargoyle-acceptance --configuration Release
```

By default the harness:

- requires Windows;
- verifies `nasm.exe` is available on `PATH`;
- discovers MSBuild or uses the `--msbuild` path;
- builds `Gargoyle.sln` for `x86`;
- checks that `Gargoyle.exe`, `setup.pic`, and `gadget.pic` exist;
- launches from the configuration output directory;
- waits for a complete setup banner with non-zero addresses;
- closes two `gargoyle` MessageBox windows to confirm the first payload run and
  the timer/APC re-entry.

Use `--rounds 1` for a shorter check that only confirms the initial PIC handoff.
Use `--skip-build` when you want to validate already-built outputs.
