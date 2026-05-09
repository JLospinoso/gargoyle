# Acceptance Harness

The acceptance harness is a Python CLI that builds and launches the existing
Gargoyle binary, validates the setup banner, and closes the benign MessageBox
payload windows. It defaults to the Win32 baseline and can also validate the
x64 sibling example.

```powershell
uv run gargoyle-acceptance --configuration Debug
uv run gargoyle-acceptance --configuration Release
uv run gargoyle-acceptance --configuration Debug --platform x64
```

By default the harness:

- requires Windows;
- verifies `nasm.exe` is available on `PATH`;
- discovers MSBuild or uses the `--msbuild` path;
- builds `Gargoyle.sln` for the requested platform;
- checks that the expected executable and PIC files exist;
- launches from the configuration output directory;
- waits for a complete platform-specific setup banner with non-zero addresses;
- closes two platform-specific MessageBox windows to confirm the first payload
  run and timer/APC re-entry.

Use `--rounds 1` for a shorter check that only confirms the initial PIC handoff.
Use `--skip-build` when you want to validate already-built outputs.

## Platforms

`--platform x86` validates the original Win32 path:

- builds `Debug|x86` or `Release|x86`;
- expects `Gargoyle.exe`, `setup.pic`, and `gadget.pic`;
- parses the Win32 PIC, gadget, configuration, stack, and trampoline addresses;
- closes MessageBox windows titled `gargoyle`.

`--platform x64` validates the sibling x64 path:

- builds `Debug|x64` or `Release|x64`;
- expects `GargoyleX64.exe`, `setup_x64.pic`, and `reentry_x64.pic`;
- parses the setup PIC, re-entry PIC, APC callback, configuration, and API
  addresses;
- closes MessageBox windows titled `gargoyle x64`.
