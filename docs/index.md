# Gargoyle

Gargoyle is a small Windows proof of concept for memory-scanner evasion.

The 2026 refresh keeps the original Win32 artifact intact while adding modern
build tooling, acceptance validation, and documentation.

## Developer Commands

```powershell
uv sync --all-groups
just check
uv run gargoyle-acceptance --configuration Debug
```

Runtime validation is Windows-only because it launches `Gargoyle.exe` and
interacts with its benign MessageBox payload.
