# Gargoyle

Gargoyle is a small Windows proof of concept for memory-scanner evasion.

The 2026 refresh keeps the original Win32 artifact intact while adding modern
build tooling, acceptance validation, documentation, and a sibling x64
timer/APC example.

## Developer Commands

```powershell
uv sync --all-groups
just check
uv run gargoyle-acceptance --configuration Debug
uv run gargoyle-acceptance --configuration Debug --platform x64
```

Runtime validation is Windows-only because it launches the native executable and
interacts with benign MessageBox payloads.
