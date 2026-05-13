# Live MessageBox Validation

Live validation is the clearest demonstration for x86 and x64. It requires an
owned Windows desktop session because the harness closes visible MessageBox
windows.

## Commands

```powershell
uv run --all-groups gargoyle-acceptance --configuration Debug --platform x86
uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64
```

## What The Rounds Mean

The first MessageBox proves initial PIC handoff. The second MessageBox proves
timer/APC re-entry under the corrected `SleepEx(INFINITE, TRUE)` wait semantics.

## Optional Manual Observation

After the first MessageBox appears, record the setup banner address for the setup
PIC and inspect the process with VMMap or a debugger. The interesting observation
is the transition between executable during the benign action and non-executable
while dormant.

Manual observation suggests the temporal protection cycle. It does not prove
that every transient state was captured or that any product would miss the
region.

See [Validation Limitations](limitations.md) and [Responsible Use](../responsible-use.md).
