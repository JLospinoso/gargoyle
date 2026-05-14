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

The first MessageBox validates initial PIC handoff into the benign demo action.
The second MessageBox validates later re-entry into the benign demo path after
an alertable `SleepEx(INFINITE, TRUE)` wait. That is consistent with the
intended timer/APC path, but the live x86/x64 MessageBox check does not
independently prove callback identity or observe every memory-protection
transition.

ARM64 and ARM64EC headless validation has stronger callback-delivery evidence
because the native runtime records completed-round and callback-round counters.
The live MessageBox path remains the clearest desktop demonstration, not a
complete event trace.

## Optional Manual Observation

After the first MessageBox appears, record the setup banner address for the setup
PIC and inspect the process with VMMap or a debugger. The interesting observation
is the transition between executable during the benign action and non-executable
while dormant.

Manual observation suggests the temporal protection cycle. It does not prove
that every transient state was captured or that any product would miss the
region.

## Harness Behavior

The Python harness waits for visible MessageBox windows owned by the launched
process and closes the requested number of rounds. If the process exits before a
round appears, the harness reports that failure instead of treating the missing
window as success. A timeout usually means the session is not interactive, the
window is blocked, or the native path did not reach the benign demo action.

See [Validation Limitations](limitations.md) and [Responsible Use](../responsible-use.md).
