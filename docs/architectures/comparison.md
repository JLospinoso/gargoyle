# Architecture Comparison

Gargoyle keeps Win32 canonical and treats other architectures as sibling
demonstrations with explicit caveats.

```mermaid
flowchart LR
    X86[x86 canonical Win32] --> Idea[Temporal memory-state lesson]
    X64[x64 sibling] --> Idea
    ARM64[ARM64 sibling] --> Idea
    ARM64EC[ARM64EC sibling] --> Idea
```

| Architecture | Role | PIC Source | Re-entry Shape | Best Evidence | Does Not Prove |
| --- | --- | --- | --- | --- | --- |
| x86 | Canonical original | NASM flat binary | ROP gadget and trampoline | Live MessageBox rounds plus optional memory-map observation | Modern x64 or ARM mechanics |
| x64 | Sibling demonstration | NASM flat binary | Separate re-entry PIC | Live MessageBox rounds | Transparent x86 stack-pivot port |
| ARM64 | Sibling demonstration | ARMASM COFF `.text` extraction | Re-entry assembly | Hosted headless rounds on Windows-on-Arm | Desktop live behavior without ARM lab |
| ARM64EC | Sibling demonstration | ARMASM COFF `.text` extraction with ARM64EC options | Re-entry assembly and EC dynamic code | Hosted ARM64EC architecture/headless checks | Mixed x64 DLL interop |

## Shared Claims

All architectures keep the demo benign and visible. All use timer/APC re-entry
and an alertable `SleepEx` wait for the corrected proof semantics.

## Refresh Summary

The 2026 refresh added build tooling, a typed acceptance harness, native quality
checks, Windows-on-Arm smoke validation, and layered documentation. The refresh
improves reproducibility and claim discipline; it does not expand Gargoyle into
an operational framework.
