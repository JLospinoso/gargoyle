# Responsible Use, Limitations, And Detection

Gargoyle is a historical Windows research proof of concept. Its refreshed
documentation should help maintainers, defenders, and researchers understand the
technique, reproduce the benign demo, and recognize the artifacts it leaves
behind. It should not evolve into a general offensive framework.

## Responsible-Use Boundaries

- Keep demo payloads benign. The repository's live runtime demonstration should
  remain the `gargoyle` MessageBox payload or an equally harmless local
  observation.

- Run the proof of concept only in systems you own or have explicit permission
  to use. Prefer disposable Windows VMs or lab machines where interactive window
  automation is acceptable.

- Do not add credential theft, persistence, lateral movement, autonomous
  exploitation, payload deployment, or operational misuse guidance.

- Treat references to larger payload experiments as historical and defensive
  context. They explain why the technique was studied and how defenders looked
  for it; they are not acceptance criteria for this repository.

- Preserve the small proof-of-concept shape. A maintainable research artifact is
  more valuable here than a broader evasion platform.

## Current Limitations

- Architecture: the Win32/x86 path remains the reference implementation. The
  checked-in x64 sibling demonstrates timer/APC re-entry with a separate
  re-entry PIC, but it is not a transparent port of the Win32 stack-pivot chain.

- Calling convention: `setup.nasm` relies on 32-bit stack calling conventions,
  `esp`/`ebp` manipulation, and a compact `pop reg; pop esp; ret`-style pivot.
  The x64 sibling uses register arguments, shadow space, stack alignment, and a
  separate re-entry surface instead of copying those assumptions.

- Runtime environment: the acceptance harness needs a Windows desktop session
  because it closes visible `gargoyle` MessageBox windows. Headless CI can build
  and run Python checks, but the live MessageBox validation is local and
  interactive by design.

- Gadget source: the demo first tries to locate a compatible pivot gadget in a
  system DLL and falls back to the tiny `gadget.pic` artifact if needed. System
  DLL layout, mitigation policy, and Windows version differences can affect this
  path.

- Visibility: Gargoyle does not make memory disappear. The core idea is to make
  the PIC non-executable while idle so simplistic executable-page scans are less
  likely to classify it as code. Process memory maps, timer state, private
  allocations, and behavioral telemetry can still expose the demo.

- Mitigations and platform changes: Control Flow Guard, CET/shadow-stack
  behavior, stricter callback validation, endpoint telemetry, and debugger or
  sandbox instrumentation can all affect ROP, callback, and context-restoration
  assumptions. Treat failures as research data, not as reasons to add bypasses.

- Timing: the default cadence is intentionally obvious: a MessageBox appears
  about every 15 seconds. Scanner timing, scheduler behavior, and manual
  interaction can make observations slightly noisy.

## Defensive Visibility

Defenders and maintainers can reason about Gargoyle through several observable
categories:

- Memory protection transitions: the setup PIC is executable while the payload
  runs and non-executable while the demo waits. VMMap, debuggers, ETW providers,
  or memory forensics can observe the region changing state.

- Private code-adjacent memory: the setup PIC, fallback gadget, scratch stack,
  and trampoline are allocated at runtime rather than loaded as ordinary module
  code. Even when non-executable, those regions remain part of the process
  address space.

- Timer and APC behavior: Gargoyle uses a waitable timer and an alertable wait
  path to re-enter the code. Auditing timer completion routines, APC delivery,
  and alertable waits can expose behavior that simple page scans miss.

- ROP and stack-pivot shape: the pivot gadget and stack trampoline are small but
  distinctive. Defensive work can look for unusual callback targets, stack
  movement into private allocations, and return paths that do not resemble
  ordinary compiler output.

- Console and UI artifacts: the refreshed demo prints platform-specific PIC,
  configuration, callback, and API addresses, then opens benign MessageBox
  windows titled `gargoyle` or `gargoyle x64`. Those are acceptance evidence,
  not stealth features.

- Forensics clues: Volatility-style plugins, page-table inspection, VAD review,
  and memory-map comparisons can all provide evidence even when an executable
  page scanner misses the idle PIC.

## Safe Defender Exercises

- Build the Debug and Release configurations and run the acceptance harness
  against the benign MessageBox payload.

- Record the setup banner addresses and inspect the Gargoyle process with VMMap
  before dismissing the MessageBox, after dismissing it, and after the next
  timer re-entry.

- Compare what user-mode memory-map tools show with what a memory-forensics
  workflow sees. Focus on whether the region exists, what its protection is, and
  whether timers or callback targets explain re-entry.

- Use the public references in [Reference Map](references.md) to compare
  Gargoyle-specific heuristics with broader sleep-obfuscation detection ideas.

## Issue Coverage

This page contributes to:

- #13 by framing the 2026 refresh as a research artifact.
- #17 by documenting responsible use, limitations, and defender visibility.
- #18 by naming the observations that the validation checklist should capture.
- #19 by setting boundaries for future work.
