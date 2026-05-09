# Future Work And Post-X64 Directions

Future Gargoyle work should preserve the tiny, understandable Win32 proof of
concept while making research directions explicit. New experiments should be
small, reviewable, and easy to separate from the baseline demo.

## Near-Term Direction

- Keep the Win32 path as the reference implementation. Do not replace it with a
  generalized framework or hide the original technique behind large abstraction
  layers.

- Keep the x64 example documented as a sibling architecture rather than a
  transparent port. The x64 calling convention, stack alignment, nonvolatile
  registers, unwind metadata, CFG, and CET all change the design constraints.

- Prefer visible, benign payload evidence for every architecture. The MessageBox
  pattern is intentionally simple because it makes runtime validation easy and
  keeps the repository in research territory.

- Keep defender observations next to offensive-mechanics explanations. Any
  future runtime change should update [Responsible Use, Limitations, And
  Detection](responsible-use.md) and [Validation Checklist](validation-checklist.md).

## X86 To X64 Contrast To Document

- Stack pivoting: the existing x86 implementation pivots through `esp`; x64
  work must account for `rsp` alignment, shadow space, and the Windows x64
  register argument convention.

- Callback shape: the current waitable timer path is compact, but x64 designs
  may choose waitable timers, timer queues, `NtContinue`-style context
  restoration, or another documented callback path. Each choice has different
  defensive visibility.

- Gadget assumptions: x86 `pop reg; pop esp; ret`-style pivots are not a direct
  recipe for x64. The checked-in x64 example uses a separate re-entry PIC; any
  future gadget or context-restoration design should explain provenance and
  failure modes without encouraging broad gadget harvesting.

- Mitigation interaction: CFG, CET, shadow stacks, and continuation-target
  validation can turn historical ROP assumptions into crashes or detections.
  Document those outcomes rather than treating them as blockers to bypass.

- Validation evidence: x64 work needs the same evidence standard as Win32:
  build output, setup banner, benign payload, protection transition, timer
  re-entry, and clear desktop-only checks.

## Possible Companion Detector

A small defensive companion could make the project more useful without changing
the PoC:

- Read a process memory map and highlight private committed regions whose
  protections change between executable and non-executable states.

- Correlate the setup banner addresses with VMMap or debugger observations.

- Emit a short report suitable for the validation checklist.

- Stay local and observational. Do not inject into unrelated processes, bypass
  product protections, or collect private data.

## Experiment Placement

- Keep the default branch focused on the buildable baseline and documented
  validation workflow.

- Put alternate x64 re-entry work in small branches or clearly named docs until
  it has a stable build and a benign acceptance story.

- Document experiments that are interesting but too large, too brittle, or too
  operational for this repository instead of merging them into the core.

- Prefer separate PRs when changes have different review surfaces: docs,
  Win32 hardening, x64 implementation, and detector experiments should not be
  tangled unless the plan explicitly calls for integration.

## Research Questions

- How does the original waitable-timer/APC design compare with later
  timer-queue and `NtContinue` sleep-obfuscation families from a defender's
  point of view?

- Which observations are stable across Windows versions: memory protections,
  VAD state, timer objects, APC delivery, stack shape, and callback targets?

- Can a tiny detector demonstrate the defensive visibility without requiring
  kernel components or product-specific telemetry?

- Which x64 design choices are educational enough to include here, and which
  belong only as references to external work such as YouMayPasser, Cronos, or
  ShellcodeFluctuation?

- The refresh audit mentioned "Mirage" as later related work. What exact public
  source should be cited, and does it belong in the same sleep-obfuscation
  family tree?

## Non-Goals

- No credential theft, persistence, lateral movement, autonomous exploitation,
  staged payload deployment, or C2-oriented features.

- No attempt to keep pace with commercial evasion frameworks.

- No broad payload loader, plugin system, or operator workflow.

- No mitigation-bypass arms race. Platform failures and detections should be
  documented as useful research outcomes.

## Issue Coverage

This page contributes to:

- #13 by keeping the refresh scope explicit.
- #19 by recording post-x64 directions that do not bloat the core PoC.
- #17 by carrying responsible-use boundaries into future experiments.
- #18 by requiring a validation story for future architecture work.
