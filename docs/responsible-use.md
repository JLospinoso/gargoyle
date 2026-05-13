# Responsible Use

Gargoyle is a historical Windows research proof of concept. The documentation
helps readers understand the technique, reproduce the benign demo in a lab, and
recognize defender-visible artifacts. It should not evolve into a general
offensive framework.

## Boundaries

- Keep demo actions benign. The live runtime demonstration should remain the
  visible `gargoyle` MessageBox or an equally harmless local observation.
- Run Gargoyle only on systems you own or have explicit permission to use.
  Prefer disposable Windows VMs or lab machines where interactive window
  automation is acceptable.
- Do not add credential theft, persistence, lateral movement, autonomous
  exploitation, deployment, networking, or operational misuse guidance.
- Treat external dual-use research as historical and defensive context. It is
  not an acceptance target for this repository.
- Preserve the small proof-of-concept shape. A maintainable research artifact is
  more valuable here than a broader evasion platform.

## Current Limitations

- Win32/x86 remains the reference implementation.
- x64, ARM64, and ARM64EC are sibling demonstrations, not transparent ports of
  the original Win32 stack-pivot chain.
- Live validation needs a Windows desktop session because it closes visible
  MessageBox windows.
- CI-safe modes validate build, identity, architecture-report, or headless smoke
  evidence; they do not replace live desktop observation.
- Gargoyle does not make memory disappear. Process memory maps, timer state,
  private allocations, stack shape, and behavioral telemetry can still expose
  the demo.
- Platform mitigations and endpoint instrumentation can affect ROP, callbacks,
  dynamic code, and timing. Treat failures as research data, not as reasons to
  add bypass features.

## Defensive Visibility

Defenders and lab users can reason about:

- memory-protection transitions over time;
- private code-adjacent memory such as PIC, fallback gadget, scratch stack, and
  trampoline regions;
- waitable timer, APC, and alertable-wait behavior;
- unusual Win32 stack-pivot and callback targets;
- stdout setup banners and visible benign MessageBox windows;
- memory-forensics views such as VAD, page-table, or memory-map comparisons.

## Safe Exercises

- Build the Debug and Release configurations and run the acceptance harness in
  an owned lab.
- Record setup-banner addresses and inspect the process before the first
  MessageBox is dismissed, while dormant, and after timer/APC re-entry.
- Compare what user-mode memory-map tools show with memory-forensics workflows.
  Focus on existence, protection state, and callback/timer context.
- Use [Research Context](research/context.md) and
  [References](research/references.md) to compare Gargoyle-specific observations
  with broader sleep-obfuscation and memory-forensics work.
