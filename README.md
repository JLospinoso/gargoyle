![gargoyle title](https://github.com/JLospinoso/gargoyle/raw/master/title.png)

![gargoyle infographic](https://github.com/JLospinoso/gargoyle/raw/master/infographic.png)

# Gargoyle

Gargoyle is a historical Windows research proof of concept for temporal memory
state. The original Win32/x86 implementation remains the canonical proof: a
benign action is observable during a small work window, while the relevant code
region spends its dormant interval non-executable before timer/APC re-entry.

The refreshed repository keeps that history central while adding sibling x64,
ARM64, and ARM64EC demonstrations, a reproducible validation harness, and clearer
evidence language. It also documents the corrected timer/APC path around
`SleepEx(INFINITE, TRUE)`.

Gargoyle does not claim invisibility or product bypass. It is not a loader,
operator workflow, or deployment guide, and it does not provide persistence,
injection, credential access, networking, or C2 guidance.

## Read Next

- [Documentation home](docs/index.md) for reader paths and project orientation.
- [Responsible use](docs/responsible-use.md) for scope boundaries and non-goals.
- [Quickstart](docs/quickstart.md) for the shortest safe build and validation
  path.
- [Timer APC and SleepEx](docs/concepts/timer-apc-sleepex.md) for the corrected
  alertable-wait evidence path.
- [Architecture comparison](docs/architectures/comparison.md) for what each
  sibling demonstration validates and does not prove.
- [Validation overview](docs/validation/overview.md) for the evidence language
  used across the repository.
- [Research references](docs/research/references.md) and
  [lineage](docs/research/lineage.md) for source mapping and relationship
  boundaries.

## Architecture And Evidence Boundaries

- Win32/x86 is the canonical historical implementation.
- x64, ARM64, and ARM64EC are sibling demonstrations, not replacements for the
  original design.
- The x64 sibling is not a direct port of the original x86 `mshtml.dll`
  gadget/trampoline path.
- x86/x64 live validation uses two benign MessageBoxes. That validates initial
  execution and later controlled re-entry, but not callback identity or every
  memory-protection transition.
- ARM64 and ARM64EC headless validation also checks completed-round and
  callback-round counters, giving stronger callback-delivery evidence.
- ARM64EC exercises the EC-code allocation behavior used by this demo. It does
  not demonstrate mixed x64 DLL interop or prove every ARM64EC dynamic-code
  pattern.

## Local Gate

```powershell
uv sync --all-groups
just ci
```

## Historical Context

- [Gargoyle, a decade later](https://lospino.so/blog/gargoyle-a-decade-later/)
- [Original 2017 article](https://lospino.so/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html)
