# Gargoyle Documentation

Gargoyle is a historical Windows research proof of concept. Its durable lesson
is temporal memory state: code can be executable during a small benign work
window, then non-executable while the process waits for timer/APC re-entry.

The original Win32 implementation remains the canonical story. The x64, ARM64,
and ARM64EC projects are sibling demonstrations that make the idea easier to
validate on modern Windows architectures; they are not replacement designs or a
general runtime framework.

## Reader Paths

| Reader | Start Here | Outcome |
| --- | --- | --- |
| Curious technical reader | [Responsible Use](responsible-use.md), then [Temporal Memory State](concepts/temporal-memory-state.md) | Understand what Gargoyle demonstrates without running it. |
| Defender or lab reproducer | [Quickstart](quickstart.md), then [Validation Overview](validation/overview.md) | Build and reproduce benign evidence in an owned Windows lab. |
| Maintainer or contributor | [Maintainer Guide](contributing/maintainer-guide.md), then [Tests And CI](implementation/tests-and-ci.md) | Make focused changes without safety or scope drift. |

## What The Refresh Adds

- Modern MSBuild, NASM, ARMASM, `uv`, `just`, and GitHub Actions validation.
- A typed Python acceptance harness with live, artifact, architecture, and
  headless modes.
- Sibling x64, ARM64, and ARM64EC examples with explicit architecture caveats.
- Corrected timer/APC evidence semantics based on alertable `SleepEx` waits.
- A layered documentation set that separates concept, implementation, validation,
  and research claims.

## What This Project Does Not Claim

Gargoyle does not make memory disappear, does not claim product evasion, and
does not provide deployment, persistence, credential access, networking, or
operator guidance. The useful claim is narrower: memory-state observations
are temporal, and point-in-time executable-page scans can miss code that is
non-executable while dormant.

## Fast Preflight

```powershell
uv sync --all-groups
just check
uv run --all-groups gargoyle-acceptance --configuration Debug
```

Use `just ci` as the canonical repository gate before publication or merge.
Runtime validation is Windows-only. The live path opens benign MessageBox
windows and should only run in an owned Windows desktop lab.
