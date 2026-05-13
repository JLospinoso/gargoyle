# Docs Style

Use a calm, historical, technical voice. The docs should make Gargoyle easy to
understand, safe to reproduce, hard to misinterpret, and boring to misuse.

## Preferred Language

| Use | Avoid |
| --- | --- |
| benign demo action | payload, except when quoting historical context |
| temporal memory-state evasion | invisibility |
| non-executable while dormant | hidden from memory |
| timer/APC re-entry | wakeup magic |
| sibling demonstration | port for x64, ARM64, or ARM64EC |
| defender-visible artifacts | bypass artifacts |

## Claim Words

- `Proves`: use only when the harness or manual check directly observes the
  property.
- `Suggests`: use when the evidence is consistent but incomplete.
- `Does not prove`: use when the repository lacks instrumentation or scope for
  the claim.

## Safety Boundaries

Every mechanics page should link to [Responsible Use](../responsible-use.md).
External offensive or dual-use references belong in [Research](../research/context.md)
as historical and defensive context, not as project goals.

## Diagram Rules

Use Mermaid for lifecycle, flow, and lineage diagrams. Diagrams should clarify
state, evidence, or responsibility. They should not provide adaptation recipes
or broaden the runtime scope.
