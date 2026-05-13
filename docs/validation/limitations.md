# Validation Limitations

Gargoyle is intentionally small and observable. Its validation does not claim
more than the harness and manual checks observe.

## Not Claimed

- No product-bypass claim.
- No stealth or invisibility claim.
- No guarantee across Windows versions or endpoint policies.
- No guarantee that manual tooling captures every transient state.
- No persistence, injection, deployment, networking, or credential-access claim.
- No claim that x64, ARM64, or ARM64EC are transparent ports of the Win32 design.

## How To Read Failures

Failures are research data. A build, runtime, mitigation, or endpoint failure
should be documented and investigated within the benign proof-of-concept scope,
not worked around by adding broader evasion features.

## Language Discipline

Use `proves` only when a check directly observes the property. Use `suggests`
when evidence is consistent but incomplete. Use `does not prove` when a claim is
outside the instrumentation or scope.

See [Docs Style](../contributing/docs-style.md) for wording examples.
