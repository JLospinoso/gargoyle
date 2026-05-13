# Maintainer Guide

Maintainers should keep Gargoyle small, reproducible, and safe to discuss. The
Win32 path remains the canonical proof of concept. Other architectures are
sibling demonstrations.

## Review Checklist

- Does the change preserve benign MessageBox or headless smoke behavior?
- Does it avoid credential access, persistence, deployment, networking, and
  operator workflows?
- Does it update docs and validation claims when mechanics change?
- Does it keep architecture-specific caveats explicit?
- Does `just check` pass?
- Does code affecting native output run the relevant build or acceptance checks?

## Change Sizing

Prefer focused PRs for docs, build tooling, architecture mechanics, acceptance
harness behavior, and research references. Do not mix a runtime change with a
large research rewrite unless the plan explicitly calls for it.

## Future Work Boundary

Interesting experiments can be documented as research questions, but the default
branch should remain a buildable, benign proof of concept. Platform failures and
detections are useful outcomes, not invitations to add bypass features.

See [Docs Style](docs-style.md) for claim language.
