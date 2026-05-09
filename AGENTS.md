# Gargoyle Agent Instructions

This file defines repository-local expectations for automated coding agents working in
Gargoyle. It specializes the workstation-level Codex instructions with the commands,
boundaries, and safety context that matter for this project.

## Working Model

- Discover current repository facts before editing. Read the relevant C++, NASM, Python,
  tests, docs, `justfile`, and workflow files before assuming behavior.
- Prefer `rg` or `rg --files` for search.
- Keep changes scoped to the requested behavior and preserve the existing proof-of-concept
  architecture unless a plan explicitly changes it.
- Prefer existing project patterns over new abstractions. The Python package is typed,
  linted, documented, and validated through `uv` and `just`.
- Use Conventional Commits for commits and PR titles unless the user requests otherwise.

## Canonical Sources

- `Gargoyle.sln`, `Gargoyle.vcxproj`, `main.cpp`, `setup.nasm`, and `gadget.nasm` are the
  source of truth for the Win32 proof of concept. The root solution also includes the
  `GargoyleX64` project.
- `GargoyleX64/` contains the sibling x64 timer/APC example. It is not a replacement
  for the Win32 baseline unless a plan explicitly changes that.
- `src/gargoyle_acceptance/` and `tests/` are the source of truth for the Python acceptance
  harness.
- `justfile` is the source of truth for local validation commands.
- `.github/workflows/ci.yml` is the source of truth for GitHub Actions CI.
- `README.md`, `docs/acceptance.md`, and `docs/api.md` should be kept aligned with behavior
  changes.

## Toolchain And Platform

- Gargoyle's reference baseline is a 32-bit Windows proof of concept. Keep Win32
  validation on `Platform=x86` unless a plan explicitly changes it. The `GargoyleX64/`
  sibling example builds with `Platform=x64` and should stay clearly separated from the
  Win32 baseline.
- The project expects a current Visual Studio C++ toolchain, Windows SDK selection through
  `WindowsTargetPlatformVersion` `10.0`, NASM on `PATH`, `uv`, and Python 3.13.
- The `MSBUILD` environment variable may override MSBuild discovery. Do not hard-code
  workstation-specific tool paths unless they are documented examples.
- The live acceptance harness opens and closes benign `gargoyle` MessageBox windows. Run it
  only in a Windows desktop session where that interaction is acceptable.

## Planning Convention

- Use `.agent/PLANS.md` for complex features, significant refactors, architecture work,
  toolchain migrations, security-sensitive changes, multi-hour tasks, multi-agent work, or
  unclear acceptance criteria.
- Keep active plans current with decisions, assumptions, progress, discoveries, validation,
  artifacts, blockers, and residual risks.
- Small localized fixes, narrow docs edits, and review-only tasks do not require a plan unless
  the user asks for one.

## Write Scope

- Edit only files needed for the task.
- Do not commit generated or local outputs such as `.venv/`, `.mypy_cache/`, `.ruff_cache/`,
  `.pytest_cache/`, `.coverage`, `coverage.xml`, `site/`, `.vs/`, `Debug/`, or `Release/`.
- Do not silently revert unrelated user changes. If unrelated dirty files block safe work,
  stop and ask for direction.
- When updating behavior, update tests and docs in the same change when practical.

## Validation

Canonical gate:

```powershell
just ci
```

Useful targeted checks:

```powershell
just lock-check
just build-debug
just build-release
just build-x64-all
just native-check
just check
uv run --all-groups gargoyle-acceptance --configuration Debug
uv run --all-groups gargoyle-acceptance --configuration Release
uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64
uv run --all-groups gargoyle-acceptance --configuration Release --platform x64
```

- Run targeted checks while iterating, then run `just ci` before claiming completion when
  practical.
- Run `just native-check` when changes affect C++ source, Visual Studio project settings,
  NASM build integration, or native output layout.
- Run the live `gargoyle-acceptance` checks when changes affect the C++/assembly runtime,
  Visual Studio project configuration, output artifacts, Windows message-box automation, or
  acceptance harness behavior.
- Run `just build-x64-all` when changes affect `GargoyleX64/` or root build orchestration.
- Summarize any command that could not be run and why.

## Safety Rules

- Do not commit secrets, credentials, PHI, private data, local Codex state, or unnecessary
  private machine paths.
- Stop if sensitive data appears in diffs, logs, outputs, or artifacts.
- Keep this repository focused on the documented research and validation proof of concept.
  Do not add credential theft, persistence, autonomous exploitation, payload deployment, or
  operational misuse guidance.
- Ask before destructive cleanup, credential changes, admin bypasses, broad environment
  changes, or user-impacting operations not already approved.

## Completion Standard

- The requested behavior is implemented or the plan is decision-complete.
- Relevant docs, tests, examples, and validation commands are updated.
- Validation has passed, or skipped/failed checks and residual risks are clearly documented.
- The final response summarizes changed behavior, validation, and any remaining cleanup.
