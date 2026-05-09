# Execution Plans

Use this file for Gargoyle's durable planning convention. Active plans may live here for
small efforts or in `.agent/plans/YYYY-MM-DD-slug.md` when a plan grows large enough to
deserve its own file.

Create or update an ExecPlan for complex features, significant refactors, architecture work,
toolchain migrations, security-sensitive changes, benchmark or validation efforts, multi-hour
tasks, multi-agent work, or work with unclear acceptance criteria.

Do not require a plan for small bug fixes, narrow documentation edits, simple command output,
or code-review-only tasks unless the user asks.

An ExecPlan is a living, restartable artifact. Another engineer or agent should be able to
continue from the plan, branch state, validation logs, linked artifacts, and changed files
without reading the full chat.

## Active Plans

### Plan: Native Quality Hardening

#### Objective

Raise the C++/MSBuild quality gate with MSVC-native warnings, code analysis, and
AddressSanitizer build coverage while keeping the proof-of-concept behavior intact.

Definition of done:

- Native projects build cleanly with stricter compiler diagnostics.
- `just` exposes code-analysis and ASan build recipes for x86 and x64.
- `just ci` includes the native quality gate.
- Any C++ warning fixes are small, behavior-preserving elegance improvements.
- PR #21 is updated, green, and still not merged.

#### User Decisions And Assumptions

User decisions:

- 2026-05-09: User asked to crank up C++ sanitizers/linters and look for elegance
  improvements.

Assumptions:

- Use MSVC-native quality tooling because `clang-tidy`, `clang-format`, and `cppcheck`
  are not available on this workstation.
- Avoid enabling Control Flow Guard or other mitigations that would interfere with raw PIC
  indirect calls unless a separate plan covers the runtime consequences.

#### Context And Evidence

- Local probes found no `clang-tidy`, `clang-format`, or `cppcheck` on `PATH`.
- `RunCodeAnalysis=true` works when run serially.
- `EnableASAN=true` works for x86 and x64 builds; incremental linking should be disabled
  for ASan to avoid linker warning LNK4300.

#### Implementation Steps

1. Tighten shared MSBuild C++ diagnostics in `build/Gargoyle.Cpp.props`.
2. Add `just native-analyze-*`, `native-asan-*`, and `native-check` recipes.
3. Fix surfaced C++ warnings with small readability/robustness edits.
4. Update docs and durable plan state.
5. Run native checks, live acceptance where needed, `just ci`, push, and monitor CI.

#### Validation

Targeted checks:

- `just native-check`
- `just build-all`
- `just acceptance-all`

Canonical gate:

- `just ci`

#### Risks And Stop Conditions

- Stop if ASan instrumentation breaks the raw PIC demo in a way that requires changing
  proof-of-concept mechanics.
- Stop if code analysis reports issues that need design judgment rather than local cleanup.

#### Progress Log

- 2026-05-09: Plan recorded after local toolchain probes.
- 2026-05-09: Added W4/WX, SDL, conformance mode, MSVC code-analysis recipes, and
  AddressSanitizer build recipes.
- 2026-05-09: Native quality gate passed with `just native-check`.
- 2026-05-09: Full validation passed with `just ci` and `just acceptance-all`.

#### Handoff Packet

- Branch: `codex/issue-backlog`
- PR/issue: PR #21
- Current status: implementation complete locally
- Remaining: commit, push, and monitor CI
- Validation run: `just native-check`, `just ci`, `just acceptance-all`
- Failed/skipped checks: one parallel `just ci` attempt failed with LNK1168 because live
  acceptance held `Debug\Gargoyle.exe`; standalone rerun passed.

### Plan: MSBuild Reshape And x64 Timer-Reentry Parity

#### Objective

Make Visual Studio/MSBuild the polished native build authority and upgrade the x64 example
from a one-shot Win64 ABI smoke to a benign timer/APC re-entry demonstration.

Definition of done:

- `Gargoyle.sln` is the only solution entrypoint.
- Shared MSBuild files hold common C++ and NASM behavior.
- x64 shows two `gargoyle x64` MessageBox rounds through timer/APC re-entry.
- The Python acceptance harness can validate both `x86` and `x64`.
- Docs, tests, `just ci`, and GitHub Actions pass.

#### User Decisions And Assumptions

User decisions:

- 2026-05-09: Use MSBuild-native project reshaping rather than CMake.
- 2026-05-09: Target timer re-entry parity for x64.
- 2026-05-09: Do a full project reshaping.
- 2026-05-09: Use an external x64 re-entry stub.
- 2026-05-09: Let Visual Studio defaults drive native output directories.

Assumptions:

- x64 parity means timer/APC re-entry plus read-only idle `setup_x64.pic`, not a full
  x64 ROP/NtContinue design.
- The external x64 PIC may remain executable as the re-entry surface, analogous to the
  Win32 executable gadget surface.
- Payloads remain benign MessageBox demonstrations only.

#### Context And Evidence

- `Gargoyle.sln` already contains `Gargoyle` and `GargoyleX64`.
- `GargoyleX64` currently loads `setup_x64.pic`, calls `VirtualProtectEx`, shows one
  `gargoyle x64` MessageBox, and returns.
- The acceptance harness currently hardcodes `Platform=x86` and Win32 artifacts.
- Current branch: `codex/issue-backlog`, PR #21.

#### Interfaces And Data Flow

- `gargoyle-acceptance` gains `--platform x86|x64`, defaulting to `x86`.
- x64 runtime gains a second raw PIC, `reentry_x64.pic`, used as the wait/re-entry surface.
- `just ci` continues as the canonical gate and builds both platforms.
- Documentation records the MSBuild-native choice and the x64 timer/APC behavior.

#### Task Graph

| ID | Task | Depends On | Owner | Files/Area | Validation |
| --- | --- | --- | --- | --- | --- |
| T1 | Record plan state | none | main | `.agent/PLANS.md` | review diff |
| T2 | Reshape MSBuild files | T1 | main | solution/project/build files | `just build-all` |
| T3 | Implement x64 timer/APC loop | T2 | main | `GargoyleX64/` | x64 smoke |
| T4 | Extend harness and tests | T2-T3 | main | `src/`, `tests/` | `just test`, live acceptance |
| T5 | Update docs and CI evidence | T4 | main | docs/readmes/agent notes | `just docs`, `just ci` |

#### Implementation Steps

1. Add shared MSBuild props/targets and remove the standalone x64 solution.
2. Convert NASM custom builds to shared `NasmPic` items that emit to `$(OutDir)`.
3. Add `reentry_x64.nasm` and expand the x64 configuration/runtime loop.
4. Add platform-aware build, artifact discovery, setup parsing, and MessageBox validation.
5. Update docs and validation commands.
6. Run targeted validation, `just ci`, push the PR branch, and monitor CI.

#### Validation

Targeted checks:

- `just build-debug`
- `just build-release`
- `just build-x64-all`
- `just check`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x86`
- `uv run --all-groups gargoyle-acceptance --configuration Release --platform x86`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64`
- `uv run --all-groups gargoyle-acceptance --configuration Release --platform x64`

Canonical gate:

- `just ci`

#### Risks And Stop Conditions

- Stop if x64 timer/APC parity requires unsafe payload behavior or mitigation-bypass work.
- Stop if dynamically generated executable memory is blocked in a way that needs user policy
  judgment.
- Stop if CI needs more than three fix iterations.

#### Progress Log

- 2026-05-09: Plan approved by user and implementation started.
- 2026-05-09: Added shared MSBuild props/targets, removed the standalone x64 solution,
  and moved NASM PIC output to `$(OutDir)`.
- 2026-05-09: Implemented `reentry_x64.pic` and upgraded the x64 setup PIC to a benign
  timer/APC re-entry loop.
- 2026-05-09: Extended `gargoyle-acceptance` with `--platform x86|x64` and added x64
  banner/artifact validation.
- 2026-05-09: Validation passed: `just check`, `just build-all`, `just acceptance-all`,
  and `just ci`.

#### Handoff Packet

- Branch: `codex/issue-backlog`
- PR/issue: PR #21, issue #2
- Current status: implementation complete locally
- Completed: MSBuild reshape; x64 timer/APC re-entry; platform-aware acceptance harness;
  docs/tests/agent notes
- Remaining: commit, push, and monitor GitHub Actions
- Validation run: `just check`, `just build-all`, `just acceptance-all`, `just ci`
- Failed/skipped checks: none
- Residual risks: x64 uses a separate executable re-entry PIC rather than an x64 ROP or
  context-restoration design; this is intentional and documented.

### Plan: 2026 Issue Backlog Completion

#### Objective

Produce ready-to-merge pull request coverage for every currently open Gargoyle issue:
#2 and #13-#19. Stop before merging.

Definition of done:

- Each open issue is either closed by a ready PR or explicitly covered by a ready PR body.
- CI passes on every opened PR, or any blocker is documented with logs and next action.
- `master` is left unmerged; local branches/PRs are ready for the user to review.

#### User Decisions And Assumptions

User decisions:

- 2026-05-08: User asked to implement all outstanding issues and stop short of merging PRs.
- 2026-05-08: User explicitly asked to work in the spirit of ExecPlans and subagents.

Assumptions:

- "Outstanding issues" means open issues in `JLospinoso/gargoyle`: #2, #13, #14, #15,
  #16, #17, #18, and #19.
- PR #20 already landed the first build baseline and acceptance harness, advancing #14 and
  #18, but follow-up docs and issue closure language are still needed.
- The x64 issue can be satisfied by a documented minimal x64 prototype with clear remaining
  blockers if a complete live x64 Gargoyle chain is too large or risky for this pass.

#### Context And Evidence

- `master` is at `f59b182` (`feat(build): add Windows baseline and acceptance harness`).
- Open issues discovered through GitHub search/API:
  - #2: x64 proof of concept.
  - #13: parent 2026 refresh.
  - #14: modernize build and developer workflow.
  - #15: reference map.
  - #16: preserve and harden Win32 PoC.
  - #17: detection, limitations, and responsible-use framing.
  - #18: validation workflow and reproducible demo notes.
  - #19: post-x64 directions.
- Current validation gate is `just ci`; PR #20 post-merge CI passed on `master`.
- `gh` is not installed locally; use local `git` for commits/pushes and the GitHub connector
  for PR creation/metadata. Use GitHub REST for public issue/check inventory when useful.

#### Scope

In scope:

- Repo-local agent and plan conventions from the dotfiles admonitions.
- Documentation and navigation updates for build, validation, references, limitations,
  responsible use, Win32 architecture, and future work.
- Focused Win32 diagnostics/hardening that preserves the small original PoC.
- Minimal x64 implementation/prototype or documented plan with compile-time artifacts where
  practical.
- PRs that are ready for review/merge but not merged.

Out of scope:

- Turning Gargoyle into a general offensive framework.
- Adding credential theft, persistence, autonomous exploitation, or non-benign payloads.
- Admin bypasses or production-like operations.
- Merging the resulting PRs.

#### Interfaces And Data Flow

- Docs/MkDocs navigation may gain pages for references, responsible use, Win32 architecture,
  validation, future work, and x64.
- `main.cpp` diagnostics may become more explicit around gadget source, protection changes,
  timer setup, stack trampoline, and setup failure paths.
- Project files may gain x64-facing artifacts only if they preserve Win32 behavior and the
  canonical `just ci` gate remains green.

#### Task Graph

| ID | Task | Depends On | Owner | Files/Area | Validation |
| --- | --- | --- | --- | --- | --- |
| T1 | Finalize agent scaffolding | none | main | `AGENTS.md`, `.agent/PLANS.md` | `git diff --check`, `just ci` |
| T2 | Reference/responsible-use/future-work docs | T1 | docs worker + main | `docs/`, `README.md`, `mkdocs.yml` | `just docs`, `just check` |
| T3 | Win32 diagnostics and architecture docs | T1 | worker + main | `main.cpp`, `docs/` | `just build-all`, acceptance Debug/Release |
| T4 | x64 prototype or documented minimal path | T1 | worker + main | project/assembly/docs | `just ci`, targeted build if added |
| T5 | Publish PRs and monitor CI | T1-T4 | main | GitHub | GitHub checks pass |

#### Parallel Work Packages

- Package: Docs/reference map
  Owner: subagent worker
  Write scope: new docs pages only unless main integrates navigation.
  Output: annotated references, limitations, responsible-use, and future-work text.
  Validation: Markdown renders through `mkdocs build --strict`.
  Integration: main reconciles README and `mkdocs.yml` changes.

- Package: Win32 hardening
  Owner: subagent worker
  Write scope: `main.cpp` and one Win32 architecture doc.
  Output: clearer diagnostics and architecture explanation without broad refactor.
  Validation: `just build-all`, acceptance harness.
  Integration: main reviews safety and keeps source behavior benign.

- Package: x64 path
  Owner: subagent worker
  Write scope: x64-specific docs/files.
  Output: minimal prototype or decision-complete implementation plan satisfying #2.
  Validation: compile/docs checks where applicable.
  Integration: main decides whether to ship code, docs, or both.

#### Implementation Steps

1. Commit and publish the agent scaffolding branch as a draft/ready PR if it remains separate.
2. Spawn subagents for docs, Win32 hardening, and x64 path exploration/implementation.
3. Implement/integrate changes on one or more branches with clear issue-closing PR bodies.
4. Run targeted validation and `just ci` for each branch.
5. Push branches, open PRs, mark ready, and monitor GitHub checks.
6. Stop before merging and leave a concise handoff packet.

#### Validation

Targeted checks:

- `git diff --check`
- `just docs`
- `just build-all`
- `uv run --all-groups gargoyle-acceptance --configuration Debug`
- `uv run --all-groups gargoyle-acceptance --configuration Release`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64`
- `uv run --all-groups gargoyle-acceptance --configuration Release --platform x64`

Canonical gate:

- `just ci` should pass unless the plan documents a blocker.

Manual or live checks:

- GitHub Actions for every opened PR should complete successfully.

#### Risks And Stop Conditions

- Stop if potential secrets/private data appear in a diff, output, log, or artifact.
- Stop if x64 implementation requires unsafe payload behavior or broad offensive framework
  features to satisfy the issue.
- Stop if CI needs more than three fix iterations.
- Stop if branch stacking makes a PR impossible to review without user direction.

#### Surprises And Discoveries

- 2026-05-08: Direct unauthenticated issue-list endpoint returned a null-shaped PowerShell
  object, while GitHub search and connector inventory returned all eight open Gargoyle issues.

#### Artifact Index

- Plan file: `.agent/PLANS.md`
- PR #20: `https://github.com/JLospinoso/gargoyle/pull/20`

#### Progress Log

- 2026-05-08: Created this ExecPlan and identified issue inventory.
- 2026-05-08: Added repo-local `AGENTS.md` and expanded `.agent/PLANS.md`.
- 2026-05-08: Integrated docs/reference, responsible-use, validation, future-work, Win32
  architecture, Win32 diagnostics, and x64 prototype work packages.
- 2026-05-08: `just build-x64-all`, `just docs`, `just ci`, Win32 Debug/Release
  acceptance, and a Debug x64 MessageBox smoke passed on `codex/issue-backlog`.
- 2026-05-09: Follow-up work upgraded x64 from a one-shot prototype to a
  timer/APC re-entry example with `just acceptance-all` coverage.

#### Decision Log

- 2026-05-08: Treat #14/#18 as advanced but still open until follow-up PRs explicitly cover
  remaining documentation and validation checklist requirements.

#### Handoff Packet

- Branch: `codex/issue-backlog`
- PR/issue: PR #21 against `master`
- Current status: implementation complete locally; follow-up push and CI monitoring remain
- Completed: issue inventory; agent scaffolding; docs/reference work; Win32 diagnostics;
  x64 timer/APC re-entry; MSBuild-native reshaping; platform-aware acceptance harness
- Remaining: commit, push, and monitor CI
- Validation run: `just build-all`, `just check`, `just acceptance-all`, and `just ci`
- Failed/skipped checks: none
- Rollout or operational notes: stop before merge
- Residual risks: x64 uses a separate executable re-entry PIC rather than an x64 ROP or
  context-restoration design; this is intentional and documented.

## Plan Template

### Plan: <Title>

#### Objective

State the user-visible outcome.

Definition of done:

- <Observable completion condition>

#### User Decisions And Assumptions

User decisions:

- <Decision and date/source>

Assumptions:

- <Assumption to verify or preserve>

#### Context And Evidence

List the repo facts, files, commands, docs, issues, PRs, logs, and prior decisions discovered
before implementation.

#### Scope

In scope:

- <Item>

Out of scope:

- <Item>

#### Interfaces And Data Flow

Describe CLI, project-file, build, assembly, Python API, configuration, documentation,
workflow, or artifact changes. Include compatibility notes and migration constraints when
relevant.

#### Task Graph

Use this section for multi-step, multi-agent, multi-worktree, or multi-PR plans. Keep it short
for simple work.

| ID | Task | Depends On | Owner | Files/Area | Validation |
| --- | --- | --- | --- | --- | --- |
| T1 | <Task> | none | main | <Area> | <Check> |

#### Parallel Work Packages

Use only when work can be safely split.

- Package: <Name>
  Owner: <main/subagent/worker>
  Write scope: <Files or modules>
  Output: <Expected result>
  Validation: <Checks>
  Integration: <How main agent integrates result>

#### Implementation Steps

1. <Step>
2. <Step>
3. <Step>

#### Validation

Targeted checks:

- <Command and expected result>

Canonical gate:

- `just ci` should pass unless the plan documents a blocker.

Manual or live checks:

- <Acceptance harness run, Windows desktop check, PR/CI evidence, or other manual evidence>

#### Risks And Stop Conditions

- <Risk or condition that requires user input>

#### Surprises And Discoveries

- YYYY-MM-DD: <Discovery, impact, and plan adjustment>

#### Artifact Index

- <File, PR, issue, log, workflow run, screenshot, or report>

#### Progress Log

- YYYY-MM-DD: <Status update and validation evidence>

#### Decision Log

- YYYY-MM-DD: <Decision and rationale>

#### Handoff Packet

- Branch:
- PR/issue:
- Current status:
- Completed:
- Remaining:
- Validation run:
- Failed/skipped checks:
- Rollout or operational notes:
- Residual risks:
