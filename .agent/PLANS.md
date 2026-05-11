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

### Plan: Timer APC Re-Entry Semantics Fix

#### Objective

Fix the timer/APC proof so the demos prove APC completion-routine execution rather than
only proving that a waitable timer object became signaled.

Definition of done:

- x86, x64, ARM64, and ARM64EC no longer use the timer handle itself as the alertable wait
  object for APC re-entry.
- x86 and x64 local live validation proves actual APC re-entry, not merely a second
  MessageBox caused by a signaled timer wait.
- ARM64 and ARM64EC hosted `windows-11-arm` headless checks complete two benign rounds and
  report at least one callback/re-entry event.
- Docs explain the discovered weakness and the corrected wait semantics.
- PR #23 is updated and stops short of merge.

#### User Decisions And Assumptions

User decisions:

- 2026-05-11: User asked to plan a fix after analysis showed the POC was relying on timer
  signaled-state wakeups rather than proving APC callback execution.
- 2026-05-11: User prefers improving x86/x64 locally first, then validating ARM through
  hosted Windows-on-Arm CI.

Assumptions:

- `SleepEx(INFINITE, TRUE)` or an equivalent alertable wait with no timer-handle object is
  the right primitive for the APC proof path because it returns for APC delivery rather than
  for the timer object becoming signaled.
- The x86/x64 behavior change should remain a benign MessageBox proof of concept and should
  not broaden into payload, persistence, or operational misuse features.
- ARM64EC v1 should continue to prove build/run identity and APC semantics, not mixed x64 DLL
  interop.

#### Context And Evidence

- GitHub Actions run `25645191500`, job `75272673545`, passed all builds and architecture
  probes, then failed `arm64 --mode headless`.
- Failure evidence: ARM64 completed `2/2` headless rounds with `0` timer/APC callbacks.
- Local API probe showed `WaitForSingleObjectEx(timer, alertable)` returned `WAIT_OBJECT_0`
  with `callbacks=0`, while `SleepEx(alertable)` subsequently returned `WAIT_IO_COMPLETION`
  with `callbacks=1`.
- Microsoft's waitable-timer APC documentation warns not to wait on the timer handle when
  using a completion routine because the thread can wake from the timer becoming signaled
  instead of from APC delivery.
- Before the fix, `GargoyleArm64/reentry_arm64.asm`,
  `GargoyleArm64EC/reentry_arm64ec.asm`, and `GargoyleX64/reentry_x64.nasm` all called
  `WaitForSingleObjectEx(timer, INFINITE, TRUE)`.
- Before the fix, `setup.nasm` built a Win32 tail-call chain around
  `WaitForSingleObjectEx` using the timer handle, so x86 was subject to the same semantic
  weakness.

#### Scope

In scope:

- Replace timer-handle alertable waits with APC-specific alertable waits in x86, x64, ARM64,
  and ARM64EC.
- Add callback/re-entry counters or equally clear control-flow evidence for x86/x64, matching
  the stricter ARM evidence.
- Extend acceptance parsing/tests so local validation catches the old false-positive shape.
- Update docs and PR notes with the discovery and corrected semantics.
- Use hosted ARM CI to validate ARM64 and ARM64EC runtime behavior.

Out of scope:

- ARM32.
- ARM64EC mixed x64 DLL interop.
- Non-benign payloads, persistence, credential access, or generalized offensive framework
  behavior.
- Merging PR #23.

#### Interfaces And Data Flow

- Native configuration blocks should carry `SleepEx` or an equivalent alertable-wait API
  address where PIC previously consumed `WaitForSingleObjectEx` for timer waits.
- The setup PIC arms the waitable timer with the existing completion routine and completion
  argument, then enters an alertable wait that can only satisfy the APC proof through APC
  delivery.
- The ARM callback/re-entry path increments an observable counter before restoring execute
  permissions. The x86/x64 live paths prove the same semantics by entering `SleepEx` rather
  than waiting on the timer handle, so the second MessageBox can no longer be produced by
  timer-object signaled-state progress.
- `--mode headless` should remain non-GUI and parse counter evidence from stdout.
- `--mode live` should still show benign MessageBoxes, but validation should distinguish
  initial handoff from APC-backed re-entry.

#### Task Graph

| ID | Task | Depends On | Owner | Files/Area | Validation |
| --- | --- | --- | --- | --- | --- |
| T1 | Add diagnostic evidence shape | none | main | `main.cpp`, `GargoyleX64/`, `GargoyleArm64/`, harness parsers | unit tests |
| T2 | Fix x64 wait semantics | T1 | main | `GargoyleX64/main_x64.cpp`, `setup_x64.nasm`, `reentry_x64.nasm` | x64 live acceptance |
| T3 | Fix x86 wait semantics | T1 | main | `main.cpp`, `setup.nasm`, optional gadget/trampoline layout | x86 live acceptance |
| T4 | Fix ARM wait semantics | T1-T2 | main | `GargoyleArm64/`, `GargoyleArm64EC/` | hosted ARM smoke |
| T5 | Update docs/tests/CI expectations | T1-T4 | main | `src/`, `tests/`, `docs/`, README, PR body | `just check`, `just ci` |

#### Implementation Steps

1. Add a minimal local repro test or native diagnostic expectation that demonstrates
   `SleepEx`/alertable APC delivery returns `WAIT_IO_COMPLETION`, while waiting on the timer
   handle can return `WAIT_OBJECT_0`.
2. Update x64 first because its separate re-entry PIC is the simplest path: replace the
   timer-handle wait with `SleepEx(INFINITE, TRUE)`, making the second live MessageBox
   dependent on APC delivery rather than the timer object's signaled state.
3. Update x86 carefully: preserve the stack-pivot/trampoline shape while replacing the
   timer-handle wait chain with an alertable APC wait and adding observable re-entry evidence.
4. Once local x86/x64 live checks prove true APC re-entry, apply the same wait primitive and
   counter expectations to ARM64/ARM64EC.
5. Push to PR #23, monitor `windows-11-arm`, and inspect logs. Stop after three new CI-fix
   iterations or if ARM64EC ABI/call-check behavior requires a design choice.
6. Update architecture docs to call out the false-positive weakness and the corrected proof.

#### Validation

Targeted checks:

- `just check`
- `just build-debug`
- `just build-x64-debug`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x86`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x86 --mode architecture --skip-build`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64 --mode architecture --skip-build`

Canonical gate:

- `just ci`

Hosted gate:

- PR #23 `Windows 11 ARM smoke`, especially ARM64 and ARM64EC headless modes.

Manual or live checks:

- Confirm the second visible MessageBox is tied to the `SleepEx` APC re-entry path rather
  than timer signaled-state progress.

#### Risks And Stop Conditions

- Stop if the x86 stack-pivot/trampoline change requires a broader redesign than swapping the
  alertable wait primitive.
- Stop if ARM64EC raw PIC execution trips ARM64EC call-checking or thunking requirements that
  need a design decision.
- Stop after three new hosted ARM CI-fix iterations.
- Stop if a proposed fix would broaden the project beyond benign local proof-of-concept
  behavior.

#### Artifact Index

- PR #23: `https://github.com/JLospinoso/gargoyle/pull/23`
- Failing ARM run: `https://github.com/JLospinoso/gargoyle/actions/runs/25645191500`
- Microsoft waitable timer APC reference:
  `https://learn.microsoft.com/en-us/windows/win32/sync/using-a-waitable-timer-with-an-asynchronous-procedure-call`

#### Progress Log

- 2026-05-11: Root cause identified: timer-handle waits can return from signaled timer state
  before the APC completion routine runs.
- 2026-05-11: Plan recorded before implementation.
- 2026-05-11: Implemented `SleepEx(INFINITE, TRUE)` re-entry waits for x86, x64, ARM64, and
  ARM64EC. Updated harness expectations, docs, and setup evidence labels.
- 2026-05-11: Local validation passed: `just check`, x86 Debug/Release live acceptance, x64
  Debug/Release live acceptance, and `just ci`.
- 2026-05-11: Pushed `2a8c336`; hosted Windows build passed and hosted ARM smoke narrowed to
  an ARM64EC access violation immediately after entering dynamic PIC memory. The likely cause
  matches Microsoft's ARM64EC dynamic-code rule: plain `VirtualAlloc` executable pages are
  classified as x64 dynamic code unless allocated with `MEM_EXTENDED_PARAMETER_EC_CODE`.
- 2026-05-11: Added ARM64EC EC-code dynamic allocation, instruction-cache flushing, and
  ARM64EC C++ API wrappers so MSVC-generated exit thunks handle Win32 calls from the PIC path.
- 2026-05-11: Local validation for the ARM64EC fix passed: `just check`, `just ci`, and
  `just docs`.
- 2026-05-11: Hosted ARM fix iteration 1 failed at ARM64EC link time because the VS2022
  ARM64EC import libraries did not resolve `VirtualAlloc2`. Switched EC allocation to resolve
  `VirtualAlloc2` dynamically from `kernelbase.dll`.
- 2026-05-11: Local validation after dynamic resolution passed: `just check` and `just ci`.
- 2026-05-11: Hosted ARM fix iteration 2 built ARM64EC, then failed at runtime with
  `VirtualAlloc2 EC_CODE PIC allocation failed (GetLastError=87)`. Adjusted allocation to
  reserve EC-code address space with `VirtualAlloc2` before committing writable storage
  inside that reservation.
- 2026-05-11: Local validation after reserve-then-commit allocation passed: `just check` and
  `just ci`.
- 2026-05-11: Hosted run `25695045729` passed both `Windows build and Python checks` and
  `Windows 11 ARM smoke`. ARM64 and ARM64EC headless checks completed the requested benign
  timer/APC rounds.

#### Handoff Packet

- Branch: `codex/arm64-arm64ec-parity`
- PR/issue: PR #23, issue #22
- Current status: complete; PR #23 is updated, validated, and ready for review/merge, but not
  merged
- Completed: failure analysis, fix plan, x86/x64/ARM64/ARM64EC wait semantic fix, harness and
  docs updates
- Remaining: none for this plan
- Validation run: local API probe; `just check`; x86 Debug/Release live acceptance; x64
  Debug/Release live acceptance; `just ci`; ARM64EC fix `just check`, `just ci`, and
  `just docs`; dynamic `VirtualAlloc2` resolution fix `just check` and `just ci`;
  reserve-then-commit allocation fix `just check` and `just ci`
- Failed/skipped checks: local ARM build remains unavailable because this workstation lacks
  ARM64/ARM64EC Visual Studio tools; PR #23 hosted ARM smoke validated ARM runtime instead
- Residual risks: ARM64EC v1 still proves build/run/binary identity and APC semantics, not
  mixed x64 DLL interop

### Plan: Issue #22 ARM64/ARM64EC Parity And Windows-On-Arm CI Smoke

#### Objective

Add modern Windows-on-Arm parity through ARM64 and ARM64EC sibling demos, CI-safe
architecture/runtime smoke coverage, and platform-aware acceptance tooling.

Definition of done:

- `Gargoyle.sln` contains `GargoyleArm64` and `GargoyleArm64EC` sibling projects.
- ARM64 and ARM64EC demos build setup/re-entry PIC blobs with `armasm64`.
- Existing x86/x64 binaries and new ARM binaries expose `--architecture-report`.
- ARM binaries expose `--mode live|headless`, `--rounds`, and `--period-ms`.
- `gargoyle-acceptance` supports `x86`, `x64`, `arm64`, and `arm64ec`, plus
  `live`, `architecture`, `headless`, and `artifacts` modes.
- GitHub Actions includes a hosted `windows-11-arm` smoke job.
- Local canonical validation passes and ARM runtime validation is delegated to hosted ARM CI.

#### User Decisions And Assumptions

User decisions:

- 2026-05-10: User approved the ARM64/ARM64EC plan and asked for implementation.
- 2026-05-10: User chose a single focused PR and a creative non-GUI hosted ARM demo.

Assumptions:

- ARM32 remains out of scope because current Windows-on-Arm work is ARM64-centered.
- ARM64EC v1 proves build/run identity and hosted Windows-on-Arm behavior, not mixed x64 DLL
  interop.
- Hosted ARM CI should run short benign console processes and avoid GUI automation.

#### Scope

In scope:

- ARM64/ARM64EC project files, ARM PIC extraction, runtime harnesses, acceptance harness,
  tests, docs, issue, PR, and CI.

Out of scope:

- ARM32.
- Hosted CI MessageBox automation.
- ARM64EC mixed x64 DLL interop.
- Merging the PR.

#### Interfaces And Data Flow

- `--platform` accepts canonical lowercase values `x86`, `x64`, `arm64`, and `arm64ec`; MSBuild
  receives `x86`, `x64`, `ARM64`, and `ARM64EC`.
- `--mode live` builds, validates artifacts and PE machine, launches the demo, parses setup, and
  closes MessageBox windows.
- `--mode artifacts` builds unless skipped, validates required files, and checks PE machine.
- `--mode architecture` runs `--architecture-report` and parses `platform`, `machine`, and
  `pointer_bits`.
- `--mode headless` runs `--mode headless` and parses setup output without MessageBox
  automation.
- `build/ArmPic.targets` assembles ARM PIC sources into COFF with `armasm64`, then
  `build/extract_pic.py` extracts `.text` into raw `.pic` blobs.
- `GARGOYLE_PLATFORM_TOOLSET` can override `PlatformToolset` for hosted ARM images that use a
  compatible Visual Studio toolset such as `v143`.

#### Validation

Targeted checks:

- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x86 --mode architecture --skip-build`
- `uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64 --mode architecture --skip-build`
- `just check`
- `just build-arm64-debug` was probed locally and reached the expected missing ARM toolset
  failure.

Canonical gate:

- `just ci`

Hosted gate:

- `just windows-arm-smoke` on GitHub Actions `windows-11-arm`

#### Risks And Stop Conditions

- Stop if parallel native edits create conflicting artifact names or CLI flags.
- Stop if CI runner availability for `windows-11-arm` requires user or repository-owner judgment.
- Stop after three CI-fix iterations.

#### Progress Log

- 2026-05-10: Created issue #22 and branch `codex/arm64-arm64ec-parity`.
- 2026-05-10: Added ARM64/ARM64EC projects, ARM PIC target, and COFF `.text` extractor.
- 2026-05-10: Added ARM64/ARM64EC runtime demos with architecture-report, live, and headless
  modes.
- 2026-05-10: Extended the acceptance harness, tests, docs, and CI for ARM platforms and modes.
- 2026-05-10: Local x86/x64 architecture acceptance passed for Debug outputs.
- 2026-05-10: Local ARM build probe reached expected MSB8020 missing ARM toolset failure on this
  workstation; hosted `windows-11-arm` CI is the runtime validation target.
- 2026-05-10: `just check` and `just ci` passed locally.

#### Handoff Packet

- Branch: `codex/arm64-arm64ec-parity`
- PR/issue: issue #22; PR pending
- Current status: implementation complete locally; push, PR creation, and hosted CI remain
- Completed: issue; project/build/runtime/harness/tests/docs/CI updates
- Remaining: commit, push, open PR, monitor GitHub checks
- Validation run: x86/x64 Debug architecture acceptance; `just check`; `just ci`
- Failed/skipped checks: local ARM build skipped after expected missing ARM toolset failure
- Residual risks: hosted `windows-11-arm` image/toolset behavior must validate ARM64 and ARM64EC
  runtime smoke paths

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
