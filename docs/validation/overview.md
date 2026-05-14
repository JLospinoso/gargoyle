# Validation Overview

Validation is evidence, not a product-bypass claim. Each mode has a narrow
meaning.

| Evidence | Proves | Suggests | Does Not Prove |
| --- | --- | --- | --- |
| Artifact mode | Expected files exist and PE machine value is compatible with the requested platform | Build graph is healthy | Runtime re-entry works |
| Architecture report | The launched binary reports expected platform facts | Correct executable was selected | Timer/APC lifecycle works |
| ARM64/ARM64EC headless mode | Configured setup/re-entry rounds complete and callback counters meet expectations | CI-safe callback delivery evidence is healthy | Desktop MessageBox behavior, every protection transition, product evasion, or invisibility |
| Two live x86/x64 MessageBoxes | Initial execution and later re-entry into the benign demo path occurred | The intended timer/APC path after alertable `SleepEx` is behaving consistently | Callback identity, every protection transition, product evasion, or invisibility |
| VMMap/manual observation | Observed region protection changed during the sampled windows | Temporal state model is visible | Every transient state was captured |

## Architecture Matrix

| Architecture | Best Validation | Caveat |
| --- | --- | --- |
| x86 | Live MessageBox plus optional memory-map observation | Historical 32-bit path; no independent callback counter |
| x64 | Live MessageBox | Sibling design with separate re-entry PIC; no independent callback counter |
| ARM64 | Hosted headless and architecture checks with completed/callback counters | Live desktop requires ARM64 lab |
| ARM64EC | Hosted headless and architecture checks with completed/callback counters | No mixed x64 DLL interop claim |

## Live Evidence Caveat

The second live MessageBox validates the controlled re-entry path after an
alertable `SleepEx` wait in this demo. It is consistent with the intended
timer/APC path, but the live x86/x64 check does not independently prove callback
identity or observe every memory-protection transition. ARM64 and ARM64EC
headless validation additionally checks completed-round and callback-round
counters, so its non-interactive evidence is stronger for callback delivery.

Every validation page inherits the boundaries in [Responsible Use](../responsible-use.md).
