# Validation Overview

Validation is evidence, not a product-bypass claim. Each mode has a narrow
meaning.

| Evidence | Proves | Suggests | Does Not Prove |
| --- | --- | --- | --- |
| Artifact mode | Expected files exist and PE machine identity matches | Build graph is healthy | Runtime re-entry works |
| Architecture report | The launched binary reports expected platform facts | Correct executable was selected | Timer/APC lifecycle works |
| Headless mode | Supported non-interactive setup/re-entry path completes | CI-safe smoke validity | Desktop MessageBox behavior |
| Two live MessageBoxes | Initial execution and timer/APC re-entry occurred | Protection cycle followed intended path | Product evasion or invisibility |
| VMMap/manual observation | Observed region protection changed during the sampled windows | Temporal state model is visible | Every transient state was captured |

## Architecture Matrix

| Architecture | Best Validation | Caveat |
| --- | --- | --- |
| x86 | Live MessageBox plus optional memory-map observation | Historical 32-bit path |
| x64 | Live MessageBox | Sibling design with separate re-entry PIC |
| ARM64 | Hosted headless and architecture checks | Live desktop requires ARM64 lab |
| ARM64EC | Hosted headless and architecture checks | No mixed x64 DLL interop claim |

Every validation page inherits the boundaries in [Responsible Use](../responsible-use.md).
