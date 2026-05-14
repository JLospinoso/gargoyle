# Assembly And PIC

The native demonstrations use raw position-independent code artifacts. The goal
is a small, inspectable research artifact, not a generalized compiler or loader.

## NASM PIC

Win32 and x64 PIC are assembled as flat binaries:

- `setup.nasm` -> `setup.pic`
- `gadget.nasm` -> `gadget.pic`
- `GargoyleX64/setup_x64.nasm` -> `setup_x64.pic`
- `GargoyleX64/reentry_x64.nasm` -> `reentry_x64.pic`

`build/NasmPic.targets` invokes NASM with `-f bin` and writes output beside the
native executable.

| Source | Artifact | Produced By | Consumed By |
| --- | --- | --- | --- |
| `setup.nasm` | `setup.pic` | `build/NasmPic.targets` | Win32 C++ harness |
| `gadget.nasm` | `gadget.pic` | `build/NasmPic.targets` | Win32 fallback gadget path |
| `GargoyleX64/setup_x64.nasm` | `setup_x64.pic` | `build/NasmPic.targets` | x64 C++ harness |
| `GargoyleX64/reentry_x64.nasm` | `reentry_x64.pic` | `build/NasmPic.targets` | x64 C++ harness and timer callback |

## ARMASM PIC

ARM64 and ARM64EC assembly is assembled to COFF objects with `armasm64`, then
`build/extract_pic.py` extracts the `.text` section to a `.pic` file. The
extractor rejects sections with relocations unless explicitly told otherwise.

| Source | Artifact | Produced By | Notes |
| --- | --- | --- | --- |
| `GargoyleArm64/setup_arm64.asm` | `setup_arm64.pic` | `build/ArmPic.targets` and `extract_pic.py` | Extracts `.text` bytes from the ARMASM COFF object. |
| `GargoyleArm64/reentry_arm64.asm` | `reentry_arm64.pic` | `build/ArmPic.targets` and `extract_pic.py` | Exports the callback entry used at offset `16`. |
| `GargoyleArm64EC/setup_arm64ec.asm` | `setup_arm64ec.pic` | `build/ArmPic.targets` and `extract_pic.py` | Uses ARM64EC assembly options from the project. |
| `GargoyleArm64EC/reentry_arm64ec.asm` | `reentry_arm64ec.pic` | `build/ArmPic.targets` and `extract_pic.py` | Exports the callback entry used at offset `16`. |

`extract_pic.py` parses COFF section headers, extracts the selected section
name, and writes raw bytes to the requested `.pic` output. The default section
is `.text`. Relocations are rejected by default because the runtime expects
position-independent bytes; `--allow-relocations` exists for diagnostics, not
for the normal build path.

## Offset Discipline

Assembly reads configuration fields by fixed offsets. Any change to C++ structs
must keep the assembly constants, static assertions, setup banners, and harness
parsers aligned.

| Architecture | Callback Offset | Counter Behavior |
| --- | --- | --- |
| x86 | Gadget/trampoline path, not a separate callback PIC offset. | Live path is MessageBox-observed; no native callback counter. |
| x64 | `reentry_x64.pic + 16` | Live path is MessageBox-observed; the re-entry restore is idempotent after callback execution. |
| ARM64 | `reentry_arm64.pic + 16` | `completed_rounds` and `callback_rounds` are checked after headless runs. |
| ARM64EC | `reentry_arm64ec.pic + 16` | `completed_rounds` and `callback_rounds` are checked after headless runs. |

## Review Boundary

Assembly changes should keep the benign MessageBox or headless smoke behavior.
Do not add deployment, staging, persistence, credential access, or adaptation
features.
