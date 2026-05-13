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

## ARMASM PIC

ARM64 and ARM64EC assembly is assembled to COFF objects with `armasm64`, then
`build/extract_pic.py` extracts the `.text` section to a `.pic` file. The
extractor rejects sections with relocations unless explicitly told otherwise.

## Offset Discipline

Assembly reads configuration fields by fixed offsets. Any change to C++ structs
must keep the assembly constants, static assertions, setup banners, and harness
parsers aligned.

## Review Boundary

Assembly changes should keep the benign MessageBox or headless smoke behavior.
Do not add deployment, staging, persistence, credential access, or adaptation
features.
