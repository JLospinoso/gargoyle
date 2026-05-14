# ROP, Stack Pivoting, And PIC

The original Win32 proof of concept used a compact ROP and stack-pivot shape to
re-enter code that had parked itself as non-executable.

## Historical Shape

`main.cpp` prepares a configuration block, scratch stack, and trampoline frame.
`setup.nasm` consumes those fields by fixed offsets. A small gadget pivots the
stack to the trampoline so the re-entry path can restore executable permission
and return to `setup.pic`.

## PIC Artifacts

The Win32 and x64 assembly files are assembled as flat binary PIC with NASM. The
ARM64 and ARM64EC assembly files are assembled to COFF objects and then converted
to `.pic` files by extracting the `.text` section.

## Review Discipline

When reviewing assembly changes:

- keep C++ and assembly configuration layouts paired;
- confirm offsets with static assertions or documented constants;
- avoid adding loader, deployment, persistence, or network behavior;
- update validation docs when the evidence semantics change.

The x64, ARM64, and ARM64EC demonstrations are sibling demonstrations, not
transparent ports of the Win32 stack-pivot chain.
