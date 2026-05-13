# Research Context

The original Gargoyle article was published in March 2017 as a compact 32-bit
Windows proof of concept. It showed that code could be non-executable while
dormant, then briefly executable during timer/APC-driven work.

## Defensive Interest

Early defensive work treated the timer, APC, ROP, stack, and memory-layout
artifacts as the real detection surface. That remains the right way to read this
repository: the point is not that code disappears, but that point-in-time
executable-page scans are incomplete evidence.

## Later Work

Later public work expanded the general sleep-obfuscation conversation with timer
queues, encryption while dormant, call-stack spoofing, and stronger
memory-hiding or anti-forensic approaches. Those projects are research context,
not implementation targets for Gargoyle.

## Safe Reading

External offensive or dual-use references are included to understand lineage and
defensive response. Do not import deployment steps, operator workflows, or
product-evasion claims into this repository.

Continue with [Lineage](lineage.md) and [References](references.md).
