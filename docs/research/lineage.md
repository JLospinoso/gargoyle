# Lineage

Lineage claims need care. Direct descent requires a source to describe the work
as Gargoyle-derived or Gargoyle-like. Shared problem space alone is not enough.

```mermaid
flowchart TD
    G[Gargoyle 2017]
    G --> D[Declared descendants or variants]
    D --> Y[YouMayPasser]
    D --> DS[DeepSleep]
    G -. adjacent idea .-> S[Sleep-obfuscation family]
    S --> SF[ShellcodeFluctuation]
    S --> E[Ekko]
    S --> C[Cronos]
    S --> F[FOLIAGE]
    G --> DEF[Defensive analysis]
    DEF --> FS[F-Secure / WithSecure]
    DEF --> VOL[Volatility plugin work]
    DEF --> TQ[Timer-queue hunting]
    G -. comparison .-> AF[Memory-hiding and anti-forensics]
    AF --> PTE[PTE / memory-subversion research]
```

## Categories

- Direct or declared descendants: projects that explicitly cite Gargoyle as a
  basis or variant. The map uses this category for YouMayPasser and DeepSleep.
- Adjacent sleep-obfuscation work: projects that share timer, sleep, memory
  permission, or dormant-state ideas without necessarily descending from
  Gargoyle. The map uses this category for ShellcodeFluctuation, Ekko, Cronos,
  and FOLIAGE.
- Defensive work: memory hunting, forensics, and timer/APC inspection.
- Stronger memory-hiding research: work that changes enumeration or memory-map
  visibility rather than only current page protections.

Every named node in this map has a corresponding entry in
[References](references.md). Solid edges indicate declared lineage or analysis
directly centered on Gargoyle. Dotted edges indicate adjacent work or comparison
only.
