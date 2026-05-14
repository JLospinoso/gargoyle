# Lineage

Lineage claims should be conservative. Direct lineage requires source
self-description, not similarity in timers, callbacks, sleep behavior, or
memory-protection changes.

```mermaid
flowchart TD
    G["Gargoyle 2017"]
    D["Declared Gargoyle relationships"]
    A["Explicitly inspired but mechanically adjacent"]
    F["Broader sleep-obfuscation family"]
    R["Defensive and forensics response"]
    H["Stronger memory-hiding and anti-forensics"]

    G --> D
    D --> DG["dotnet-gargoyle"]
    D --> Y["YouMayPasser"]
    D --> DS["DeepSleep"]

    G -. inspired context .-> A
    A --> SF["ShellcodeFluctuation"]

    G -. family context .-> F
    F --> EC["Ekko / Cronos / FOLIAGE-related analysis"]
    F --> TQ["Timer-queue hunting context"]

    G -. analyzed by .-> R
    R --> V["Volatility and memory-hunting work"]

    G -. compared with .-> H
    H --> PTE["PTE-aware and memory-subversion research"]
```

## Categories

- Declared Gargoyle relationships: sources that describe themselves as
  Gargoyle-related. This category includes `dotnet-gargoyle`, YouMayPasser, and
  DeepSleep. The claim is relationship, not mechanical identity.
- Explicitly inspired but mechanically adjacent work: ShellcodeFluctuation cites
  Gargoyle as background for cyclic memory-protection changes, but it should not
  be treated as a direct continuation of the original waitable-timer/APC proof.
- Broader sleep-obfuscation family: Ekko, Cronos, FOLIAGE-related analysis,
  timer-queue hunting, and similar work belong here unless a primary source makes
  a narrower Gargoyle lineage claim.
- Defensive and forensics response: Volatility plugin work, memory hunting, and
  timer inspection analyze or respond to the technique. They are not lineage
  claims.
- Stronger memory-hiding and anti-forensics: PTE-aware analysis and
  memory-subversion research are separate from Gargoyle-style protection cycling.
  They may be useful comparison points, but they are not "Gargoyle but stronger."

See [References](references.md) for the annotated source map.
