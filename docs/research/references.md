# References

This page is an annotated public source map. It separates original Gargoyle
work, declared relationships, adjacent work, defensive response, and stronger
memory-hiding research. It is not an implementation guide, endorsement, target
list, or operational reading order.

Access dates use `Accessed 2026-05-14.`

## Original And Retrospective Work

- [Gargoyle: A memory scanning evasion technique](https://lospino.so/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html)
  is the original 2017 article and the historical Win32/x86 proof. Use it to
  understand the original framing, not as a claim of general invisibility.
  Accessed 2026-05-14.
- [Gargoyle, a decade later](https://lospino.so/blog/gargoyle-a-decade-later/)
  is the 2026 retrospective. It reframes the durable lesson as temporal memory
  state, explains the refresh, and narrows the validation claims. Accessed
  2026-05-14.
- [JLospinoso/gargoyle](https://github.com/JLospinoso/gargoyle) is the public
  repository for the original proof, refreshed documentation, validation harness,
  and sibling architecture demonstrations. Accessed 2026-05-14.

## Declared Relationships

- [WithSecureLabs/dotnet-gargoyle](https://github.com/WithSecureLabs/dotnet-gargoyle)
  describes itself as a spiritual .NET equivalent of Gargoyle. Treat it as a
  declared conceptual relationship, not mechanical identity. Accessed
  2026-05-14.
- [waldo-irc/YouMayPasser](https://github.com/waldo-irc/YouMayPasser) describes
  itself as an x64 implementation of Gargoyle. Treat that self-description as
  lineage evidence, while keeping architecture-specific mechanics separate.
  Accessed 2026-05-14.
- [thefLink/DeepSleep](https://github.com/thefLink/DeepSleep) describes itself
  as a Gargoyle-like x64 variant and credits the original technique. Treat it as
  a declared relationship, not proof that every Win32/x86 detail carries over.
  Accessed 2026-05-14.

## Explicitly Inspired But Mechanically Adjacent Work

- [mgeeky/ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation)
  cites Gargoyle as background for cyclic memory-protection changes. Its
  mechanics are adjacent rather than a direct continuation of the original
  waitable-timer/APC proof. Accessed 2026-05-14.

## Broader Sleep-Obfuscation Family

- [Cracked5pider/Ekko](https://github.com/Cracked5pider/Ekko) is a timer-queue
  sleep-obfuscation proof of concept. It is useful family context, not a
  declared Gargoyle descendant. Accessed 2026-05-14.
- [Idov31/Cronos](https://github.com/Idov31/Cronos) is a waitable-timer based
  sleep-obfuscation proof of concept. Treat it as broader-family context unless
  a primary source states a Gargoyle lineage claim. Accessed 2026-05-14.
- [MDSec, "How I Met Your Beacon"](https://www.mdsec.co.uk/2022/07/part-1-how-i-met-your-beacon-overview/)
  places Gargoyle, ShellcodeFluctuation, Ekko, FOLIAGE-related analysis, and
  related work in a broader page-protection and event-driven sleep-obfuscation
  discussion. Accessed 2026-05-14.
- [Binary Defense, "Understanding Sleep Obfuscation"](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation/)
  gives a defender-oriented comparison of sleep-obfuscation approaches, including
  FOLIAGE, Ekko, and Cronos observations. Use it as family context, not lineage
  proof. Accessed 2026-05-14.

## Defensive And Forensics Response

- [Elastic, "Hunting In Memory"](https://www.elastic.co/security-labs/hunting-memory)
  discusses memory-resident technique hunting and places Gargoyle in a defensive
  taxonomy. Accessed 2026-05-14.
- [Volatility Foundation 2018 contest summary](https://volatilityfoundation.org/results-from-the-2018-volatility-contests-are-in/)
  summarizes Gargoyle-focused Volatility work, including timer APC inspection,
  emulation, ROP-chain following, and `VirtualProtectEx` argument analysis.
  Accessed 2026-05-14.
- [WithSecureLabs Volatility plugin: gargoyle.py](https://github.com/WithSecureLabs/volatility-plugins/blob/master/gargoyle.py)
  is the public Volatility plugin artifact associated with Gargoyle detection
  work. Accessed 2026-05-14.
- [WithSecure, "Hunting for timer-queue timers"](https://labs.withsecure.com/publications/hunting-for-timer-queue-timers)
  covers timer-queue hunting. It is defensive context for related
  sleep-obfuscation mechanisms, not Gargoyle lineage. Accessed 2026-05-14.

## Stronger Memory-Hiding And Anti-Forensic Research

- [Windows Memory Forensics: Detecting Unintentionally Hidden Injected Code by
  Examining Page Table Entries](https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-windows_memory_forensics_detecting_unintentionally_hidden_injected_code_by_examining_page_table_entries.pdf)
  gives page-table-aware forensics context for cases where higher-level memory
  views are incomplete. Accessed 2026-05-14.
- [Hiding Process Memory Via Anti-Forensic Techniques](https://dfrws.org/wp-content/uploads/2020/10/2020_USA_paper-hiding_process_memory_via_anti-forensic_techniques.pdf)
  covers stronger memory-subversion techniques. Keep this separate from
  Gargoyle-style protection cycling, which changes current page state but does
  not make memory disappear. Accessed 2026-05-14.
- [Black Hat Asia 2023, "You Can Run But You Can't Hide"](https://i.blackhat.com/Asia-23/AS-23-Uhlmann-You-Can-Run-But-You-Cant-Hide.pdf)
  discusses residue from transient implant state, including evidence left by
  pages that were executable earlier in a process lifetime. It is useful
  defensive context for temporal state, not a Gargoyle lineage claim. Accessed
  2026-05-14.

## Windows API And Tooling References

- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
  documents page-protection changes used in the historical proof. Accessed
  2026-05-14.
- [SetWaitableTimer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)
  documents waitable timers and completion-routine behavior. Accessed
  2026-05-14.
- [SleepEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)
  documents alertable sleeps. The refreshed demo uses this as the corrected
  evidence path for timer/APC callback dispatch. Accessed 2026-05-14.
- [Using Waitable Timers with an Asynchronous Procedure Call](https://learn.microsoft.com/en-us/windows/win32/sync/using-a-waitable-timer-with-an-asynchronous-procedure-call)
  is Microsoft's conceptual example for waitable timers with APC completion.
  Accessed 2026-05-14.
- [Understanding Arm64EC ABI and assembly code](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi)
  documents ARM64EC ABI constraints, including dynamic-code distinctions relevant
  to the ARM64EC sibling caveat. Accessed 2026-05-14.
- [VMMap](https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap) is the
  Sysinternals memory viewer used for optional manual observation of sampled
  memory states. Accessed 2026-05-14.

## Open Follow-Ups

- Keep uncertain or unstable references out of this map until a stable public
  source supports the claim.
- Before adding future relationship claims, prefer primary-source
  self-description over similarity in timers, sleeps, callbacks, or protection
  changes.
