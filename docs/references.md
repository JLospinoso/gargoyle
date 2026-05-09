# Reference Map

This page places Gargoyle in the public research lineage around memory-scanner
evasion, process-memory forensics, and later sleep-obfuscation work. It is a
curated map, not an endorsement of every linked project or an implementation
guide. The repository should remain a small, benign research artifact.

Access dates below use 2026-05-08.

## Original Work

- [Gargoyle: A memory scanning evasion technique](https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html)
  is the original March 2017 article that explains the waitable-timer, APC,
  stack-pivot, and protection-flipping proof of concept. It is still the best
  starting point for understanding what this repository is intended to show.
  Accessed 2026-05-08.

- [JLospinoso/gargoyle](https://github.com/JLospinoso/gargoyle) is the
  original public proof-of-concept repository. The current refresh preserves the
  Win32 implementation while adding build, validation, and documentation
  scaffolding around it. Accessed 2026-05-08.

## Detection And Forensics

- [Hunting for Gargoyle Memory Scanning Evasion](https://blog.f-secure.com/hunting-for-gargoyle-memory-scanning-evasion/)
  documents F-Secure Countercept's defensive analysis and summarizes the core
  detection idea: code may be non-executable when memory scanners run, but the
  timer/APC and memory-layout artifacts remain observable. Accessed 2026-05-08.

- [WithSecureLabs volatility-plugins: gargoyle.py](https://github.com/WithSecureLabs/volatility-plugins/blob/master/gargoyle.py)
  is the public Volatility plugin associated with that detection work. It is a
  useful reference for Gargoyle-specific memory-forensics heuristics. Accessed
  2026-05-08.

- [Hiding Process Memory Via Anti-Forensic Techniques](https://www.sciencedirect.com/science/article/pii/S2666281720302614)
  is the DFRWS USA 2020 open-access paper that compares Gargoyle with stronger
  memory-hiding approaches and notes that Gargoyle changes scanner visibility
  rather than truly removing the memory range from the process map. Accessed
  2026-05-08.

- [Black Hat USA 2020 slides: Hiding Process Memory Via Anti-Forensic Techniques](https://i.blackhat.com/USA-20/Wednesday/us-20-Block-Hiding-Process-Memory-Via-Anti-Forensic-Techniques.pdf)
  are the conference slides for the same research thread and cite Gargoyle as
  prior work. Accessed 2026-05-08.

- [DFRWS-memory-subversion/DFRWS-USA-2020](https://github.com/DFRWS-memory-subversion/DFRWS-USA-2020)
  contains the companion materials for the DFRWS 2020 paper, including detection
  and subversion research artifacts. Accessed 2026-05-08.

- [Windows Memory Forensics: Detecting Unintentionally Hidden Injected Code by
  Examining Page Table Entries](https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-windows_memory_forensics_detecting_unintentionally_hidden_injected_code_by_examining_page_table_entries.pdf)
  gives related page-table and memory-forensics context for injected code that
  ordinary virtual-address-descriptor views may miss or misclassify. Accessed
  2026-05-08.

## Direct Derivatives And Adjacent Experiments

- [Bypassing Memory Scanners with Cobalt Strike and Gargoyle](https://labs.withsecure.com/publications/experimenting-bypassing-memory-scanners-with-cobalt-strike-and-gargoyle)
  is an MWR/WithSecure experiment that applied the Gargoyle idea to a larger
  payload. It is useful here mainly because it made defender-visible artifacts
  explicit and helped motivate the later detection work. Accessed 2026-05-08.

- [waldo-irc/YouMayPasser](https://github.com/waldo-irc/YouMayPasser) describes
  itself as an x64 Gargoyle implementation and documents several indicators of
  compromise in its README. Treat it as lineage and design context rather than
  a target architecture for this repository. Accessed 2026-05-08.

- [mgeeky/ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation)
  cites Gargoyle as background for cyclically changing memory protections and
  optionally encrypting content while dormant. It is part of the broader family
  of memory-state fluctuation ideas that followed Gargoyle. Accessed
  2026-05-08.

## Later Sleep-Obfuscation Family

- [Idov31/Cronos](https://github.com/Idov31/Cronos) is a waitable-timer based
  sleep-obfuscation proof of concept that draws from the Ekko family and uses
  repeated protection and encryption state changes during idle periods. It is a
  useful comparison point because it keeps timers central while moving beyond
  Gargoyle's tiny Win32 shape. Accessed 2026-05-08.

- [Cronos Sleep Obfuscation](https://idov31.github.io/posts/cronos-sleep-obfuscation)
  is the companion write-up for Cronos and discusses how later sleep
  obfuscators evolved from simple memory-protection toggling into timer-driven
  encryption and re-entry strategies. Accessed 2026-05-08.

- [Understanding Sleep Obfuscation](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation/)
  gives a defender-oriented comparison of Ekko, Cronos, Foliage, and related
  approaches. It is especially useful for thinking about detection categories
  rather than any single implementation. Accessed 2026-05-08.

- [Hunting for timer-queue timers](https://labs.withsecure.com/publications/hunting-for-timer-queue-timers)
  covers detection work for timer-queue based sleep obfuscation and contrasts
  that family with waitable-timer variants such as Cronos. Accessed 2026-05-08.

## Windows API And Tool References

- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
  is the Win32 API Gargoyle uses to toggle the setup PIC between executable and
  non-executable protections. Accessed 2026-05-08.

- [SetWaitableTimer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)
  documents the waitable timer and completion routine behavior that Gargoyle
  uses for re-entry. Accessed 2026-05-08.

- [WaitForSingleObjectEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex)
  documents alertable waits, which are important because queued APC completion
  routines only run when the relevant thread enters an alertable state. Accessed
  2026-05-08.

- [Using Waitable Timers with an Asynchronous Procedure Call](https://learn.microsoft.com/en-us/windows/win32/sync/using-a-waitable-timer-with-an-asynchronous-procedure-call)
  is Microsoft's conceptual example for waitable timers with APC completion
  routines. Accessed 2026-05-08.

- [VMMap](https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap) is the
  Sysinternals process memory viewer used in the original demo instructions and
  in the refreshed manual validation checklist. Accessed 2026-05-08.

## Open Follow-Ups

- The initial refresh audit mentioned "Mirage" among later related work, but no
  reliable public source was verified during this docs pass. Keep it as a
  follow-up research item before adding it as a citation.

- The x64 lineage deserves an implementation-focused comparison now that
  Gargoyle has a sibling x64 timer/APC example. This page intentionally records
  public references without prescribing a broader evasion design.
