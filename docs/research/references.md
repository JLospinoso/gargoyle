# References

This page is an annotated map of public sources. It is not an implementation
guide, endorsement, or target list.

Access dates are recorded per entry.

## Original Work

- [Gargoyle: A memory scanning evasion technique](https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html)
  is the original March 2017 article explaining the waitable-timer, APC,
  stack-pivot, and protection-flipping proof of concept. Accessed 2026-05-08.
- [JLospinoso/gargoyle](https://github.com/JLospinoso/gargoyle) is the public
  repository. The current refresh preserves Win32 while adding validation and
  sibling demonstrations. Accessed 2026-05-08.

## Detection And Forensics

- [Hunting for Gargoyle Memory Scanning Evasion](https://blog.f-secure.com/hunting-for-gargoyle-memory-scanning-evasion/)
  documents defensive analysis focused on timer/APC and memory-layout artifacts.
  Accessed 2026-05-08.
- [WithSecureLabs volatility-plugins: gargoyle.py](https://github.com/WithSecureLabs/volatility-plugins/blob/master/gargoyle.py)
  is the public Volatility plugin associated with Gargoyle detection work.
  Accessed 2026-05-08.
- [Hiding Process Memory Via Anti-Forensic Techniques](https://www.sciencedirect.com/science/article/pii/S2666281720302614)
  compares Gargoyle with stronger memory-hiding approaches and notes that
  Gargoyle changes scanner visibility rather than removing the memory range.
  Accessed 2026-05-08.
- [Windows Memory Forensics: Detecting Unintentionally Hidden Injected Code by
  Examining Page Table Entries](https://dfrws.org/wp-content/uploads/2019/06/2019_USA_paper-windows_memory_forensics_detecting_unintentionally_hidden_injected_code_by_examining_page_table_entries.pdf)
  gives page-table and memory-forensics context. Accessed 2026-05-08.

## Direct And Adjacent Work

- [Bypassing Memory Scanners with Cobalt Strike and Gargoyle](https://labs.withsecure.com/publications/experimenting-bypassing-memory-scanners-with-cobalt-strike-and-gargoyle)
  applied the idea in a larger red-team experiment and is useful here as
  historical and defensive context. Accessed 2026-05-08.
- [waldo-irc/YouMayPasser](https://github.com/waldo-irc/YouMayPasser) describes
  itself as an x64 Gargoyle implementation. Accessed 2026-05-08.
- [thefLink/DeepSleep](https://github.com/thefLink/DeepSleep) describes itself
  as a Gargoyle-like x64 ROP/PIC variant and explicitly credits the original
  Gargoyle technique. Accessed 2026-05-13.
- [mgeeky/ShellcodeFluctuation](https://github.com/mgeeky/ShellcodeFluctuation)
  cites Gargoyle as background for cyclic memory-protection changes. Accessed
  2026-05-08.
- [Cracked5pider/Ekko](https://github.com/Cracked5pider/Ekko) is an archived
  timer-queue sleep-obfuscation proof of concept. It is adjacent context, not a
  declared Gargoyle descendant. Accessed 2026-05-13.
- [Idov31/Cronos](https://github.com/Idov31/Cronos) is a waitable-timer based
  sleep-obfuscation proof of concept adjacent to the broader family. Accessed
  2026-05-08.
- [MDSec: How I Met Your Beacon](https://www.mdsec.co.uk/2022/07/part-1-how-i-met-your-beacon-overview/)
  discusses FOLIAGE, Ekko, ShellcodeFluctuation, and Gargoyle in a broader
  page-protection and event-driven sleep-obfuscation family. Accessed
  2026-05-13.
- [Understanding Sleep Obfuscation](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation/)
  gives a defender-oriented comparison of related approaches, including FOLIAGE,
  Ekko, and Cronos detection observations. Accessed 2026-05-08.
- [Hunting for timer-queue timers](https://labs.withsecure.com/publications/hunting-for-timer-queue-timers)
  covers timer-queue detection work. Accessed 2026-05-08.

## Windows API And Tool References

- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
  documents the API used to change page protections. Accessed 2026-05-08.
- [SetWaitableTimer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer)
  documents waitable timer completion routine behavior. Accessed 2026-05-08.
- [SleepEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)
  documents alertable sleeps used by the corrected proof. Accessed 2026-05-11.
- [Using Waitable Timers with an Asynchronous Procedure Call](https://learn.microsoft.com/en-us/windows/win32/sync/using-a-waitable-timer-with-an-asynchronous-procedure-call)
  is Microsoft's conceptual waitable timer/APC example. Accessed 2026-05-08.
- [Understanding Arm64EC ABI and assembly code](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi)
  documents ARM64EC call checking, thunking, and dynamic-code requirements.
  Accessed 2026-05-11.
- [VMMap](https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap) is the
  Sysinternals memory viewer used for optional manual observation. Accessed
  2026-05-08.

## Open Follow-Ups

- Keep uncertain references such as "Mirage" out of the main map until a
  reliable public source is verified.
- Continue separating direct descendants, adjacent sleep-obfuscation work, and
  stronger memory-hiding research.
