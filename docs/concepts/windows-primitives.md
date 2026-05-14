# Windows Primitives

Gargoyle combines a small set of Windows primitives. The docs describe them to
make the proof of concept understandable, not to provide a broader adaptation
guide.

## Memory Protections

Windows committed pages carry protections such as read-only, read/write, and
execute/read. Gargoyle's observable state change is the transition of the setup
PIC between executable and non-executable protection.

The Win32 path uses `VirtualProtectEx` from the setup and re-entry chain. The
x64 and ARM-family sibling demonstrations also route protection changes through
the configuration block and imported Windows APIs.

## Waitable Timers And APCs

A waitable timer can queue an APC completion routine to the thread that set it.
That APC only runs when the thread enters an alertable wait. The refreshed demos
therefore rely on `SleepEx(INFINITE, TRUE)` for re-entry evidence.

## Alertable Waits

An alertable wait allows queued APCs to run on the waiting thread. Waiting on the
timer handle itself is weaker evidence because the timer object can become
signaled before the APC completion routine runs.

## Observable Artifacts

Defenders and lab users can reason about:

- private committed regions containing PIC, configuration, scratch stack, and
  re-entry code;
- memory-protection transitions over time;
- timer and APC behavior;
- unusual stack or callback targets in the Win32 path;
- stdout banners and benign MessageBox windows.

See [Responsible Use](../responsible-use.md) for the project boundaries.
