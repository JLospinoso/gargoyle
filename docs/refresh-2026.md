# 2026 Refresh

The 2026 refresh keeps Gargoyle's original Win32 proof of concept recognizable
while making it easier to build, validate, and discuss as a historical research
artifact. The goal is not to turn the repository into a broader payload
framework. The goal is to preserve the original lesson, document what changed,
and make the evidence clear enough for a retrospective post.

## What Changed

- Added a Python acceptance harness with build discovery, artifact checks,
  platform-aware setup-banner parsing, live MessageBox validation, and
  non-interactive modes for CI-safe evidence.
- Added a sibling x64 example that uses pointer-sized configuration, Win64 ABI
  calls from PIC, and a separate executable re-entry PIC instead of replacing
  the Win32 stack-pivot design.
- Added ARM64 and ARM64EC sibling projects so hosted Windows-on-Arm CI can prove
  build identity, PE machine type, architecture reporting, and benign headless
  timer/APC rounds.
- Corrected the timer/APC proof to use `SleepEx(INFINITE, TRUE)` for re-entry
  waits, which ties the second round to APC delivery instead of timer-handle
  signaled state.
- Added strict documentation, Python checks, native MSVC analysis, AddressSanitizer
  builds, and GitHub Actions coverage around the refreshed examples.
- Added responsible-use, validation, architecture, reference, and future-work
  documentation so later discussion stays historical, reproducible, and
  defender-aware.

## Architecture Claims

| Architecture | What It Proves | Validation Path | Caveat |
| --- | --- | --- | --- |
| x86 | The original Win32 reference path still demonstrates the ROP/APC/protection-cycle baseline. | Live acceptance builds `Debug|x86` or `Release|x86`, parses the setup banner, and closes two benign `gargoyle` MessageBoxes. | This remains the historical shape and intentionally keeps the compact 32-bit stack-pivot design. |
| x64 | The sibling x64 example demonstrates timer/APC re-entry and protection cycling with pointer-sized configuration and Win64 ABI calls. | Live acceptance builds `Debug|x64` or `Release|x64`, validates x64 artifacts, parses setup and re-entry addresses, and closes two benign `gargoyle x64` MessageBoxes. | It is not a transparent port of the original x86 stack-pivot chain; it uses a separate re-entry PIC. |
| ARM64 | The native Windows-on-Arm example builds and runs short benign timer/APC rounds on hosted ARM64 Windows. | `windows-11-arm` CI builds ARM64 Debug/Release, checks PE machine identity, runs architecture reports, and runs headless rounds without GUI automation. | Desktop live validation still depends on ARM64 Windows hardware or an equivalent local lab. |
| ARM64EC | The ARM64EC example proves build/runtime identity, EC dynamic-code allocation, architecture reporting, and APC semantics in an ARM64EC process. | `windows-11-arm` CI builds ARM64EC Debug/Release, checks ARM64EC-compatible image identity, runs architecture reports, and runs headless rounds. | Version 1 does not demonstrate mixed x64 DLL interop; it keeps ARM64EC focused on identity and runtime semantics. |

## Why The SleepEx Fix Matters

The original wait shape could wake because the timer object became signaled,
even if the completion routine had not yet run. That made a successful-looking
second round weaker evidence than intended.

The refreshed implementation arms the waitable timer and then enters an
alertable `SleepEx(INFINITE, TRUE)` wait. In this shape, progress through the
re-entry path is tied to APC delivery. The demos still remain benign and visible,
but the proof now better matches the claim: timer/APC re-entry is what drives the
next round.

## What This Does Not Claim

- It does not make Gargoyle a general loader, operator workflow, or stealth
  framework.
- It does not claim that x64, ARM64, or ARM64EC reproduce every detail of the
  original Win32 stack-pivot chain.
- It does not claim to defeat modern endpoint products or platform mitigations.
- It does not add credential access, persistence, deployment, networking, or
  non-benign payload behavior.
- It does not treat platform failures or detections as bypass problems. Those
  outcomes are research data and should be documented.

The useful retrospective claim is narrower and more durable: Gargoyle made
memory scanning a temporal problem. The refresh makes that lesson easier to
rebuild, observe, and cite across modern Windows architectures.
