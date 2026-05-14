# Lab Setup

Gargoyle is meant to run in an owned Windows lab where benign MessageBox windows
and native build tooling are acceptable. Do not run the live demo on systems you
do not own or administer.

## Windows Desktop Expectations

Live validation opens visible MessageBox windows. The Python harness finds those
windows by process ID and title, closes them, and reports the number of rounds
completed. This requires an interactive desktop session; it is not a service or
headless automation workflow.

Headless, artifact, and architecture modes are safer for CI and remote runners.
They do not replace live desktop observation.

## Toolchain

- Visual Studio C++ tools with MSBuild.
- Windows SDK selected through `WindowsTargetPlatformVersion` `10.0`.
- MSVC platform toolset `v145` by default, or `GARGOYLE_PLATFORM_TOOLSET` for
  explicit retargeting.
- NASM for `setup.nasm`, `gadget.nasm`, `setup_x64.nasm`, and
  `reentry_x64.nasm`.
- ARM64 tools and `armasm64` for ARM64 and ARM64EC sibling projects.
- Python 3.13, `uv`, and `just`.

The `MSBUILD` environment variable can point recipes at a specific
`MSBuild.exe`.

## Suggested Lab Flow

1. Clone the repo in a disposable Windows VM or lab workstation.
2. Run `uv sync --all-groups`.
3. Run `just check` to verify Python and docs.
4. Run `just build-debug` or `just build-x64-debug`.
5. Run one live acceptance command from [Quickstart](quickstart.md).
6. Use optional memory-map or debugger observations only after the benign
   harness path works.

## Troubleshooting

- Missing NASM: install NASM and confirm `nasm -v`.
- Missing MSBuild: install Visual Studio C++ tools or set `MSBUILD`.
- Missing PIC files: build from the solution or run acceptance without
  `--skip-build`.
- MessageBox timeout: confirm the session is interactive and no endpoint policy
  blocked the process.
- ARM local build failure: use hosted `windows-11-arm` CI unless the local
  workstation has ARM64 and ARM64EC tools installed.
