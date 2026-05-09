![gargoyle title](https://github.com/JLospinoso/gargoyle/raw/master/title.png)

![gargoyle infographic](https://github.com/JLospinoso/gargoyle/raw/master/infographic.png)

# Building gargoyle

*gargoyle* is only implemented for 32-bit Windows (64-bit Windows on Windows is fine). The current build-only baseline is tested with:

* [Visual Studio](https://visualstudio.microsoft.com/downloads/): Visual Studio 18 with MSVC toolset `v145`, or a compatible retargeted Visual Studio C++ toolchain.
* Windows 10 SDK. The project uses `WindowsTargetPlatformVersion` `10.0` so MSBuild selects the latest installed Windows 10 SDK.
* [Netwide Assembler](https://www.nasm.us/) on your `PATH`. On Windows, you can install the current winget package:

```powershell
winget install --id NASM.NASM --source winget --accept-package-agreements --accept-source-agreements
where.exe nasm
nasm -v
```

Clone *gargoyle*:

```sh
git clone https://github.com/JLospinoso/gargoyle.git
```

Open `Gargoyle.sln` and build the `Debug|x86` or `Release|x86` configuration. You can also build from PowerShell:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' Gargoyle.sln /p:Configuration=Debug /p:Platform=x86 /m
& 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' Gargoyle.sln /p:Configuration=Release /p:Platform=x86 /m
```

The executable loads `setup.pic` and `gadget.pic` relative to the current working directory. The Visual Studio debugger is configured to run from the output directory so F5 can find those files. If you launch manually, run from `Debug\` or `Release\`.

You can run the Python acceptance harness with [uv](https://docs.astral.sh/uv/):

```powershell
uv sync --all-groups
uv run gargoyle-acceptance --configuration Debug
uv run gargoyle-acceptance --configuration Release
```

The harness builds the requested configuration, launches `Gargoyle.exe` from the output directory, validates the setup banner, and closes two benign `gargoyle` MessageBox windows to confirm initial PIC execution and timer re-entry. Use `uv run gargoyle-acceptance --help` for options.

There is some harness code in `main.cpp` that configures the following three components:

* *gargoyle* stack trampoline, stack, and configuration (read/write memory on the heap)
* *gargoyle* position independent code (PIC) that receives the ROP gadget/stack trampoline and runs arbitrary code
* A ROP gadget. If you have `mshtml.dll`, *gargoyle* will load it into memory and use it. If it is not available, you will have to tell *gargoyle* to allocate its own (3-byte) ROP gadget on the heap:

```cpp
// main.cpp
auto use_mshtml{ true };
auto gadget_memory = get_gadget(use_mshtml, gadget_pic_path);
```

Every 15 seconds, gargoyle will pop up a message box. When you click ok, gargoyle sets up the tail calls to mark itself non-executable and to wait for the timer. For fun, use [Sysinternals's excellent VMMap tool](https://technet.microsoft.com/en-us/sysinternals/vmmap.aspx) to examine when *gargoyle*'s PIC is executable. If a message box is active, *gargoyle* will be executable. If it is not, *gargoyle* should not be executable. The PIC's address is printed to `stdout` just before the harness calls into the PIC.

# More information
See the blog post [available at lospi.net](https://jlospinoso.github.io/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html) for more information.

Also feel free to hop on gitter: [![Join the chat at https://gitter.im/grgyl/Lobby](https://badges.gitter.im/grgyl/Lobby.svg)](https://gitter.im/grgyl/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

