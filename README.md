![gargoyle title](https://github.com/JLospinoso/gargoyle/raw/master/title.png)

![gargoyle infographic](https://github.com/JLospinoso/gargoyle/raw/master/infographic.png)

# Building gargoyle

*gargoyle* is only implemented for 32-bit Windows (64-bit Windows on Windows is fine). You must have the following installed:

* [Visual Studio](https://www.visualstudio.com/downloads/): 2015 Community is tested, but it may work for other versions.
* [Netwide Assembler](http://www.nasm.us/pub/nasm/releasebuilds/?C=M;O=D) v2.12.02 x64 is tested, but it may work for other versions. Make sure `nasm.exe` is on your path.

Clone *gargoyle*:

```sh
git clone https://github.com/JLospinoso/gargoyle.git
```

Open `Gargoyle.sln`, build, and run. There is some harness code in `main.cpp` that configures the following three components:

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
Blog post coming soon at [lospi.net](https://jlospinoso.github.io/).
