![gargoyle title](https://github.com/JLospinoso/gargoyle/raw/master/title.png)

![gargoyle infographic](https://github.com/JLospinoso/gargoyle/raw/master/infographic.png)

# Gargoyle

Gargoyle is a historical Windows research proof of concept for temporal
memory-state evasion. The original Win32 implementation remains the canonical
demonstration: code is executable while the benign demo action runs, then
non-executable while the process waits for timer/APC re-entry.

The refreshed repository keeps that Win32 story central while adding build
tooling, an acceptance harness, and sibling x64, ARM64, and ARM64EC
demonstrations for modern validation. It is not a loader, operator workflow, or
product-bypass guide.

Start with the documentation:

- [Docs home](docs/index.md) for reader paths and project orientation.
- [Responsible use](docs/responsible-use.md) for safety boundaries and non-goals.
- [Quickstart](docs/quickstart.md) for the shortest safe build and validation path.
- [Architecture comparison](docs/architectures/comparison.md) for what each
  sibling demonstration validates and does not prove.
- [Research context](docs/research/context.md) for the original article,
  defensive work, and later related research.

The canonical local gate is:

```powershell
uv sync --all-groups
just ci
```

For the original write-up, see
[Gargoyle: a memory scanning evasion technique](https://lospi.net/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html).

