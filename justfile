set shell := ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]

default:
  just --list

sync:
  uv sync --all-groups --frozen

lock:
  uv lock

lock-check:
  uv lock --check

lint:
  uv run --all-groups ruff check .

lint-fix:
  uv run --all-groups ruff check --fix .

format-check:
  uv run --all-groups ruff format --check src tests

format:
  uv run --all-groups ruff format src tests

pydoclint:
  uv run --all-groups pydoclint src

typecheck:
  uv run --all-groups mypy

test:
  uv run --all-groups pytest

docs:
  uv run --all-groups mkdocs build --strict

docs-serve:
  uv run --all-groups mkdocs serve -a 127.0.0.1:8000

build configuration:
  $nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'; if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }; $msbuild = if ($env:MSBUILD) { $env:MSBUILD } elseif (Test-Path 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe') { 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' } else { 'MSBuild.exe' }; & $msbuild Gargoyle.sln /p:Configuration={{configuration}} /p:Platform=x86 /m

build-debug:
  just build Debug

build-release:
  just build Release

build-all:
  just build-debug
  just build-release

acceptance configuration="Debug":
  uv run --all-groups gargoyle-acceptance --configuration {{configuration}}

check:
  just format-check
  just lint
  just pydoclint
  just typecheck
  just test
  just docs

ci:
  just sync
  just lock-check
  just build-all
  just check
