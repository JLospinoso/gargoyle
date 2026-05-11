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
  $nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'; if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }; $msbuild = if ($env:MSBUILD) { $env:MSBUILD } elseif (Test-Path 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe') { 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' } else { 'MSBuild.exe' }; $extra = @(); if ($env:GARGOYLE_PLATFORM_TOOLSET) { $extra += "/p:PlatformToolset=$env:GARGOYLE_PLATFORM_TOOLSET" }; & $msbuild Gargoyle.sln /p:Configuration={{configuration}} /p:Platform=x86 $extra /m

build-debug:
  just build Debug

build-release:
  just build Release

build-x64 configuration:
  $nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'; if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }; $msbuild = if ($env:MSBUILD) { $env:MSBUILD } elseif (Test-Path 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe') { 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' } else { 'MSBuild.exe' }; $extra = @(); if ($env:GARGOYLE_PLATFORM_TOOLSET) { $extra += "/p:PlatformToolset=$env:GARGOYLE_PLATFORM_TOOLSET" }; & $msbuild Gargoyle.sln /p:Configuration={{configuration}} /p:Platform=x64 $extra /m

build-x64-debug:
  just build-x64 Debug

build-x64-release:
  just build-x64 Release

build-x64-all:
  just build-x64-debug
  just build-x64-release

build-arm64 configuration:
  $nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'; if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }; $msbuild = if ($env:MSBUILD) { $env:MSBUILD } elseif (Test-Path 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe') { 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' } else { 'MSBuild.exe' }; $extra = @(); if ($env:GARGOYLE_PLATFORM_TOOLSET) { $extra += "/p:PlatformToolset=$env:GARGOYLE_PLATFORM_TOOLSET" }; & $msbuild Gargoyle.sln /p:Configuration={{configuration}} /p:Platform=ARM64 $extra /m

build-arm64-debug:
  just build-arm64 Debug

build-arm64-release:
  just build-arm64 Release

build-arm64ec configuration:
  $nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'; if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }; $msbuild = if ($env:MSBUILD) { $env:MSBUILD } elseif (Test-Path 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe') { 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' } else { 'MSBuild.exe' }; $extra = @(); if ($env:GARGOYLE_PLATFORM_TOOLSET) { $extra += "/p:PlatformToolset=$env:GARGOYLE_PLATFORM_TOOLSET" }; & $msbuild Gargoyle.sln /p:Configuration={{configuration}} /p:Platform=ARM64EC $extra /m

build-arm64ec-debug:
  just build-arm64ec Debug

build-arm64ec-release:
  just build-arm64ec Release

build-arm-all:
  just build-arm64-debug
  just build-arm64-release
  just build-arm64ec-debug
  just build-arm64ec-release

build-all:
  just build-debug
  just build-release
  just build-x64-all

native-analyze configuration="Debug" platform="x86":
  $nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'; if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }; $msbuild = if ($env:MSBUILD) { $env:MSBUILD } elseif (Test-Path 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe') { 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' } else { 'MSBuild.exe' }; $extra = @(); if ($env:GARGOYLE_PLATFORM_TOOLSET) { $extra += "/p:PlatformToolset=$env:GARGOYLE_PLATFORM_TOOLSET" }; & $msbuild Gargoyle.sln /p:Configuration={{configuration}} /p:Platform={{platform}} /p:RunCodeAnalysis=true $extra /m:1

native-analyze-all:
  just native-analyze Debug x86
  just native-analyze Release x86
  just native-analyze Debug x64
  just native-analyze Release x64

native-asan configuration="Debug" platform="x86":
  $nasmDir = Join-Path $env:LOCALAPPDATA 'bin\NASM'; if (Test-Path (Join-Path $nasmDir 'nasm.exe')) { $env:Path = "$nasmDir;$env:Path" }; $msbuild = if ($env:MSBUILD) { $env:MSBUILD } elseif (Test-Path 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe') { 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe' } else { 'MSBuild.exe' }; $extra = @(); if ($env:GARGOYLE_PLATFORM_TOOLSET) { $extra += "/p:PlatformToolset=$env:GARGOYLE_PLATFORM_TOOLSET" }; $outDir = Join-Path $PWD 'asan\{{platform}}\{{configuration}}'; $intDir = Join-Path $PWD 'asan\obj\{{platform}}\{{configuration}}'; New-Item -ItemType Directory -Force $outDir, $intDir | Out-Null; & $msbuild Gargoyle.sln /p:Configuration={{configuration}} /p:Platform={{platform}} /p:EnableASAN=true $extra "/p:OutDir=$outDir\" "/p:IntDir=$intDir\" /m:1

native-asan-all:
  just native-asan Debug x86
  just native-asan Debug x64

native-check:
  just native-analyze-all
  just native-asan-all

acceptance configuration="Debug" platform="x86" mode="live":
  uv run --all-groups gargoyle-acceptance --configuration {{configuration}} --platform {{platform}} --mode {{mode}}

acceptance-x86 configuration="Debug":
  just acceptance {{configuration}} x86

acceptance-x64 configuration="Debug":
  just acceptance {{configuration}} x64

acceptance-arm64 configuration="Debug" mode="artifacts":
  just acceptance {{configuration}} arm64 {{mode}}

acceptance-arm64ec configuration="Debug" mode="artifacts":
  just acceptance {{configuration}} arm64ec {{mode}}

arm-smoke configuration="Debug" mode="artifacts":
  just acceptance-arm64 {{configuration}} {{mode}}
  just acceptance-arm64ec {{configuration}} {{mode}}

arm-smoke-all mode="artifacts":
  just arm-smoke Debug {{mode}}
  just arm-smoke Release {{mode}}

windows-arm-smoke:
  just build-debug
  just build-x64-debug
  just build-arm-all
  uv run --all-groups gargoyle-acceptance --configuration Debug --platform x86 --mode architecture --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Debug --platform x64 --mode architecture --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Debug --platform arm64 --mode architecture --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Release --platform arm64 --mode architecture --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Debug --platform arm64ec --mode architecture --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Release --platform arm64ec --mode architecture --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Debug --platform arm64 --mode headless --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Release --platform arm64 --mode headless --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Debug --platform arm64ec --mode headless --skip-build
  uv run --all-groups gargoyle-acceptance --configuration Release --platform arm64ec --mode headless --skip-build

acceptance-all:
  just acceptance-x86 Debug
  just acceptance-x86 Release
  just acceptance-x64 Debug
  just acceptance-x64 Release

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
  just native-check
  just check
