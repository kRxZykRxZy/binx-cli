# BinX

**Binary Inspector** — a local, developer-first binary analysis toolkit.

The CLI command is `binx`.

## Current release

**v0.1.0 — Foundation**

BinX v0.1 establishes the safe binary-reading and metadata foundation used by later releases.

### Features

- PE32 / PE32+ detection and basic metadata
- ELF32 / ELF64 detection and basic metadata
- Mach-O 32/64 and fat-binary detection
- x86, x86-64, ARM, ARM64 and RISC-V architecture identification where available
- little- and big-endian metadata handling
- safe bounds-checked binary reading
- SHA-256, SHA-1 and MD5 hashing
- human-readable terminal output
- JSON output
- output-to-file support
- stable error/exit codes
- malformed-input handling
- CMake + C++20
- unit and CTest integration tests
- Windows CNG hashing and OpenSSL hashing on non-Windows builds

BinX treats inspected files as untrusted data. It never executes the input file and has no cloud/API dependency.

## Build

### Windows

Use a Visual Studio Developer Command Prompt:

```cmd
cmake -S . -B build
cmake --build build --config Release
build\Release\binx.exe --help
ctest --test-dir build -C Release --output-on-failure
```

### Linux/macOS

An OpenSSL development package is required.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage

```cmd
binx info app.exe
binx inspect app.exe
binx hash app.exe
binx inspect app.exe --json
binx inspect app.exe --json --output report.json
binx hash app.exe --json --output hashes.json
```

## v0.1 scope

v0.1 intentionally stops at safe identification, metadata extraction and hashing. Deep PE analysis, ELF internals, strings, hex search, dependencies, disassembly, symbols, diffing and crash analysis are scheduled for later releases.

## Roadmap

v0.1 Foundation → v0.2 deep PE → v0.3 ELF/formats → v0.4 strings/hex/search → v0.5 dependencies → v0.6 disassembly → v0.7 symbols/PDB/DWARF → v0.8 diff/size → v0.9 crash analysis → v0.95 unified analysis/reporting → v1.0 complete local toolkit.

Cloud/API is intentionally post-v1.
