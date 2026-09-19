# BinX

Binary Inspector — a local, developer-first binary analysis toolkit.

The CLI command is binx.

## Current release

v0.2.0 — Deep PE Inspector

v0.2 adds a real PE32/PE32+ analysis engine on top of the safe v0.1 foundation.

### v0.2 features

- PE32 and PE32+ header parsing
- COFF and optional-header decoding
- central RVA to file-offset mapping
- section enumeration and validation
- section permission decoding
- section overlap diagnostics
- import DLL/function/ordinal parsing
- export/function/ordinal/forwarder parsing
- base relocation block and entry parsing
- resource-tree enumeration
- TLS directory and callback enumeration
- debug-directory metadata
- CodeView RSDS / PDB metadata
- PE subsystem and characteristic decoding
- structured diagnostics
- partial-parser recovery
- structured JSON schema v2
- info, inspect, sections, imports, exports, resources, relocations and hash commands
- deterministic terminal output
- Windows CNG hashing and OpenSSL hashing on non-Windows builds
- malformed-input coverage and synthetic PE integration tests

### Safety

BinX treats binaries as untrusted data. It never executes the inspected file, never loads the target DLL, never invokes TLS callbacks, never resolves dependencies by loading them, and never downloads PDBs.

There is no cloud/API dependency or telemetry.

## Build

Windows:

    cmake -S . -B build
    cmake --build build --config Release
    ctest --test-dir build -C Release --output-on-failure
    build\Release\binx.exe --help

Linux/macOS:

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ctest --test-dir build --output-on-failure

## Usage

    binx info app.exe
    binx inspect app.exe
    binx sections app.exe
    binx imports app.exe
    binx exports app.dll
    binx resources app.exe
    binx relocations app.exe
    binx hash app.exe

    binx inspect app.exe --json
    binx imports app.exe --json
    binx inspect app.exe --json --output report.json
    binx sections app.exe --output sections.txt
    binx inspect app.exe --verbose

## Roadmap

v0.1 Foundation -> v0.2 deep PE -> v0.3 ELF/formats -> v0.4 strings/hex/search -> v0.5 dependencies -> v0.6 disassembly -> v0.7 symbols/PDB/DWARF -> v0.8 diff/size -> v0.9 crash analysis -> v0.95 unified analysis/reporting -> v1.0 complete local toolkit.

Cloud/API remains post-v1.
