# BinX

**Binary Inspector** — a developer-first local binary analysis CLI.

The command is `binx`.

## v0.1

BinX v0.1 establishes the analysis foundation:

- PE32 / PE32+ detection and basic metadata
- ELF32 / ELF64 detection and basic metadata
- Mach-O detection
- architecture and endianness detection
- safe bounds-checked binary reading
- MD5, SHA-1 and SHA-256 hashing
- human-readable output
- JSON output
- stable exit codes
- no execution of inspected binaries
- no cloud services or telemetry

## Build

### Windows

Using Visual Studio's Developer Command Prompt:

```cmd
cmake -S . -B build
cmake --build build --config Release
build\Release\binx.exe --help
```

### Usage

```cmd
binx info app.exe
binx inspect app.exe
binx hash app.exe
binx inspect app.exe --json
```

BinX treats input files as untrusted data and never executes them.

## Roadmap

v0.1 Foundation → v0.2 PE → v0.3 ELF/formats → v0.4 strings/hex/search → v0.5 dependencies → v0.6 disassembly → v0.7 symbols/PDB/DWARF → v0.8 diff/size → v0.9 crash analysis → v0.95 unified analysis/reporting → v1.0 complete local toolkit.

Cloud/API is intentionally post-v1.
