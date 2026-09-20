## v0.9.0 - Offline Crash Analysis

- Added `crash` and `crash-analysis` commands.
- Added Windows minidump parsing for system architecture, exception code/address, crashing thread and module metadata.
- Added ELF core-dump parsing for architecture, thread notes and signal information.
- Added deterministic text output and JSON schema version 7.
- Kept crash analysis offline and non-executing; dump files are treated strictly as untrusted data.

# Changelog

## v0.8.0 - Binary Diff and Size Analysis

- Added `diff`/`compare` for deterministic byte-level comparison of two binaries.
- Added bounded change hunks, changed/added/removed byte counts and similarity ratio.
- Added PE and ELF section-level size/change analysis when section metadata is available.
- Added `size` command with code/data/header/image size breakdowns.
- Added JSON schema version 6 for diff and size reports.
- Fixed the v0.7 build integration by compiling the symbols implementation into the main executable.
- Bumped the project and CLI version to 0.8.0.


## v0.7.0 - Symbols and Debug Information

- Added unified `symbols`/`sym` command.
- Added ELF symbol-table extraction with function/object/section classification and binding information.
- Added PE import/export symbols and CodeView/PDB identity records.
- Added `debug`/`debug-info` command.
- Added DWARF section discovery and bounded `.debug_info` compilation-unit counting for DWARF v2-v5.
- Added machine-readable JSON schema version 5 for symbols and debug metadata.
- Added tests for PE PDB identity and unified symbol extraction.
- Kept all symbol/debug analysis local; no cloud or symbol-server access.


## v0.6.0 - Disassembly

- Added built-in offline x86/x86-64 disassembly.
- Added disasm/disassemble commands, entry-point mode, limits, branch targets and JSON output.
- Added disassembly unit coverage.

All notable BinX changes are documented here.

## v0.5.0 - Dependency Analysis

- Added unified dependency extraction for PE imports, ELF DT_NEEDED and Mach-O dylib load commands.
- Added direct dependency CLI commands: deps and dependencies.
- Added recursive dependency graph construction with deterministic filesystem resolution.
- Added configurable search paths, maximum depth and maximum node count.
- Added cycle detection and unresolved-dependency reporting.
- Added Graphviz DOT graph output.
- Added JSON schema version 5 for dependency results and graphs.
- Added loader-relative dependency resolution for @loader_path, @executable_path and $ORIGIN forms.
- Made ELF dependency discovery work from PT_DYNAMIC/PT_LOAD without requiring section headers.
- Added dependency-analysis tests and kept the no-execution/no-network architecture.

## v0.4.0 - Strings, Hex & Search

- Added format-independent byte analysis, strings, hexdump, search and region classification.

## v0.3.0 - Deep ELF Inspector

- Added ELF32/ELF64 parsing, sections, segments, symbols, dynamic entries, notes and relocations.

## v0.2.0 - Deep PE Inspector

- Added PE32/PE32+ analysis, imports, exports, resources, relocations, TLS and debug metadata.

## v0.1.0 - Foundation

- Added safe binary reading, format detection, metadata, hashing and stable CLI errors.
