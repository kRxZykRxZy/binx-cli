# Changelog

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
