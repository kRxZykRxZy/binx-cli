# Changelog

All notable BinX changes are documented here.

## v0.4.0 - Strings, Hex & Search

- Added format-independent byte analysis.
- Added ASCII, UTF-8 and UTF-16LE/UTF-16BE string extraction with offsets and minimum-length filtering.
- Added bounded hexdump with configurable offset, length and width.
- Added text search and wildcard hex-byte search.
- Added decimal and 0x-prefixed numeric CLI options.
- Added binary-region classification for zero, printable and binary runs.
- Added JSON schema version 4 for analysis output.
- Added malformed/boundary-focused unit coverage for strings, UTF-16, hexdump, search and patterns.
- Preserved local-only operation: no execution, networking, telemetry or cloud dependency.

## v0.3.0 - Deep ELF Inspector

- Added ELF32/ELF64 parsing, sections, segments, symbols, dynamic entries, notes and relocations.

## v0.2.0 - Deep PE Inspector

- Added PE32/PE32+ analysis, imports, exports, resources, relocations, TLS and debug metadata.

## v0.1.0 - Foundation

- Added safe binary reading, format detection, metadata, hashing and stable CLI errors.
