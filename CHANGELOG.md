# Changelog

All notable BinX changes are documented here.

## v0.3.0 - Deep ELF Inspector

- Added a structured ELF32/ELF64 parser.
- Added little-endian and big-endian ELF decoding.
- Added ELF file-header validation and architecture decoding.
- Added program-header parsing and PT_INTERP detection.
- Added section-header parsing and section-name resolution.
- Added symbol-table and dynamic-symbol parsing.
- Added dynamic-table parsing.
- Added ELF note parsing.
- Added REL and RELA relocation parsing with symbol association.
- Added ELF section/segment/symbol/dynamic/note/relocation commands.
- Added ELF JSON schema v3.
- Added malformed/truncated ELF diagnostics and bounded parsing.
- Kept PE analysis and v0.1 hashing behavior intact.
- Kept BinX local-only with no execution, network access, telemetry or cloud dependency.

## v0.2.0 - Deep PE Inspector

- Structured PE32/PE32+ analysis, sections, imports, exports, relocations, resources, TLS and debug metadata.
- Added structured diagnostics and JSON schema v2.

## v0.1.0 - Foundation

- Added safe binary reading, format detection, metadata, hashing, JSON output and stable CLI errors.
