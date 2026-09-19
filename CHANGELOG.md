# Changelog

All notable BinX changes are documented here.

## v0.2.0 - Deep PE Inspector

- Replaced the minimal PE parser with a structured PE32/PE32+ analysis engine.
- Added PE/COFF and optional-header models.
- Added a reusable RVA/file-offset mapper.
- Added section parsing, permission decoding and overlap/range validation.
- Added imports, exports and forwarded-export parsing.
- Added base-relocation parsing.
- Added resource-tree enumeration with recursion and cycle limits.
- Added TLS directory and callback enumeration without execution.
- Added debug-directory and CodeView RSDS/PDB metadata.
- Added PE characteristic and subsystem decoders.
- Added structured diagnostics and per-component parse states.
- Added structured JSON schema v2.
- Added deep-analysis commands: sections, imports, exports, resources and relocations.
- Expanded synthetic parser tests across every v0.2 subsystem.
- Preserved v0.1 info/hash behavior and no-cloud/no-execution design.

## v0.1.0 - Foundation

- Added the BinX C++20/CMake project structure.
- Added safe bounds-checked binary reading.
- Added PE32 and PE32+ metadata parsing.
- Added ELF32 and ELF64 metadata parsing.
- Added Mach-O thin and fat-format detection.
- Added architecture and endianness normalization.
- Added SHA-256, SHA-1 and MD5 hashing.
- Added human-readable and JSON output.
- Added output-to-file support.
- Added stable CLI exit codes.
- Added malformed-input unit coverage.
- Added Windows and Linux CI configuration.
- Established a no-execution, no-cloud local analysis model.
