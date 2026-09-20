# BinX Architecture

## Design principles

BinX is deliberately split so parsing, analysis, presentation and process control do not depend on one another unnecessarily.

### Core

include/binx/core/ and src/core/

- binary.* owns immutable in-memory input and metadata.
- byte_reader.* provides bounded primitive reads.
- text.* provides shared formatting primitives.
- error.hpp defines Result<T> and stable error codes.

### Formats

include/binx/formats/ and src/formats/

- detect.* performs format and architecture detection.
- pe.* parses Portable Executable structures.
- elf.* parses ELF headers, sections, segments, symbols, notes, dynamic entries and relocations.
- macho.* handles Mach-O metadata.

Format parsers return structured data and never print.

### Analysis

include/binx/analysis/ and src/analysis/

Each capability is an independent API boundary:

- byte_analysis — strings, hexdump, byte/text search, region classification.
- dependencies — direct dependency extraction and recursive resolution.
- disassembly — offline x86/x86-64 instruction decoding.
- symbols — symbols and debug metadata.
- diff — binary comparison and size analysis.
- crash — Windows minidump and ELF core analysis.
- report — composition of existing analyzers into a bounded summary.

An analyzer may consume format models, but does not own CLI concerns.

### CLI

include/binx/cli/ and src/cli/

- options parses argv into an explicit Options value.
- commands centralizes command-family classification.
- runner contains orchestration only.
- io handles stdout/file routing.
- output, analysis_output and dependency_output render models.

main.cpp is intentionally tiny and acts as the process composition root.

## Build graph

    binx_core
      core
      formats
      hashing
      analysis

    binx
      main
      cli/*
      -> binx_core

    binx_tests
      test_core
      test_cli
      -> binx_core

This keeps unit tests independent of the executable and makes the core reusable by future applications.

## Determinism

Output ordering is stable and filesystem dependency resolution is deterministic. Bounded result limits avoid accidental unbounded output from hostile or huge inputs.

## Extension points

New format support belongs in formats/. New analysis belongs in analysis/. New presentation belongs in cli/. New commands should update commands.*, options.*, runner.*, help text and regression tests.

This keeps feature work additive instead of increasing the responsibility of a single translation unit.
