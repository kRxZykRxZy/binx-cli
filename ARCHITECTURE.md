# ARCHITECTURE.md

# BinX Architecture

## 1. Product boundary

BinX is a **local, developer-first binary inspection and analysis toolkit**.

The primary executable is:

```text
binx
```

The pre-v1 architecture has one deliberate trust boundary:

> **Input files are data. They are never executed, loaded, or sent to a service.**

BinX v0.1-v1.0 has no required cloud/API component.

A future cloud product may exist after v1, but it must sit outside the local analysis core.

## 2. Design goals

1. Safety against hostile/malformed binary data.
2. Deterministic analysis and output.
3. Strong modular separation.
4. Windows and Linux first-class CI targets.
5. Bounded work for untrusted sizes, counts, recursion, and samples.
6. Human-readable terminal output plus machine-readable JSON.
7. Small dependency footprint.
8. Offline-first operation.
9. Graceful recovery from damaged optional metadata.

## 3. Layered model

```text
+------------------------------------------------------------+
|                         CLI / UX                           |
| commands, arguments, help, text output, JSON, files       |
+-------------------------------+----------------------------+
                                |
                                v
+------------------------------------------------------------+
|                    Analysis orchestration                 |
| byte | deps | disasm | symbols | diff | size | crash     |
| report                                                     |
+-------------------------------+----------------------------+
                                |
                                v
+------------------------------------------------------------+
|                     Format parsers                         |
|             PE/COFF | ELF | Mach-O | detect               |
+-------------------------------+----------------------------+
                                |
                                v
+------------------------------------------------------------+
|                         Core                               |
| bounded reader | binary container | diagnostics          |
+-------------------------------+----------------------------+
                                |
                                v
+------------------------------------------------------------+
|                    Local filesystem bytes                 |
+------------------------------------------------------------+
```

Hashing is a small cross-cutting service used where content identity is required.

## 4. Repository layout

```text
binx-cli/
├── .github/workflows/ci.yml
├── docs/
│   ├── json.md
│   ├── v0.1.md
│   ├── v0.2.md
│   ├── v0.3.md
│   ├── v0.6.md
│   ├── v0.7.md
│   ├── v0.9.md
│   └── v0.95.md
├── include/binx/
│   ├── analysis/
│   ├── cli/
│   ├── core/
│   ├── formats/
│   ├── hashing/
│   ├── error.hpp
│   └── version.hpp
├── src/
│   ├── analysis/
│   ├── cli/
│   ├── core/
│   ├── formats/
│   ├── hashing/
│   └── main.cpp
├── tests/
│   ├── fixtures/
│   └── test_core.cpp
├── AGENTS.md
├── ARCHITECTURE.md
├── TODO.md
├── CHANGELOG.md
├── CMakeLists.txt
├── LICENSE
└── README.md
```

The `include/binx/` tree mirrors responsibilities in `src/`.

## 5. Core layer

### binary

`binx/core/binary` owns the inspected file representation and safe byte-access boundary.

It provides file size and bounded access. It does not know PE, ELF, Mach-O, DWARF, PDB, or CLI concepts.

### byte_reader

`binx/core/byte_reader` provides endian-aware primitive reads and bounded slices.

Conceptually:

```text
raw bytes + range
      |
      v
 ByteReader
      |
      +--> integer reads
      +--> endian conversion
      +--> bounded subviews
      +--> safe extraction
```

Format parsers should use these primitives rather than unchecked raw indexing.

### Diagnostics

Parser errors should identify the operation and, where useful, offset/size context. Unsupported, malformed, truncated, and unavailable data should be distinguishable.

## 6. Format detection

`src/formats/detect.cpp` performs conservative signature/type detection before format-specific parsing.

Recognized families include PE, ELF, Mach-O, and Windows minidump containers. ELF core dumps are identified through ELF metadata.

Unknown input should remain unknown rather than being guessed into a format.

## 7. PE subsystem

Located in:

```text
include/binx/formats/pe.hpp
src/formats/pe.cpp
```

Accumulated PE functionality includes:
- DOS/COFF headers;
- PE32/PE32+ optional headers;
- sections;
- RVA-to-file-offset mapping;
- imports;
- exports;
- relocations;
- resources;
- TLS;
- debug directory;
- CodeView/PDB metadata;
- characteristics/subsystem decoding;
- validation and diagnostics.

PE parsing returns structured data. It does not print directly.

## 8. ELF subsystem

Located in:

```text
include/binx/formats/elf.hpp
src/formats/elf.cpp
```

Supported functionality includes:
- ELF32/ELF64;
- little/big endian;
- file/section/program headers;
- interpreter;
- symbols;
- dynamic entries;
- notes;
- REL/RELA relocations;
- machine/type/section/segment/symbol decoding.

Dependency discovery can use `PT_DYNAMIC`/`PT_LOAD` data without requiring section headers.

ELF core dumps reuse safe ELF primitives and are interpreted by crash analysis.

## 9. Mach-O subsystem

Located in:

```text
include/binx/formats/macho.hpp
src/formats/macho.cpp
```

Its current role includes format metadata and dylib load-command dependency extraction.

Mach-O constants, load commands, and path-token rules remain isolated from generic analysis and CLI code.

## 10. Analysis layer

The analysis layer consumes parsed format data and/or bounded raw bytes and returns reusable result models.

### Byte analysis

`byte_analysis` handles strings, hex views, byte search, and region classification.

### Dependency analysis

`dependencies` handles:
- PE imports;
- ELF DT_NEEDED;
- Mach-O dylibs;
- recursive local resolution;
- explicit search paths;
- loader-relative path tokens;
- cycle detection;
- depth/node limits;
- unresolved dependencies;
- deterministic graphs.

Critical flow:

```text
dependency discovered
        |
        v
inspect local metadata/bytes
        |
        X  never load or execute it
```

### Disassembly

`disassembly` performs bounded offline x86/x86-64 decoding. It may identify instruction boundaries and branch targets, but it never executes decoded code.

### Symbols/debug

`symbols` unifies:
- ELF symbols;
- PE imports/exports;
- CodeView/PDB identity;
- DWARF section and compilation-unit discovery.

External symbol servers are outside the v1 boundary.

### Diff/size

`diff` compares byte streams and available section metadata.

It provides change counts, bounded hunks, similarity, section comparisons, and size breakdowns. Large-input work should be bounded where practical.

### Crash analysis

`crash` parses crash containers strictly as data.

Windows minidump analysis includes architecture, exception, crashing thread, modules, and stack descriptors where present.

ELF core analysis includes architecture, thread notes, and signal information where present.

No module loading or symbol downloading occurs.

### Unified report

`report` orchestrates existing analyzers rather than duplicating parsers.

A report can summarize:
- file identity/size;
- format/architecture/endianness/platform;
- dependencies;
- symbols;
- debug metadata;
- size totals;
- bounded string samples.

Detailed commands remain the source of deep analysis.

## 11. CLI layer

The CLI has two responsibilities:

1. Parse commands/options and choose an analysis operation.
2. Render structured results as text or JSON.

It should not contain binary-format parsing.

Preferred flow:

```text
argv
 |
 v
command/options
 |
 v
analysis engine
 |
 v
typed result
 |
 +----> text renderer
 |
 +----> JSON renderer
```

This makes analysis engines testable without terminal formatting.

## 12. JSON architecture

JSON is a compatibility surface.

Rules:
- explicit schema versions;
- stable field types;
- deterministic ordering;
- documented collection bounds;
- structured diagnostics;
- regression tests for representative output.

JSON should be generated from the same result models used for text output.

## 13. Hashing

Hashing lives under:

```text
include/binx/hashing/hasher.hpp
src/hashing/hasher.cpp
```

Platform implementation:
- Windows: CNG/BCrypt;
- non-Windows: OpenSSL Crypto.

Higher layers depend on the small hashing interface, not platform APIs.

## 14. Build architecture

CMake is authoritative.

```text
CMake
 |
 +--> binx executable
 |
 +--> binx_tests
 |
 +--> CTest
 |
 +--> install rules
```

C++20 is required. Existing strict warning flags should remain enabled.

## 15. Testing architecture

```text
unit
  +--> core readers
  +--> format parsers
  +--> analysis algorithms

integration
  +--> synthetic fixtures
  +--> CLI behavior
  +--> JSON output

regression
  +--> malformed/truncated inputs
  +--> fixed parser bugs

CI
  +--> Windows build/test
  +--> Linux build/test
```

Malformed binary data is a first-class test category.

## 16. Security architecture

The trust boundary is explicit:

```text
UNTRUSTED INPUT
      |
      v
bounded reader
      |
      v
validated parser
      |
      v
typed analysis result
      |
      v
deterministic renderer
```

Parsed metadata must never invoke external processes, dynamic loaders, shell commands, or network clients.

Dependency paths must be explicit and bounded.

## 17. Modularity strategy

Modularize by responsibility, not by creating hundreds of trivial wrappers.

Good:
- one parser per format family;
- reusable reader primitives;
- independent analysis engines;
- separate renderers;
- common diagnostics/results.

Bad:
- one class per trivial field;
- wrappers that only rename functions;
- abstractions that hide bounds checking;
- a universal parser abstraction that erases useful format-specific capabilities.

The goal is maximum useful separation with minimum accidental complexity.

## 18. v1.0 target

```text
                 +------------------+
                 |      binx        |
                 +--------+---------+
                          |
                    CLI orchestration
                          |
       +------------------+------------------+
       |                  |                  |
   format data        raw bytes          metadata
       |                  |                  |
       +------------------+------------------+
                          |
                    analysis engines
                          |
               typed deterministic results
                          |
                 +--------+--------+
                 |                 |
              terminal           JSON
```

No cloud service is required anywhere in this graph.

## 19. Post-v1 extension boundary

A future cloud/API system should look like:

```text
                    Local BinX Core
                         |
              +----------+----------+
              |                     |
        local CLI             optional library
                                    |
                              explicit adapter
                                    |
                               remote API
```

The remote adapter must be opt-in. Local analysis must remain useful when networking is unavailable.

## 20. Architectural invariants

Before v1.0:
- [ ] All reads are bounds-checked.
- [ ] Parser arithmetic is overflow-safe.
- [ ] Malformed input cannot trigger execution.
- [ ] Dependency resolution never loads binaries.
- [ ] Debug/symbol analysis never contacts external servers.
- [ ] Output is deterministic.
- [ ] JSON contracts are documented.
- [ ] Analysis is independent of terminal rendering.
- [ ] Format parsers are independent of CLI dispatch.
- [ ] Windows and Linux CI pass.
- [ ] Local core has no cloud/API requirement.
