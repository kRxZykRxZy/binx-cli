# AGENTS.md

## Purpose

BinX (Binary Inspector) is a local, developer-first binary analysis toolkit. The CLI executable is `binx`.

The project is intentionally offline-first through v1.0: no cloud/API dependency, telemetry, hidden network access, target execution, or dynamic loading.

## Current state

- Current release: **v0.95.0**
- Next milestone: **v1.0**
- Language: C++20
- Build: CMake 3.20+
- CI: GitHub Actions on Windows and Linux
- Tests: CTest + native C++ tests

Roadmap:
`v0.1 foundation -> v0.2 PE -> v0.3 ELF -> v0.4 byte/string/search -> v0.5 dependencies -> v0.6 disassembly -> v0.7 symbols/debug -> v0.8 diff/size -> v0.9 crash -> v0.95 reporting -> v1.0 complete local toolkit`.

Cloud/API is **post-v1 only**.

## Safety invariants

Treat every input as untrusted bytes.

Never:
- execute an inspected binary;
- load target DLLs/shared libraries/bundles;
- invoke TLS callbacks;
- resolve dependencies by loading them;
- download PDBs, symbols, or other external analysis data;
- add telemetry or hidden network requests;
- mutate the inspected input.

Dependency analysis may inspect explicitly configured local files, but must never execute or dynamically load them.

Crash dumps are untrusted containers and must be parsed with the same bounds-safety rules.

## Architecture rules

Keep the repository modular:

- `src/core/` — bounded binary access and common primitives.
- `src/formats/` — PE/ELF/Mach-O parsing and detection.
- `src/analysis/` — byte analysis, dependencies, disassembly, symbols/debug, diff/size, crash, reporting.
- `src/hashing/` — platform hashing.
- `src/cli/` — rendering/presentation.
- `src/main.cpp` — command dispatch/orchestration.
- `include/binx/` mirrors subsystem interfaces.
- `tests/` — deterministic tests and fixtures.
- `docs/` — feature and JSON documentation.

Do not grow `main.cpp` into a parser or duplicate format logic in CLI output code.

## Parser requirements

Every parser must:

1. validate offsets before reading;
2. validate lengths before slicing;
3. protect offset/length arithmetic from integer overflow;
4. reject impossible counts and spans;
5. return structured diagnostics/errors for malformed input;
6. recover from damaged optional structures only when bounds prove recovery is safe.

Malformed input is normal input for a binary inspector.

## Determinism

Identical input/options should produce identical text and JSON output.

Avoid unordered output where ordering matters, generated timestamps, environment-dependent fields, and unstable absolute paths in machine-readable results.

## JSON compatibility

JSON is a compatibility surface.

When changing a schema:
- document the change;
- avoid silent type changes;
- add regression tests;
- update `docs/json.md`;
- update the relevant release documentation.

## CLI conventions

Current command families include:

`info`, `inspect`, `sections`, `imports`, `exports`, `resources`, `relocations`, `segments`, `symbols`, `debug`, `dynamic`, `notes`, `strings`, `hexdump`, `search`, `regions`, `deps`, `graph`, `disasm`, `diff`, `size`, `crash`, `report`, `hash`.

New analysis commands should:
- provide `--help`;
- provide `--json` where structured output is meaningful;
- have predictable exit/error behavior;
- have tests;
- be documented.

## C++ standards

Use C++20, RAII, const-correctness, explicit ownership, standard containers, smart pointers, narrow interfaces, and descriptive names.

Avoid owning raw pointers, global mutable state, unnecessary dependencies, and compiler-specific behavior outside isolated platform code.

Preserve the existing strict warning flags.

## Build and test

Windows:

```cmd
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
build\Release\binx.exe --help
```

Linux/macOS:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

CI must be green before release.

## Test strategy

Each parser/analysis feature should have:
- valid fixtures;
- malformed/truncated fixtures;
- boundary/overflow tests;
- representative format/architecture variants where applicable;
- deterministic text/JSON assertions;
- regression tests for fixed bugs.

Synthetic fixtures are preferred for exact parser-state coverage.

## Documentation

Keep these synchronized:

- `README.md` — user-facing overview and commands.
- `CHANGELOG.md` — release history.
- `docs/vX.Y.md` — milestone behavior.
- `docs/json.md` — machine-readable contracts.
- `ARCHITECTURE.md` — implementation structure.
- `TODO.md` — active and future engineering work.

Do not call a feature complete until implementation, tests, documentation, and CI coverage are complete.

## v1.0 release gate

Before v1.0:
- all v0.x command families are stable;
- PE/ELF/Mach-O detection is safe;
- malformed input is handled safely;
- JSON output is documented/tested;
- dependency traversal remains non-executing;
- symbols/debug remain offline;
- diff/size/crash/report are covered;
- CLI help/version/errors are consistent;
- Windows and Linux CI are green;
- release documentation is complete.

v1.0 means a coherent, production-usable local toolkit; it does not require every imaginable reverse-engineering feature.

## Future boundary

Post-v1 cloud/API work must be architecturally separated from the local core. The v1 analyzer must remain fully useful without a network connection.
