# TODO.md

# BinX Engineering TODO

Current release: **v0.95.0**  
Target: **v1.0 — Complete Local Toolkit**

The goal is to finish and harden the local/offline product before considering any cloud/API layer.

## P0 — v1.0 release gate

### Core safety and correctness
- [ ] Audit every parser for offset + length overflow.
- [ ] Audit every parser for truncation handling.
- [ ] Audit count-to-byte-size calculations.
- [ ] Ensure malformed optional structures produce diagnostics instead of crashes.
- [ ] Verify no analysis path executes or dynamically loads an inspected file.
- [ ] Verify dependency resolution never loads a discovered module.
- [ ] Verify symbol/debug paths never perform network access.
- [ ] Verify no telemetry exists.

### CLI consistency
- [ ] Normalize command aliases and help text.
- [ ] Standardize exit codes for success, malformed input, unsupported format, and usage errors.
- [ ] Standardize JSON error objects.
- [ ] Ensure structured-analysis commands have deterministic `--json` output.
- [ ] Make `--output` behavior consistent where supported.
- [ ] Audit verbose output for nondeterminism.
- [ ] Add/expand command smoke tests.

### PE
- [ ] Expand PE32/PE32+ malformed-header coverage.
- [ ] Verify RVA/file-offset mapping on boundary and overlapping sections.
- [ ] Harden imports, exports, relocations, resources, TLS, and debug parsing.
- [ ] Expand CodeView/PDB identity edge cases.
- [ ] Cover unusual section alignment and virtual-size cases.
- [ ] Expand machine/characteristic decoding.

### ELF
- [ ] Expand ELF32/ELF64 malformed-input coverage.
- [ ] Verify little- and big-endian paths consistently.
- [ ] Harden section/program-header relationship validation.
- [ ] Expand dynamic, relocation, and note parsing tests.
- [ ] Expand symbol binding/type/visibility coverage.
- [ ] Expand PT_DYNAMIC/PT_LOAD dependency discovery.
- [ ] Harden ELF core-dump note traversal.

### Mach-O
- [ ] Expand Mach-O detection and metadata coverage.
- [ ] Cover supported 32/64-bit variants.
- [ ] Cover load-command boundary cases.
- [ ] Expand dylib dependency/path-token parsing.
- [ ] Document unsupported Mach-O features explicitly.

### Byte/string/search
- [ ] Add more string-encoding fixtures.
- [ ] Test very large files with bounded scanning.
- [ ] Test wildcard hex-search edge cases.
- [ ] Verify region classification on malformed/unknown formats.
- [ ] Add regression coverage for overlapping matches.

### Dependency analysis
- [ ] Harden recursive traversal limits.
- [ ] Test multi-node cycles.
- [ ] Verify deterministic graph ordering.
- [ ] Expand Windows/ELF/Mach-O search-path tests.
- [ ] Test unresolved dependencies without failing unrelated analysis.
- [ ] Keep DOT output deterministic.

### Disassembly
- [ ] Expand x86/x86-64 opcode coverage.
- [ ] Test invalid/truncated instruction streams.
- [ ] Verify entry-point and bounded-length modes.
- [ ] Verify branch target reporting.
- [ ] Ensure disassembly never executes code.
- [ ] Document architecture limitations.

### Symbols and debug
- [ ] Expand ELF symbol classification.
- [ ] Expand PE import/export normalization.
- [ ] Expand CodeView/PDB identity parsing.
- [ ] Expand DWARF v2-v5 discovery tests.
- [ ] Harden malformed DWARF length/unit handling.
- [ ] Keep debug analysis bounded and offline.
- [ ] Do not add symbol-server downloading to v1.

### Diff and size
- [ ] Expand byte-level diff fixtures.
- [ ] Test identical, empty, prefix, suffix, and divergent files.
- [ ] Test large inputs with bounded memory use.
- [ ] Verify section-level PE/ELF comparisons are deterministic.
- [ ] Document size-category calculations.
- [ ] Keep diff/size JSON schema stable.

### Crash analysis
- [ ] Expand Windows minidump stream coverage.
- [ ] Expand malformed minidump-directory tests.
- [ ] Expand ELF core-note coverage.
- [ ] Test unknown architectures/signals cleanly.
- [ ] Bound module/thread enumeration.
- [ ] Keep crash analysis offline and non-executing.

### Unified reporting
- [ ] Verify reports for each supported format.
- [ ] Ensure failed optional analyzers do not corrupt unrelated fields.
- [ ] Add PE/ELF/Mach-O report fixtures.
- [ ] Add deterministic JSON snapshots.
- [ ] Keep report as orchestration, not duplicate parsing.
- [ ] Keep string samples and other summaries bounded.

## P1 — Quality and maintainability

### Modularization
- [ ] Keep `main.cpp` focused on dispatch.
- [ ] Split oversized CLI parsing/output responsibilities where useful.
- [ ] Keep format-specific logic in `src/formats/`.
- [ ] Keep cross-format analysis in `src/analysis/`.
- [ ] Keep presentation separate from analysis models.
- [ ] Prefer reusable parser primitives over duplicated bounds checks.
- [ ] Introduce shared diagnostics/results only where they reduce duplication without creating a monolith.

### Test infrastructure
- [ ] Add fixture helpers for minimal PE/ELF/Mach-O inputs.
- [ ] Add local malformed/fuzz-style byte cases.
- [ ] Add CLI integration tests for major commands.
- [ ] Add JSON regression tests.
- [ ] Test empty and very small inputs.
- [ ] Test maximum/boundary integer values.
- [ ] Keep CI runtime reasonable.

### Build/release
- [ ] Verify clean Windows build from a fresh checkout.
- [ ] Verify clean Linux build from a fresh checkout.
- [ ] Test Release builds.
- [ ] Test installation layout.
- [ ] Make versioning authoritative/consistent.
- [ ] Add release packaging documentation.
- [ ] Consider reproducible-build guidance.

### Documentation
- [ ] Refresh README command examples.
- [ ] Complete CHANGELOG through v1.0.
- [ ] Add `docs/v1.0.md`.
- [ ] Expand `docs/json.md` into a complete schema reference.
- [ ] Keep ARCHITECTURE.md synchronized with module boundaries.
- [ ] Keep AGENTS.md synchronized with engineering invariants.
- [ ] Document unsupported features explicitly.

## P2 — Post-v1 local backlog

- [ ] Additional binary formats where justified.
- [ ] More architectures for disassembly.
- [ ] Deeper DWARF line/type information.
- [ ] Additional Mach-O analysis.
- [ ] Richer crash unwind metadata.
- [ ] Optional plugin architecture for analysis modules.
- [ ] Performance benchmarks and profiling.
- [ ] Library API for embedding the local analyzer.
- [ ] Package-manager distribution.
- [ ] Cross-platform release artifacts.

## Post-v1 — separate cloud direction

Cloud/API functionality is **not part of v0.1-v1.0**.

Potential future work:
- [ ] Optional remote analysis service.
- [ ] Authentication and usage controls.
- [ ] Server-side sandboxing.
- [ ] API versioning.
- [ ] Rate limiting.
- [ ] Privacy/data-retention controls.
- [ ] Explicit opt-in upload flow.
- [ ] Local-core/cloud-adapter separation.

No post-v1 feature should silently add network behavior to the local `binx` executable.

## Historical milestone status

- [x] v0.1 foundation
- [x] v0.2 deep PE inspection
- [x] v0.3 deep ELF inspection
- [x] v0.4 strings/hex/search/regions
- [x] v0.5 dependency analysis
- [x] v0.6 disassembly
- [x] v0.7 symbols/debug information
- [x] v0.8 diff/size analysis
- [x] v0.9 crash analysis
- [x] v0.95 unified analysis/reporting
- [ ] v1.0 final hardening/release gate
