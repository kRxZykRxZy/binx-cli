# Contributing to BinX

## Development requirements

- C++20 compiler
- CMake 3.20+
- OpenSSL Crypto on non-Windows systems
- Git

## Repository structure

Core parsing and reusable APIs live under include/binx/ and src/. CLI-only code belongs under include/binx/cli/ and src/cli/. Regression tests live in tests/; release and architecture documentation lives in docs/.

## Change requirements

Every parser change should include malformed-input coverage where practical. Every new CLI command should have option parsing coverage and at least one regression test for its output or dispatch path.

Do not add network access, telemetry, dynamic loading or target execution to the analysis core.

## Local verification

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ctest --test-dir build --output-on-failure

For sanitizer verification:

    cmake -S . -B build-asan -DBINX_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
    cmake --build build-asan
    ctest --test-dir build-asan --output-on-failure

Keep commits focused and document user-visible changes in CHANGELOG.md.
