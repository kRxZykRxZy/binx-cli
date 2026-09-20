# BinX Testing

The regression suite has two independent executable tests:

- `binx_core` exercises parsers, analysis engines, hashing, crash handling and unified reports.
- `binx_cli` exercises CLI option parsing, aliases and shared formatting helpers.

CTest also executes `binx --help` and `binx --version`.

## Release gates

Every v1 change should pass:

    cmake --preset release
    cmake --build --preset release
    ctest --preset release

and sanitizer coverage where supported:

    cmake --preset asan
    cmake --build --preset asan
    ctest --preset asan

CI additionally covers GCC, Clang, MSVC, sanitizer builds and Windows CPack packaging.
