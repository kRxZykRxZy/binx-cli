# Security

## Scope

BinX analyzes untrusted binary and crash-dump files.

## Security model

BinX is designed to inspect bytes without executing target code. It must not:

- execute an input binary;
- load target DLLs or shared libraries;
- invoke TLS callbacks;
- download symbols or other external data;
- make network requests because an input references an external resource.

## Reporting a vulnerability

Please report security issues privately to the repository maintainers rather than opening a public issue containing exploit details. Include the affected command, a minimal reproducer where safe, expected behaviour, observed behaviour and the BinX version.

## Defensive expectations

Parser changes should retain explicit bounds checks, avoid integer overflow in offset/size calculations, cap attacker-controlled counts, and preserve deterministic failure behaviour.
