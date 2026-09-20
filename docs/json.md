# BinX JSON interface

## v0.2 schema

PE commands use schema version 2:

    {
      "schema_version": 2,
      "format": "PE32+",
      "headers": {},
      "sections": [],
      "imports": [],
      "exports": [],
      "relocations": [],
      "resources": [],
      "tls": {},
      "debug": {},
      "statuses": {},
      "diagnostics": []
    }

Addresses are hexadecimal strings so consumers do not lose 64-bit precision.

Terminal formatting and JSON are separate renderings of the same parsed model. Binary parsers never emit JSON directly.

## v0.1 compatibility

Generic info output continues to use schema version 1 for non-PE files and retains the v0.1 fields.

## Diagnostics

Each diagnostic contains:
- severity
- stable code
- component
- optional file offset
- optional RVA
- message

Scripts should branch on code, not human-readable message.


## v1.0 schema policy

JSON schema versions are scoped to command families rather than tied to the application version. Existing schemas remain available for backward compatibility while each renderer owns its documented structure.

Current stable schemas include PE inspection (v2), ELF inspection (v3), byte-analysis output (v4), symbol/debug output (v5), dependency output (v5), binary diff/size output (v6), crash output (v7), and unified reporting (v5).

All JSON output is generated from structured models. Shared escaping is implemented in the reusable core text module.

Consumers should validate `schema_version` and branch on stable field names/codes rather than terminal wording.
