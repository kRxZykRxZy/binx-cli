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
