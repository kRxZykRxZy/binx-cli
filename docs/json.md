# BinX v0.1 JSON

JSON output is intended for scripts and CI.

Example:

```json
{
  "file": {
    "name": "app.exe",
    "size": 184832
  },
  "format": "PE32+",
  "architecture": "x86-64",
  "endianness": "little",
  "platform": "Windows",
  "valid": true,
  "entry_point": "0x140001000",
  "entry_point_rva": "0x1000",
  "image_base": "0x140000000",
  "machine": 34404,
  "section_count": 6,
  "image_size": 20480,
  "headers_size": 1024,
  "subsystem": 3,
  "timestamp": 0
}
```

Fields that are not applicable to a format may be omitted. Hexadecimal address values are strings so JSON consumers do not lose precision.
