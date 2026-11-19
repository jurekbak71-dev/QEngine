#!/usr/bin/env python3
"""Read-only instruction-level check of Core 5.2.0 parameter value paths.

Confirms byte input with tag 4 and float32-to-float64 path with tag 7.
Does not infer defaults, min/max or external plugin support.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from trace_spatial_parameter_sites import sections, va_to_file

PATHS = {
    "byte": {
        "callee_va": 0x014CDA18,
        "instructions": {
            0x014CDA34: (0xE1A08003, "mov r8, r3"),
            0x014CDB60: (0xE5D83000, "ldrb r3, [r8]"),
            0x014CDB8C: (0xE3A02004, "mov r2, #4"),
            0x014CDB90: (0xE5C32000, "strb r2, [r3]"),
        },
        "observed_type_tag": 4,
        "source_kind": "byte",
    },
    "floating": {
        "callee_va": 0x014CD12C,
        "instructions": {
            0x014CD148: (0xE1A08003, "mov r8, r3"),
            0x014CD264: (0xEDD87A00, "vldr s15, [r8]"),
            0x014CD278: (0xEEF70AE7, "vcvt.f64.f32 d16, s15"),
            0x014CD298: (0xE3A02007, "mov r2, #7"),
            0x014CD29C: (0xE5C32000, "strb r2, [r3]"),
            0x014CD2A0: (0xE1C380F8, "strd r8, r9, [r3, #8]"),
        },
        "observed_type_tag": 7,
        "source_kind": "float32 converted to float64",
    },
}


def check_instruction_set(blob, section_map, mapping=PATHS):
    observations = []
    for path_name, meta in mapping.items():
        evidence = []
        for va, (expected, semantic) in meta["instructions"].items():
            file_offset = va_to_file(va, section_map)
            actual = (struct.unpack_from("<I", blob, file_offset)[0]
                      if file_offset is not None and file_offset + 4 <= len(blob)
                      else None)
            evidence.append({"address": f"0x{va:08X}", "expected": f"0x{expected:08X}",
                             "actual": f"0x{actual:08X}" if actual is not None else None,
                             "instruction": semantic, "matches": actual == expected})
        observations.append({"name": path_name,
                             "callee_va": f"0x{meta['callee_va']:08X}",
                             "source_kind": meta["source_kind"],
                             "observed_type_tag": meta["observed_type_tag"],
                             "instruction_matches": sum(item['matches'] for item in evidence),
                             "instruction_count": len(evidence), "instructions": evidence})
    return observations


def verify(blob):
    if blob[:6] != b'\x7fELF\x01\x01' or len(blob) < 52 or struct.unpack_from('<H', blob, 18)[0] != 40:
        raise ValueError('Expected ARM32 little endian ELF')
    evidence = check_instruction_set(blob, sections(blob))
    return {"evil_sha256": hashlib.sha256(blob).hexdigest(),
            "total_matched": sum(item['instruction_matches'] for item in evidence),
            "total_checked": sum(item['instruction_count'] for item in evidence),
            "all_instruction_patterns_match": all(
                item['instruction_matches'] == item['instruction_count'] for item in evidence),
            "paths": evidence,
            "interpretation": "Read-only evidence of byte/tag4 and float32-to-float64/tag7 code paths; not parameter bounds or defaults"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil', type=Path, required=True)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    result = json.dumps(verify(args.evil.read_bytes()), ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(result, encoding='utf-8')
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
