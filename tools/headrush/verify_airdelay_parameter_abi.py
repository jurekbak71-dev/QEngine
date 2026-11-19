#!/usr/bin/env python3
"""Read-only verification of ARM32 AIR Delay name/length and value ABI patterns.

It proves literal string-length matches and byte/float loads at known sites.
It does not establish UI-accessible parameters, bounds or DSP patchability.
"""
import argparse
import json
import struct
from pathlib import Path
from trace_spatial_parameter_sites import sections, va_to_file
from trace_airdelay_argument_layout import trace

BYTE_CALLEE = 0x014CDA18
FLOAT_CALLEE = 0x014CD12C
CALLEE_PATTERNS = {
    BYTE_CALLEE: (0x014CDA34, 0xE1A08003, 0x014CDB60, 0xE5D83000, "byte"),
    FLOAT_CALLEE: (0x014CD148, 0xE1A08003, 0x014CD264, 0xEDD87A00, "float32"),
}


def word(blob, sec, va):
    off = va_to_file(va, sec)
    if off is None or off + 4 > len(blob):
        raise ValueError("Unmapped instruction 0x%x" % va)
    return struct.unpack_from("<I", blob, off)[0]


def validate(blob, layout=None):
    sec = sections(blob)
    rows = (layout if layout is not None else trace(blob))["rows"]
    if not rows:
        raise ValueError("No AIR Delay calls")
    findings = []
    for item in rows:
        path, slots = item["path"], item["stack_slots"]
        if not isinstance(path, str) or not slots.get("4") or not slots.get("8"):
            raise ValueError("Missing parameter path or stack slot")
        target = item["destination_va"]
        if target not in CALLEE_PATTERNS:
            raise ValueError("Unknown callee 0x%x" % target)
        mov_va, mov_op, read_va, read_op, kind = CALLEE_PATTERNS[target]
        moved = word(blob, sec, mov_va) == mov_op
        loaded = word(blob, sec, read_va) == read_op
        caller = any(word(blob, sec, va) == 0xE1A03006
                     for va in range(item["call_va"] - 28, item["call_va"], 4))
        n = slots["4"]["value_bits"]
        name_bytes = len(path.encode("utf-8"))
        findings.append({
            "path": path, "name_bytes": name_bytes,
            "passed_length": n, "name_length_matches": n == name_bytes,
            "callee_va": target, "value_load_kind": kind,
            "callee_r8_from_r3": moved, "callee_reads_r8": loaded,
            "caller_r3_from_r6": caller,
        })
    return {
        "calls_checked": len(findings),
        "name_lengths_matched": sum(i["name_length_matches"] for i in findings),
        "valid_callee_read_patterns": sum(
            i["callee_r8_from_r3"] and i["callee_reads_r8"] and i["caller_r3_from_r6"]
            for i in findings),
        "results": findings,
        "caution": "30/31/32 match string byte lengths, not parameter IDs or bounds. Interpretation of actual values remains unverified.",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evil", required=True, type=Path)
    p.add_argument("--layout", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    prior = json.loads(a.layout.read_text()) if a.layout else None
    result = json.dumps(validate(a.evil.read_bytes(), prior), indent=2, ensure_ascii=False) + "\n"
    if a.output:
        a.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
