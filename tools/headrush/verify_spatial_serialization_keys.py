#!/usr/bin/env python3
"""Read-only cross-check of ARM string key references against Core factory rigs.

Confirms ARM references to 'type' and ('state' or 'value') and shared
construction helper; does not prove ABI, editable DSP or accepted ranges.
"""
import argparse
import json
import sqlite3
import struct
from pathlib import Path

from trace_spatial_parameter_sites import sections, va_to_file, decode_branch

KEY_SITES = {
    "byte": (
        ("type", 0x014CDA8C, 0x014CDAA0, 0x014CDABC),
        ("state", 0x014CDAC8, 0x014CDAD0, 0x014CDAE8),
    ),
    "floating": (
        ("type", 0x014CD1A0, 0x014CD1B4, 0x014CD1D0),
        ("value", 0x014CD1DC, 0x014CD1E4, 0x014CD1FC),
    ),
}
CONSTRUCTOR_VA = 0x009F43F8


def get_word(blob, mapping, va):
    offset = va_to_file(va, mapping)
    if offset is None or offset + 4 > len(blob):
        raise ValueError("unmapped instruction 0x%x" % va)
    return struct.unpack_from("<I", blob, offset)[0]


def get_name(blob, mapping, ldr_va, add_va):
    ldr = get_word(blob, mapping, ldr_va)
    add = get_word(blob, mapping, add_va)
    if (ldr & 0xfffff000) != 0xe59f1000 or add != 0xe08f1001:
        raise ValueError("unexpected LDR/ADD instruction pattern")
    literal_va = ldr_va + 8 + (ldr & 0xfff)
    displacement = get_word(blob, mapping, literal_va)
    if displacement & 0x80000000:
        displacement -= 0x100000000
    target_va = (add_va + 8 + displacement) & 0xffffffff
    offset = va_to_file(target_va, mapping)
    if offset is None:
        raise ValueError("string target not mapped")
    terminator = blob.find(b"\x00", offset, min(offset+128, len(blob)))
    if terminator < 0:
        raise ValueError("unterminated string")
    return blob[offset:terminator].decode("ascii")


def inspect_code(blob, mapping=None, sites=KEY_SITES):
    if mapping is None:
        if len(blob) < 52 or blob[:6] != b"\x7fELF\x01\x01":
            raise ValueError("expected ELF32 little-endian")
        mapping = sections(blob)
    findings = []
    for family, entries in sites.items():
        for expected, ldr, add, call in entries:
            actual = get_name(blob, mapping, ldr, add)
            target = decode_branch(get_word(blob, mapping, call), call)
            findings.append({"family": family, "expected_key": expected,
                             "recovered_key": actual, "key_matches": actual == expected,
                             "constructor_va": target,
                             "constructor_matches": target == CONSTRUCTOR_VA,
                             "ldr_va": ldr, "add_va": add, "call_va": call})
    return {"matched_keys": sum(x["key_matches"] for x in findings),
            "matched_constructors": sum(x["constructor_matches"] for x in findings),
            "total": len(findings), "findings": findings}


def inspect_factory_db(path):
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute("SELECT content FROM rigs").fetchall()
    counts = {"state": 0, "value": 0, "mixed": 0}
    examples = {}
    for (raw,) in rows:
        rig = json.loads(raw)
        patch = rig["data"]["Patch"]["children"]
        for instance, node in patch.items():
            if instance != "AIR Delay" and not instance.startswith("AIR Delay "):
                continue
            for key, item in node.get("children", {}).items():
                if "state" in item and "value" in item:
                    counts["mixed"] += 1
                elif "state" in item and "type" in item:
                    counts["state"] += 1
                    examples.setdefault("state", {"key": key, "item": item})
                elif "value" in item and "type" in item:
                    counts["value"] += 1
                    examples.setdefault("value", {"key": key, "item": item})
    return {"rig_count": len(rows), "air_delay_parameter_instances": counts,
            "example_items": examples}


def inspect(blob, db_path=None):
    evidence = {"code": inspect_code(blob),
                "caution": "Key names match serialized preset layout. Type tags 4/5/7 in native memory have NOT been equated with preset JSON type codes."}
    if db_path is not None:
        evidence["factory"] = inspect_factory_db(db_path)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evil", required=True, type=Path)
    parser.add_argument("--db", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = inspect(args.evil.read_bytes(), args.db)
    content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(content, encoding="utf-8")
    else:
        print(content, end="")


if __name__ == "__main__":
    main()
