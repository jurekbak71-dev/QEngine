#!/usr/bin/env python3
"""Offline verification of ARM32 PC-relative vtable references; does not execute firmware."""
import argparse
import json
import struct
from pathlib import Path
from probe_dsp_vtables import discover, va_to_file, sections


def arm_pc_literal_vtable_reference(blob, function_va, expected_vtable_va, elf_sections):
    foff = va_to_file(function_va & ~1, elf_sections)
    if foff is None or foff + 120 > len(blob):
        return False
    words = struct.unpack_from('<30I', blob, foff)
    for i, opcode in enumerate(words):
        if (opcode & 0xfffff000) != 0xe59f3000:
            continue
        literal_va = (function_va & ~1) + 4*i + 8 + (opcode & 0xfff)
        literal_off = va_to_file(literal_va, elf_sections)
        if literal_off is None or literal_off + 4 > len(blob):
            continue
        delta = struct.unpack_from('<i', blob, literal_off)[0]
        for j in range(i + 1, min(i + 12, len(words))):
            if words[j] == 0xe08f3003:
                computed = ((function_va & ~1) + 4*j + 8 + delta) & 0xffffffff
                if computed == expected_vtable_va:
                    return True
    return False


def verify(blob):
    ss = sections(blob)
    report = discover(blob)
    matches = []
    for module in report['results']:
        vtables = [v for ti in module['typeinfo_candidates'] for v in ti['candidate_vtables']]
        ok = any(arm_pc_literal_vtable_reference(blob, v['first_virtual_function_va'],
                                                  v['vtable_va'], ss) for v in vtables)
        matches.append({'type': module['type'], 'pc_relative_vtable_reference': ok})
    return {'modules_checked': len(matches),
            'modules_matched': sum(m['pc_relative_vtable_reference'] for m in matches),
            'results': matches}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = json.dumps(verify(args.evil.read_bytes()), indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(report, encoding='utf-8')
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
