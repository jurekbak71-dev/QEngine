#!/usr/bin/env python3
"""Read-only ARM literal and PC-relative ADD cross-references for DSP vtables.

This script analyses a vendor ELF supplied locally; it does not execute,
patch, or publish the firmware. Hits are static candidates, not call traces.
"""
import argparse
import json
import struct
from collections import defaultdict
from pathlib import Path
from probe_dsp_vtables import discover, sections, va_to_file


def find_references(blob, targets):
    sec = sections(blob)
    code = next(s for s in sec if s['name'] == '.text')
    start, length = code['offset'], code['size']
    target_set = set(targets)
    loads = defaultdict(dict)
    for off in range(start, start + length - 3, 4):
        word = struct.unpack_from('<I', blob, off)[0]
        if (word & 0x0F7F0000) != 0x051F0000 or not (word & (1 << 24)):
            continue
        reg = (word >> 12) & 15
        if reg == 15:
            continue
        va = code['addr'] + off - start
        literal_va = va + 8 + (word & 0xFFF) * (1 if word & (1 << 23) else -1)
        literal_off = va_to_file(literal_va, sec)
        if literal_off is None or literal_off + 4 > len(blob):
            continue
        displacement = struct.unpack_from('<i', blob, literal_off)[0]
        loads[reg][va] = (displacement, literal_va)
    hits = defaultdict(list)
    for off in range(start, start + length - 3, 4):
        word = struct.unpack_from('<I', blob, off)[0]
        if (word & 0x0FFF0FF0) != 0x008F0000:
            continue
        reg, source = (word >> 12) & 15, word & 15
        if reg != source or reg == 15:
            continue
        va = code['addr'] + off - start
        for load_va in range(max(code['addr'], va - 64), va, 4):
            item = loads[reg].get(load_va)
            if not item:
                continue
            displacement, literal_va = item
            target = (va + 8 + displacement) & 0xFFFFFFFF
            if target in target_set:
                hits[target].append({'ldr_va': load_va, 'add_va': va,
                                     'literal_va': literal_va, 'target_va': target})
    return hits


def inspect(blob):
    inventory = discover(blob)
    targets = set()
    for module in inventory['results']:
        for typeinfo in module['typeinfo_candidates']:
            for vt in typeinfo['candidate_vtables']:
                targets.update((vt['vtable_va'], vt['vtable_va'] + 8))
    refs = find_references(blob, targets)
    entries = []
    for module in inventory['results']:
        vtables = [v['vtable_va'] for t in module['typeinfo_candidates']
                   for v in t['candidate_vtables']]
        matched = [ref for va in vtables for delta in (0, 8)
                   for ref in refs.get(va + delta, [])]
        entries.append({'type': module['type'], 'vtable_vas': vtables,
                        'references': matched})
    return {'modules': len(entries),
            'modules_with_references': sum(bool(x['references']) for x in entries),
            'total_references': sum(len(x['references']) for x in entries),
            'results': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = json.dumps(inspect(args.evil.read_bytes()), indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(report, encoding='utf-8')
    else:
        print(report, end='')


if __name__ == '__main__':
    main()
