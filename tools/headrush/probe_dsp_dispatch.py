#!/usr/bin/env python3
"""Read-only scan of a HeadRush ARM32 computed-branch DSP factory candidate.

The dispatch pattern is CMP r0,#138; ADDLS pc,pc,r0,lsl#2. Indices and
branch targets are static candidates, not proof of Remote Editor ModuleType IDs.
"""
import argparse
import json
import struct
from pathlib import Path
from probe_dsp_factory_xrefs import inspect as get_references
from probe_dsp_vtables import sections, va_to_file

PATTERN = (0xe350008a, 0x908ff100)


def decode_branch(word, address):
    if (word & 0x0f000000) != 0x0a000000:
        raise ValueError('Expected immediate ARM B')
    displacement = word & 0x00ffffff
    if displacement & 0x800000:
        displacement -= 0x1000000
    return (address + 8 + (displacement << 2)) & 0xffffffff


def locate_dispatch(blob):
    sec = sections(blob)
    code = next(s for s in sec if s['name'] == '.text')
    found = []
    for off in range(code['offset'], code['offset'] + code['size'] - 12, 4):
        if struct.unpack_from('<II', blob, off) != PATTERN:
            continue
        va = code['addr'] + off - code['offset']
        third = struct.unpack_from('<I', blob, off + 8)[0]
        if (third & 0xff000000) != 0xea000000:
            continue
        table_va = va + 12
        table_file = va_to_file(table_va, sec)
        if table_file is None:
            continue
        targets = []
        for index in range(139):
            addr = table_va + 4 * index
            insn = struct.unpack_from('<I', blob, table_file + 4 * index)[0]
            targets.append(decode_branch(insn, addr))
        found.append({'dispatch_va': va, 'jump_table_va': table_va,
                      'default_target_va': decode_branch(third, va + 8),
                      'targets': targets})
    return found


def inspect(blob):
    dispatches = locate_dispatch(blob)
    if len(dispatches) != 1:
        raise ValueError(f'Expected unique DSP dispatch pattern; found {len(dispatches)}')
    switch = dispatches[0]
    xref = get_references(blob)
    by_add = {}
    for entry in xref['results']:
        for hit in entry['references']:
            by_add.setdefault(hit['add_va'], set()).add(entry['type'])
    cases = []
    for index, target in enumerate(switch['targets']):
        # Keep the next sequential constructor case outside the lookahead window.
        nearest = sorted((va - target, typ) for va, types in by_add.items()
                         if 0 <= va - target <= 48 for typ in types)
        selected = nearest[0][1] if nearest and target != switch['default_target_va'] else None
        cases.append({'case': index, 'branch_target_va': target,
                      'candidate_dsp_type': selected,
                      'vtable_reference_offset': nearest[0][0] if selected else None,
                      'default': target == switch['default_target_va']})
    return {'dispatch_va': switch['dispatch_va'],
            'jump_table_va': switch['jump_table_va'],
            'default_target_va': switch['default_target_va'],
            'mapped_cases': sum(bool(x['candidate_dsp_type']) for x in cases),
            'cases': cases}


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
