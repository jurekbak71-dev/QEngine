#!/usr/bin/env python3
"""Bound spatial controller method scans using ARM EHABI .ARM.exidx.

Static analysis only. A decoded unwind range is a candidate method span,
not evidence of DSP audio execution or a plugin loader.
"""
import argparse
import bisect
import collections
import hashlib
import json
import mmap
import sqlite3
import struct
from pathlib import Path

from probe_spatial_controller_vtables import parse_sections, va_to_off, find_names_in_code

MODELS = ('AIR Delay', 'Shimmer', 'Multi Chorus')
SLOTS = (25, 26)


def prel31(value, place):
    displacement = value & 0x7fffffff
    if displacement & 0x40000000:
        displacement -= 0x80000000
    return (place + displacement) & 0xffffffff


def exidx_starts(blob, sections):
    exidx = next((s for s in sections if s['name'] == '.ARM.exidx'), None)
    text = next((s for s in sections if s['name'] == '.text'), None)
    if not exidx or not text or exidx['size'] < 16 or exidx['size'] % 8:
        raise ValueError('Missing or malformed .ARM.exidx')
    starts = []
    for pos in range(0, exidx['size'], 8):
        entry_off = exidx['off'] + pos
        value = struct.unpack_from('<I', blob, entry_off)[0]
        address = prel31(value, exidx['va'] + pos)
        if not text['va'] <= address <= text['va'] + text['size']:
            raise ValueError('Unwind start outside .text')
        if starts and address <= starts[-1]:
            raise ValueError('Unsorted .ARM.exidx starts')
        starts.append(address)
    return starts


def exact_range(starts, address):
    index = bisect.bisect_left(starts, address)
    if index >= len(starts)-1 or starts[index] != address:
        raise ValueError(f'Method 0x{address:08X} is not an exact bounded exidx start')
    return address, starts[index+1]


def u32_at_va(blob, sections, address):
    off = va_to_off(address, sections)
    if off is None or off + 4 > len(blob):
        raise ValueError(f'Unmapped VA 0x{address:08X}')
    return struct.unpack_from('<I', blob, off)[0]


def direct_bl_target(word, location):
    if word & 0xff000000 != 0xeb000000:
        return None
    offset = word & 0xffffff
    if offset & 0x800000:
        offset -= 0x1000000
    return (location + 8 + offset*4) & 0xffffffff


def call_refs(blob, sections, begin, end):
    targets = collections.defaultdict(list)
    for address in range(begin, end, 4):
        dest = direct_bl_target(u32_at_va(blob, sections, address), address)
        if dest is not None:
            targets[dest].append(address)
    return [{'target_va': f'0x{target:08X}', 'count': len(locations),
             'call_sites_va': [f'0x{loc:08X}' for loc in locations]}
            for target, locations in sorted(targets.items(),
                    key=lambda pair: (-len(pair[1]), pair[0]))]


def read_factory_keys(db_path, models=MODELS):
    uri = Path(db_path).resolve().as_uri() + '?mode=ro&immutable=1'
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute('SELECT content FROM rigs').fetchall()
    result = {model: set() for model in models}
    for (content,) in rows:
        patch = json.loads(content)['data']['Patch']['children']
        for model in models:
            for key, node in patch.items():
                if key == model or (key.startswith(model+' ')
                                    and key[len(model)+1:].isdigit()):
                    result[model].update(node.get('children', {}))
    return {model: sorted(values) for model, values in result.items()}


def inspect(blob, vtable_report, db_path=None, models=MODELS):
    digest = hashlib.sha256(blob).hexdigest()
    if digest != vtable_report.get('source_sha256'):
        raise ValueError('Binary hash disagrees with vtable report')
    sections = parse_sections(blob)
    starts = exidx_starts(blob, sections)
    keys = read_factory_keys(db_path, models) if db_path else None
    result = {}
    for model in models:
        primary = vtable_report['controllers'][model]['vtables'][0]
        if primary['offset_to_top'] != 0:
            raise ValueError(f'{model} lacks primary vtable')
        vtable_va = int(primary['vtable_va'], 16)
        result[model] = {}
        for slot in SLOTS:
            declared = int(primary['function_va'][slot], 16)
            if u32_at_va(blob, sections, vtable_va+8+4*slot) != declared:
                raise ValueError(f'Vtable slot {model}[{slot}] differs from original ELF')
            begin, end = exact_range(starts, declared & ~1)
            labels = find_names_in_code(blob, sections, begin, end-begin)
            calls = call_refs(blob, sections, begin, end)
            literal_names = {r['label'] for r in labels}
            output = {
                'start_va': f'0x{begin:08X}',
                'next_exidx_va': f'0x{end:08X}',
                'bounded_bytes': end-begin,
                'vtable_pointer_verified': True,
                'literal_refs': labels,
                'direct_unconditional_arm_bl_count': sum(c['count'] for c in calls),
                'direct_bl_targets': calls,
            }
            if keys is not None:
                original = set(keys[model])
                output['factory_key_matches'] = sorted(original & literal_names)
                output['factory_keys_not_literal_in_method'] = sorted(original-literal_names)
            result[model][str(slot)] = output
    return {
        'source_sha256': digest, 'exidx_entries': len(starts),
        'methods': result,
        'caution': ('A32 BL and LDR-literal+ADD-PC references inside .ARM.exidx '
                    'ranges only. This does not prove DSP runtime parameter updates. '
                    'Non-literal or other-method fields are not excluded.'),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', type=Path, required=True)
    parser.add_argument('--vtables', type=Path, required=True)
    parser.add_argument('--db', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with args.evil.open('rb') as stream, mmap.mmap(
            stream.fileno(), 0, access=mmap.ACCESS_READ) as binary:
        report = inspect(binary, json.loads(args.vtables.read_text(encoding='utf-8')),
                         args.db)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n',
                        encoding='utf-8')
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
