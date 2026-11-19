#!/usr/bin/env python3
"""Read-only ARM32 ELF RTTI/vtable inspector for spatial effect controllers.

Method addresses and literal string references are static evidence only,
not proof of a DSP signal-path entry point or native plugin support.
"""
import argparse
import hashlib
import json
import re
import sqlite3
import struct
from pathlib import Path

CONTROLLERS = {
    'AIR Delay': 'N8EvilDSPs18AIRDelayControllerE',
    'Shimmer': 'N8EvilDSPs17ShimmerControllerE',
    'Multi Chorus': 'N8EvilDSPs21MultiChorusControllerE',
}


def parse_sections(blob):
    if len(blob) < 52 or blob[:6] != b'\x7fELF\x01\x01' or struct.unpack_from('<H', blob, 18)[0] != 40:
        raise ValueError('Expected ELF32 ARM little-endian')
    shoff = struct.unpack_from('<I', blob, 32)[0]
    entsize, count, name_idx = struct.unpack_from('<HHH', blob, 46)
    if entsize < 40 or not count or name_idx >= count or shoff + count * entsize > len(blob):
        raise ValueError('Invalid section table')
    headers = [struct.unpack_from('<10I', blob, shoff + i * entsize) for i in range(count)]
    nh = headers[name_idx]
    if nh[4] + nh[5] > len(blob):
        raise ValueError('Invalid section name table')
    names = blob[nh[4]:nh[4] + nh[5]]
    result = []
    for h in headers:
        end = names.find(b'\x00', h[0]) if h[0] < len(names) else -1
        name = names[h[0]:end].decode('ascii') if end >= 0 else '?'
        if h[1] != 8 and h[4] + h[5] > len(blob):
            raise ValueError('Section extends beyond ELF')
        result.append({'name': name, 'type': h[1], 'va': h[3],
                       'off': h[4], 'size': h[5]})
    return result


def va_to_off(va, sections):
    for s in sections:
        if s['type'] != 8 and s['va'] <= va < s['va'] + s['size']:
            return s['off'] + va - s['va']
    return None


def off_to_va(off, sections):
    for s in sections:
        if s['type'] != 8 and s['off'] <= off < s['off'] + s['size']:
            return s['va'] + off - s['off']
    return None


def u32(blob, offset):
    if offset is None or offset < 0 or offset + 4 > len(blob):
        return None
    return struct.unpack_from('<I', blob, offset)[0]


def pointer_refs(blob, sections):
    out = {}
    for s in sections:
        if not s['name'].startswith('.data.rel.ro'):
            continue
        for pos in range(s['off'], s['off'] + s['size'] - 3, 4):
            out.setdefault(u32(blob, pos), []).append(pos)
    return out


def c_string_at_va(blob, sections, va):
    off = va_to_off(va, sections)
    if off is None:
        return None
    end = blob.find(b'\x00', off, min(off + 96, len(blob)))
    if end < 0 or not 2 <= end - off <= 80:
        return None
    raw = blob[off:end]
    return raw.decode('ascii') if all(32 <= ch < 127 for ch in raw) else None


def find_names_in_code(blob, sections, start, max_bytes=0x400):
    """Find candidate LDR-literal+ADD-PC links to printable rodata strings."""
    text = next(s for s in sections if s['name'] == '.text')
    end = min(start + max_bytes, text['va'] + text['size'])
    out = []
    for add_va in range(start, end, 4):
        add = u32(blob, va_to_off(add_va, sections))
        if add is None or (add & 0x0FFF0FF0) != 0x008F0000:
            continue
        reg = (add >> 12) & 15
        if (add & 15) != reg or reg == 15:
            continue
        for ldr_va in range(max(start, add_va - 48), add_va, 4):
            ldr = u32(blob, va_to_off(ldr_va, sections))
            if ldr is None or (ldr & 0xFFFFF000) != (0xE59F0000 | (reg << 12)):
                continue
            literal = u32(blob, va_to_off(ldr_va + 8 + (ldr & 0xFFF), sections))
            if literal is None:
                continue
            delta = literal - 0x100000000 if literal & 0x80000000 else literal
            target = (add_va + 8 + delta) & 0xFFFFFFFF
            section = next((s for s in sections if s['va'] <= target < s['va']+s['size']), None)
            if section is None or section['name'] != '.rodata':
                continue
            label = c_string_at_va(blob, sections, target)
            if label is not None:
                row = {'label': label, 'reference_va': add_va, 'string_va': target}
                if row not in out:
                    out.append(row)
    return out


def controller_vtables(blob, sections, refs, mangled):
    rodata = next(s for s in sections if s['name'] == '.rodata')
    pattern = re.escape(mangled.encode()) + b'\x00'
    matches = [rodata['off'] + m.start() for m in re.finditer(
        pattern, blob[rodata['off']:rodata['off'] + rodata['size']])]
    if len(matches) != 1:
        raise ValueError(f'Expected one RTTI name for {mangled}, got {len(matches)}')
    name_va = off_to_va(matches[0], sections)
    typeinfos = [off_to_va(ref-4, sections) for ref in refs.get(name_va, [])]
    text = next(s for s in sections if s['name'] == '.text')
    tables = []
    for ti in typeinfos:
        if ti is None:
            continue
        for ref in refs.get(ti, []):
            header_off = ref - 4
            raw_top, first = u32(blob, header_off), u32(blob, ref+4)
            if raw_top is None or first is None:
                continue
            top = raw_top if raw_top < 0x80000000 else raw_top - 0x100000000
            if top > 0 or top < -4096 or top % 4:
                continue
            if not text['va'] <= (first & ~1) < text['va'] + text['size']:
                continue
            methods = []
            for idx in range(128):
                pointer = u32(blob, ref+4+idx*4)
                if pointer is None or not text['va'] <= (pointer & ~1) < text['va']+text['size']:
                    break
                methods.append(pointer)
            if len(methods) >= 2:
                tables.append({'vtable_va': off_to_va(header_off, sections),
                               'typeinfo_va': ti, 'offset_to_top': top,
                               'function_va': methods})
    return sorted(tables, key=lambda x: x['offset_to_top'], reverse=True)


def inspect(blob, names=CONTROLLERS, db_path=None):
    sec = parse_sections(blob)
    refs = pointer_refs(blob, sec)
    controllers = {}
    for model, rtti in names.items():
        tables = controller_vtables(blob, sec, refs, rtti)
        controllers[model] = {
            'rtti_name': rtti,
            'vtables': [{'vtable_va': f"0x{v['vtable_va']:08X}",
                         'typeinfo_va': f"0x{v['typeinfo_va']:08X}",
                         'offset_to_top': v['offset_to_top'],
                         'virtual_functions': len(v['function_va']),
                         'function_va': [f'0x{x:08X}' for x in v['function_va']]}
                        for v in tables],
        }
    primaries = {model: [int(v, 16) for v in d['vtables'][0]['function_va']]
                 for model, d in controllers.items()
                 if d['vtables'] and d['vtables'][0]['offset_to_top'] == 0}
    common, specialized = [], []
    if len(primaries) == len(names):
        size = min(len(x) for x in primaries.values())
        for idx in range(size):
            values = [x[idx] for x in primaries.values()]
            (common if len(set(values)) == 1 else specialized).append(idx)

    comparisons = []
    if all(len(c['vtables']) >= 3 for c in controllers.values()):
        for index in range(3):
            sub = {name: d['vtables'][index]['function_va'] for name, d in controllers.items()}
            size = min(len(x) for x in sub.values())
            shared = [i for i in range(size) if len({v[i] for v in sub.values()}) == 1]
            comparisons.append({'subtable': index, 'comparable_virtual_functions': size,
                                'shared_indices': shared,
                                'specialized_indices': [i for i in range(size) if i not in shared]})

    if 26 in specialized:
        for model, functions in primaries.items():
            controllers[model]['specialized_slot_26_string_refs'] = find_names_in_code(
                blob, sec, functions[26])

    if db_path:
        path = Path(db_path)
        uri = path.resolve().as_uri() + '?mode=ro&immutable=1'
        with sqlite3.connect(uri, uri=True) as db:
            rows = db.execute('SELECT content FROM rigs').fetchall()
        keys = {model: set() for model in names}
        for (content,) in rows:
            patch = json.loads(content)['data']['Patch']['children']
            for model in names:
                for name, value in patch.items():
                    if name == model or (name.startswith(model+' ') and name[len(model)+1:].isdigit()):
                        keys[model].update(value.get('children', {}))
        for model, detail in controllers.items():
            labels = {row['label'] for row in detail.get('specialized_slot_26_string_refs', [])}
            detail['observed_rig_keys'] = sorted(keys[model])
            detail['specialized_method_labels_matching_rig_keys'] = sorted(labels & keys[model])
    return {'source_sha256': hashlib.sha256(blob).hexdigest(),
            'controllers': controllers,
            'primary_vtable_shared_indices': common,
            'primary_vtable_specialized_indices': specialized,
            'subtable_comparisons': comparisons,
            'limitations': 'Static RTTI/vtable evidence; specialized methods are not verified as audio callbacks.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil', type=Path, required=True)
    p.add_argument('--db', type=Path)
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    result = json.dumps(inspect(a.evil.read_bytes(), db_path=a.db), indent=2, ensure_ascii=False) + '\n'
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(result, encoding='utf-8')
        print('Saved', a.out)
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
