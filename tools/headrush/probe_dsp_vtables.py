#!/usr/bin/env python3
"""Read-only RTTI/typeinfo/vtable candidate inventory in HeadRush ARM32 Evil ELF."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from probe_dsp_modules import inspect as inspect_names


def sections(blob):
    if blob[:4] != b'\x7fELF' or blob[4:6] != b'\x01\x01' or struct.unpack_from('<H', blob, 18)[0] != 40:
        raise ValueError('Expected ARM32 little endian ELF')
    shoff = struct.unpack_from('<I', blob, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', blob, 46)
    if shentsize < 40 or not shnum or shoff + shentsize * shnum > len(blob):
        raise ValueError('Invalid ELF section table')
    headers = [struct.unpack_from('<10I', blob, shoff + i * shentsize) for i in range(shnum)]
    if shstrndx >= shnum:
        raise ValueError('Invalid section string table')
    name_header = headers[shstrndx]
    names = blob[name_header[4]:name_header[4] + name_header[5]]
    output = []
    for h in headers:
        off = h[0]
        name = names[off:names.find(b'\x00', off)].decode('ascii', 'replace') if off < len(names) else '?'
        output.append({'name': name, 'addr': h[3], 'offset': h[4],
                       'size': h[5], 'type': h[1]})
    return output


def file_to_va(pos, sec):
    for s in sec:
        if s['type'] != 8 and s['offset'] <= pos < s['offset'] + s['size']:
            return pos - s['offset'] + s['addr']
    return None


def va_to_file(addr, sec):
    for s in sec:
        if s['type'] != 8 and s['addr'] <= addr < s['addr'] + s['size']:
            return addr - s['addr'] + s['offset']
    return None


def discover(blob):
    sec = sections(blob)
    module_names = inspect_names(blob)['modules']
    code = next(s for s in sec if s['name'] == '.text')
    pointer_sections = [s for s in sec if s['name'].startswith('.data.rel.ro')]
    pointers = {}
    for s in pointer_sections:
        for off in range(s['offset'], s['offset'] + s['size'] - 3, 4):
            value = struct.unpack_from('<I', blob, off)[0]
            pointers.setdefault(value, []).append(off)

    results = []
    for m in module_names:
        rtti_name_va = file_to_va(m['offset'], sec)
        typeinfos = []
        for name_ref in pointers.get(rtti_name_va, []):
            if name_ref < 4:
                continue
            ti_va = file_to_va(name_ref - 4, sec)
            tables = []
            for ti_ref in pointers.get(ti_va, []):
                if ti_ref < 4 or ti_ref + 8 > len(blob):
                    continue
                offset_to_top = struct.unpack_from('<i', blob, ti_ref - 4)[0]
                first_func = struct.unpack_from('<I', blob, ti_ref + 4)[0]
                if offset_to_top == 0 and code['addr'] <= (first_func & ~1) < code['addr'] + code['size']:
                    tables.append({'vtable_file_offset': ti_ref - 4,
                                   'vtable_va': file_to_va(ti_ref - 4, sec),
                                   'first_virtual_function_va': first_func})
            typeinfos.append({'typeinfo_va': ti_va, 'typeinfo_file_offset': name_ref - 4,
                              'candidate_vtables': tables})
        results.append({'type': m['type'], 'rtti_name_file_offset': m['offset'],
                        'rtti_name_va': rtti_name_va, 'typeinfo_candidates': typeinfos})
    return {'sha256': hashlib.sha256(blob).hexdigest(),
            'modules': len(results),
            'modules_with_typeinfo': sum(bool(m['typeinfo_candidates']) for m in results),
            'modules_with_vtable': sum(any(t['candidate_vtables'] for t in m['typeinfo_candidates']) for m in results),
            'results': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = discover(args.evil.read_bytes())
    output = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(output, encoding='utf-8')
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
