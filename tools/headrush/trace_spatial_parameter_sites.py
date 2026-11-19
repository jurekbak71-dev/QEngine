#!/usr/bin/env python3
"""Read-only scan of ARM32 code references to full spatial parameter paths.

PC-relative LDR+ADD matches prove static code references, not a writable
control endpoint, parameter range or direct DSP algorithm access.
"""
import argparse
import json
import re
import struct
from pathlib import Path

FOCUS = ('AIR Delay', 'AIR Reverb', 'Shimmer', 'Multi Chorus',
         'AIR Flanger', 'Tape Echo', 'BBD Delay')


def sections(blob):
    if len(blob) < 52 or blob[:6] != b'\x7fELF\x01\x01':
        raise ValueError('Expected ELF32 little endian')
    shoff = struct.unpack_from('<I', blob, 32)[0]
    entsize, count, names_index = struct.unpack_from('<HHH', blob, 46)
    if entsize < 40 or not count or names_index >= count or shoff + entsize * count > len(blob):
        raise ValueError('Invalid ELF section table')
    headers = [struct.unpack_from('<10I', blob, shoff + i * entsize) for i in range(count)]
    names_h = headers[names_index]
    names = blob[names_h[4]:names_h[4] + names_h[5]]
    result = []
    for header in headers:
        offset = header[0]
        end = names.find(b'\x00', offset) if offset < len(names) else -1
        name = names[offset:end].decode('ascii', 'replace') if end >= 0 else '?'
        result.append({'name': name, 'type': header[1], 'addr': header[3],
                       'offset': header[4], 'size': header[5]})
    return result


def file_to_va(offset, section_list):
    return next((s['addr'] + offset - s['offset'] for s in section_list
                 if s['type'] != 8 and s['offset'] <= offset < s['offset'] + s['size']), None)


def va_to_file(address, section_list):
    return next((s['offset'] + address - s['addr'] for s in section_list
                 if s['type'] != 8 and s['addr'] <= address < s['addr'] + s['size']), None)


def parameter_paths(blob, section_list):
    paths = {}
    for model in FOCUS:
        prefix = ('/Engine/Patch/' + model + '/').encode()
        for match in re.finditer(re.escape(prefix) + rb'[A-Za-z0-9_-]+\x00', blob):
            va = file_to_va(match.start(), section_list)
            if va is not None:
                paths[va] = {'model': model,
                             'path': match.group()[:-1].decode('ascii'), 'string_va': va}
    return paths


def decode_branch(instruction, address):
    if (instruction & 0x0f000000) != 0x0b000000:
        return None
    offset = instruction & 0xffffff
    if offset & 0x800000:
        offset -= 0x1000000
    return (address + 8 + 4 * offset) & 0xffffffff


def sites(blob, paths):
    ss = sections(blob)
    code = next(s for s in ss if s['name'] == '.text')
    begin, end = code['offset'], code['offset'] + code['size']
    unique = {}
    for off in range(begin + 64, end - 4, 4):
        instruction = struct.unpack_from('<I', blob, off)[0]
        if (instruction & 0x0fff0ff0) != 0x008f0000:
            continue
        reg, src = (instruction >> 12) & 15, instruction & 15
        if reg != src or reg == 15:
            continue
        address = code['addr'] + off - begin
        for earlier in range(off - 4, off - 65, -4):
            ldr = struct.unpack_from('<I', blob, earlier)[0]
            if (ldr & 0xfffff000) != (0xe59f0000 | reg << 12):
                continue
            load_address = code['addr'] + earlier - begin
            literal = va_to_file(load_address + 8 + (ldr & 0xfff), ss)
            if literal is None or literal + 4 > len(blob):
                continue
            displacement = struct.unpack_from('<i', blob, literal)[0]
            target = (address + 8 + displacement) & 0xffffffff
            if target not in paths:
                continue
            next_call = None
            for nextoff in range(off + 4, min(off + 68, end), 4):
                next_address = code['addr'] + nextoff - begin
                destination = decode_branch(struct.unpack_from('<I', blob, nextoff)[0], next_address)
                if destination is not None:
                    next_call = {'call_site_va': next_address, 'call_target_va': destination}
                    break
            row = {**paths[target], 'ldr_va': load_address,
                   'add_va': address, 'next_arm_bl': next_call}
            unique[(row['path'], row['add_va'])] = row
    return sorted(unique.values(), key=lambda r: (r['model'], r['path'], r['add_va']))


def inspect(blob):
    ss = sections(blob)
    paths = parameter_paths(blob, ss)
    refs = sites(blob, paths)
    grouped = {}
    for model in FOCUS:
        group = [r for r in refs if r['model'] == model]
        grouped[model] = {
            'paths_found': sum(p['model'] == model for p in paths.values()),
            'paths_with_arm_reference': len({r['path'] for r in group}),
            'arm_references': len(group)}
    return {'paths_found': len(paths), 'arm_refs_found': len(refs),
            'by_model': grouped, 'references': refs,
            'warning': 'Static ARM LDR+ADD evidence only; BL call destination and numeric arguments are not proven to be parameter min/max/default or device API endpoints.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    rendered = json.dumps(inspect(args.evil.read_bytes()), indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    else:
        print(rendered, end='')


if __name__ == '__main__':
    main()
