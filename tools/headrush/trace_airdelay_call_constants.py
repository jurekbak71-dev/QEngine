#!/usr/bin/env python3
"""Read-only audit of 32-bit constants passed by AIR Delay ARM call sites.

Recovered stack arguments are not automatically defaults or parameter ranges.
"""
import argparse
import json
import struct
from pathlib import Path
from trace_spatial_parameter_sites import sections, va_to_file

TARGETS = {0x14CDA18, 0x14CD12C}


def arm_imm12(bits):
    n = bits & 255
    rotation = ((bits >> 8) & 15) * 2
    return ((n >> rotation) | (n << (32 - rotation))) & 0xffffffff if rotation else n


def movw_immediate(word):
    return ((word >> 4) & 0xf000) | (word & 0xfff)


def classify_immediate(word):
    if (word & 0xfff00000) == 0xe3a00000:
        return ('mov', (word >> 12) & 15, arm_imm12(word & 0xfff))
    if (word & 0xfff00000) == 0xe3000000:
        return ('movw', (word >> 12) & 15, movw_immediate(word))
    if (word & 0xfff00000) == 0xe3400000:
        return ('movt', (word >> 12) & 15, movw_immediate(word))
    return None


def find_argument_at_call(blob, sec, start_va, call_va):
    regs = {}
    sp0 = None
    for va in range(start_va, call_va + 4, 4):
        off = va_to_file(va, sec)
        if off is None or off + 4 > len(blob):
            raise ValueError(f'VA outside file 0x{va:x}')
        word = struct.unpack_from('<I', blob, off)[0]
        op = classify_immediate(word)
        if op:
            name, reg, imm = op
            if name == 'mov':
                regs[reg] = (imm, va)
            elif name == 'movw':
                regs[reg] = (imm, va)
            elif name == 'movt':
                previous, _ = regs.get(reg, (None, None))
                regs[reg] = (((imm << 16) | (previous & 0xffff)), va) if previous is not None else (None, va)
        elif (word & 0xffff0fff) == 0xe58d0000:
            reg = (word >> 12) & 15
            value, origin = regs.get(reg, (None, None))
            sp0 = {'value_bits': value, 'source_register': reg,
                   'source_instruction_va': origin, 'store_va': va}
        if va < call_va and (word & 0x0f000000) == 0x0b000000:
            for reg in (0, 1, 2, 3, 12):
                regs.pop(reg, None)
            sp0 = None
    return sp0


def analyze(blob, reference_report):
    sec = sections(blob)
    refs = [r for r in reference_report['references']
            if r['model'] == 'AIR Delay' and r['next_arm_bl']
            and r['next_arm_bl']['call_target_va'] in TARGETS]
    if not refs:
        raise ValueError('No AIR Delay references with known BL targets')
    start = min(r['add_va'] for r in refs) - 0x20
    rows = []
    for row in sorted(refs, key=lambda r: r['next_arm_bl']['call_site_va']):
        call = row['next_arm_bl']
        info = find_argument_at_call(blob, sec, start, call['call_site_va'])
        bits = info['value_bits'] if info else None
        decoded = struct.unpack('<f', struct.pack('<I', bits))[0] if bits is not None else None
        rows.append({'parameter_path': row['path'],
                     'call_site_va': call['call_site_va'],
                     'call_target_va': call['call_target_va'],
                     'stack_argument': info,
                     'interpreted_as_float32': decoded,
                     'limitation': 'Argument meaning and allowed parameter range are unverified.'})
    return {'analyzed': len(rows), 'rows': rows}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil', required=True, type=Path)
    p.add_argument('--references', required=True, type=Path)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    report = analyze(a.evil.read_bytes(), json.loads(a.references.read_text()))
    content = json.dumps(report, indent=2, ensure_ascii=False) + '\n'
    if a.output:
        a.output.write_text(content, encoding='utf-8')
    else:
        print(content, end='')


if __name__ == '__main__':
    main()
