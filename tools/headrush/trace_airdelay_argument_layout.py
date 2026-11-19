#!/usr/bin/env python3
"""Read-only ARM32 argument-layout tracer for AIR Delay registration calls.

Recovers known constants in stack slots [sp], [sp,#4], [sp,#8].
This is partial static propagation, not proof of default/min/max values.
"""
import argparse
import json
import struct
from pathlib import Path
from trace_spatial_parameter_sites import sections, va_to_file, decode_branch
from trace_airdelay_call_constants import classify_immediate

START_VA = 0x00A11E64
END_VA = 0x00A11F84
TARGETS = {0x014CDA18, 0x014CD12C}


def literal_word(blob, section_map, va):
    offset = va_to_file(va, section_map)
    if offset is None or offset + 4 > len(blob):
        return None
    return struct.unpack_from('<I', blob, offset)[0]


def c_string(blob, section_map, va):
    offset = va_to_file(va, section_map)
    if offset is None:
        return None
    end = blob.find(b'\x00', offset, min(offset + 256, len(blob)))
    if end < 0:
        return None
    try:
        return blob[offset:end].decode('utf-8')
    except UnicodeDecodeError:
        return None


def trace(blob, start_va=START_VA, end_va=END_VA, targets=TARGETS):
    section_map = sections(blob)
    registers = {}
    stack = {}
    rows = []
    for va in range(start_va, end_va + 4, 4):
        word = literal_word(blob, section_map, va)
        if word is None:
            raise ValueError(f'Unmapped ARM instruction 0x{va:08x}')
        immediate = classify_immediate(word)
        if immediate:
            kind, register, value = immediate
            if kind == 'movt':
                lower = registers.get(register, (None, None, None))[0]
                registers[register] = (
                    ((value << 16) | (lower & 0xffff), va, 'MOVW+MOVT')
                    if lower is not None else (None, va, 'unknown lower 16 bits'))
            elif kind == 'movw':
                registers[register] = (value, va, 'MOVW')
            else:
                registers[register] = (value, va, 'MOV immediate')
        elif (word & 0xfffff000) == (0xe59f0000 | (((word >> 12) & 15) << 12)):
            register = (word >> 12) & 15
            value = literal_word(blob, section_map, va + 8 + (word & 0xfff))
            registers[register] = (value, va, 'LDR literal')
        elif ((word & 0x0fff0ff0) == 0x008f0000
              and (word & 15) == ((word >> 12) & 15)):
            register = (word >> 12) & 15
            value = registers.get(register, (None, None, None))[0]
            if value is None:
                registers[register] = (None, va, 'unknown address')
            else:
                displacement = value - 0x100000000 if value & 0x80000000 else value
                registers[register] = ((va + 8 + displacement) & 0xffffffff,
                                       va, 'PC-relative address')
        if (word & 0xffff0000) == 0xe58d0000:
            register, offset = (word >> 12) & 15, word & 0xfff
            if offset in (0, 4, 8):
                value, source, origin = registers.get(register, (None, None, 'unknown'))
                stack[offset] = {'value_bits': value, 'register': register,
                                 'source_instruction_va': source,
                                 'store_va': va, 'origin': origin}
        dest = decode_branch(word, va)
        if dest is not None:
            if dest in targets:
                slots = {str(i): stack.get(i) for i in (0, 4, 8)}
                pointer = slots['8']['value_bits'] if slots['8'] else None
                name = c_string(blob, section_map, pointer) if pointer is not None else None
                rows.append({'call_va': va, 'target_va': dest,
                             'parameter_path': name, 'stack_slots': slots})
            for register in (0, 1, 2, 3, 12, 14):
                registers.pop(register, None)
            stack.clear()
    return {'calls': len(rows), 'rows': rows,
            'warning': 'Partial static tracing only. Stack slot numbers are not proven parameter IDs, min/max, defaults or supported control API.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil', required=True, type=Path)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    content = json.dumps(trace(a.evil.read_bytes()), ensure_ascii=False, indent=2) + '\n'
    if a.output:
        a.output.write_text(content, encoding='utf-8')
    else:
        print(content, end='')


if __name__ == '__main__':
    main()
