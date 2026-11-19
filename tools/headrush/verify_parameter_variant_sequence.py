#!/usr/bin/env python3
"""Read-only check of two-stage typed parameter values in Core 5.2.0 Evil.

Exact static instruction matching only; no ABI, bounds, DSP replacement
or external plugin support implied.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from trace_spatial_parameter_sites import sections, va_to_file, decode_branch

LAYOUTS = {
    'byte': {
        'function': 0x014CDA18,
        'shared': {'tag_immediate': 0x014CDB3C, 'tag_store': 0x014CDB48,
                   'helper_call': 0x014CDB28},
        'value': {'load': 0x014CDB60, 'helper_call': 0x014CDB74,
                  'tag_immediate': 0x014CDB8C, 'tag_store': 0x014CDB90},
        'load_opcode': 0xE5D83000, 'tag': 4,
    },
    'float': {
        'function': 0x014CD12C,
        'shared': {'tag_immediate': 0x014CD244, 'tag_store': 0x014CD250,
                   'helper_call': 0x014CD230},
        'value': {'load': 0x014CD264, 'convert': 0x014CD278,
                  'helper_call': 0x014CD280,
                  'tag_immediate': 0x014CD298, 'tag_store': 0x014CD29C},
        'load_opcode': 0xEDD87A00, 'tag': 7,
    },
}


def word(blob, sec, address):
    offset = va_to_file(address, sec)
    if offset is None or offset + 4 > len(blob):
        return None
    return struct.unpack_from('<I', blob, offset)[0]


def inspect(blob, layouts=LAYOUTS, sec=None):
    if sec is None:
        if (len(blob) < 52 or blob[:6] != b'\x7fELF\x01\x01'
                or struct.unpack_from('<H', blob, 18)[0] != 40):
            raise ValueError('expected ARM32 little endian ELF')
        sec = sections(blob)
    result = []
    for family, desc in layouts.items():
        shared, value = desc['shared'], desc['value']
        patterns = {
            'shared_tag_5': (shared['tag_immediate'], 0xE3A02005),
            'shared_tag_store': (shared['tag_store'], 0xE5C32000),
            'input_load': (value['load'], desc['load_opcode']),
            'value_tag': (value['tag_immediate'], 0xE3A02000 | desc['tag']),
            'value_tag_store': (value['tag_store'], 0xE5C32000),
        }
        if 'convert' in value:
            patterns['float_conversion'] = (value['convert'], 0xEEF70AE7)
        tests = {name: {'address': hex(address),
                        'match': word(blob, sec, address) == expected}
                 for name, (address, expected) in patterns.items()}
        calls = {}
        for phase, address in [('shared', shared['helper_call']),
                               ('value', value['helper_call'])]:
            opcode = word(blob, sec, address)
            calls[phase] = decode_branch(opcode, address) if opcode is not None else None
        result.append({'family': family, 'function_va': hex(desc['function']),
                       'tagged_checks': tests, 'helper_targets': calls,
                       'matches': sum(x['match'] for x in tests.values()),
                       'checks': len(tests)})
    return {'sha256': hashlib.sha256(blob).hexdigest(), 'variants': result,
            'all_patterns_match': all(x['matches'] == x['checks'] for x in result),
            'caution': 'Tag 5 precedes tag 4/7. Tag semantics and object owner are not established.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil', type=Path, required=True)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    data = json.dumps(inspect(a.evil.read_bytes()), indent=2) + '\n'
    if a.output:
        a.output.write_text(data, encoding='utf-8')
    else:
        print(data, end='')


if __name__ == '__main__':
    main()
