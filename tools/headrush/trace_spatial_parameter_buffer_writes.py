#!/usr/bin/env python3
"""Cross-check ARM32 connector byte-buffer writes and upstream field setter.

Read-only, version-pinned inspection. A buffer write and dirty marker are not
proof that the receiver is an active audio DSP algorithm.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from trace_spatial_connector_objects import EXPECTED_SHA256, elf_sections, read_u32, decode_bl
from compare_spatial_connector_methods import METHODS

# Offsets relative to the first virtual method of each connector type.
METHOD_WORDS = {
    0x010: 0xE5900004,  # LDR r0, [r0, #4] : object retained by connector
    0x030: 0xE1A05001,  # MOV r5, r1: second argument
    0x040: 0xE5903000,  # LDR r3, [r0]: vptr
    0x048: 0xE5933020,  # LDR r3, [r3, #32]: vfunc index 8
    0x04C: 0xE12FFF33,  # BLX r3
    0x060: 0xE5948018,  # LDR r8, [r4, #24]: entry index
    0x078: 0xE5D53B64,  # LDRB r3, [r5, #0xB64]
    0x07C: 0xE5952B8C,  # LDR r2, [r5, #0xB8C]
    0x088: 0xE7923188,  # LDR r3, [r2, r8, LSL #3]
    0x08C: 0xE0828188,  # ADD r8, r2, r8, LSL #3
    0x0E8: 0xE5983004,  # LDR r3, [r8, #4]
    0x0F8: 0xE5D31000,  # LDRB r1, [r3]
    0x0FC: 0xE5D30001,  # LDRB r0, [r3, #1]
    0x100: 0xE1500001,  # CMP r0, r1
    0x104: 0x01570001,  # CMPEQ r7, r1
    0x108: 0x13A01001,  # MOVNE r1, #1
    0x10C: 0x11C320B0,  # STRHNE r2, [r3]
    0x110: 0x15C31002,  # STRBNE r1, [r3, #2]
    0x114: 0xE3A03001,  # MOV r3, #1
    0x118: 0xE5C53B6C,  # STRB r3, [r5, #0xB6C]
    0x1AC: 0xE5983004,  # LDR r3, [r8, #4]
    0x1B0: 0xE3A02001,  # MOV r2, #1
    0x1B4: 0xE5C37000,  # STRB r7, [r3]
    0x1B8: 0xE5C32002,  # STRB r2, [r3, #2]
    0x1BC: 0xEAFFFFD6,  # B back to common continuation +0x11C
}

# Upstream producer of the controller +0xB8C slot and a separate clear path.
SETTER_WORDS = {
    0x7A68A0: 0xE5913000,  # vptr of an input object
    0x7A68A4: 0xE5955534,  # control object from owner +0x534
    0x7A68A8: 0xE1A00001,
    0x7A68AC: 0xE5933020,
    0x7A68B0: 0xE12FFF33,
    0x7A68B8: 0xE59D6008,
    0x7A68BC: 0xE5850B8C,  # controller +0xB8C = helper result
}
CLEAR_WORDS = {
    0x7D208C: 0xE3A03000,
    0x7D2098: 0xE5803B8C,  # controller +0xB8C = 0
}
HELPER_WORDS = {
    0xCB2E88: 0xE5943000,
    0xCB2E94: 0xE59330BC,  # virtual function index 47
    0xCB2E98: 0xE12FFF33,
    0xCB2EBC: 0xE5934018,  # data selection from offset +24
    0xCB2EEC: 0xE1A00004,  # return selected value in r0
}
CONSTRUCTOR_INDEX_SITES = {
    'ShimmerIntervalKind': {
        'source_load': (0x92BA10, 0xE59D8020),
        'refcount_call': 0x92BA24,
        'object_stm': (0x92BA38, 0xE8850108),
        'index_set': (0x92BA50, 0xE3A03000),
        'index_store': (0x92BA58, 0xE5853018),
        'index': 0,
    },
    'ChorusMultiVoiceKind': {
        'source_load': (0x9269D0, 0xE59D9028),
        'refcount_call': 0x9269E4,
        'object_stm': (0x9269F8, 0xE8880208),
        'index_set': (0x926A10, 0xE3A03004),
        'index_store': (0x926A18, 0xE5883018),
        'index': 4,
    },
    'ChorusMultiWaveformKind': {
        'source_load': (0x926C24, 0xE59D7028),
        'refcount_call': 0x926C38,
        'object_stm': (0x926C4C, 0xE8850088),
        'index_set': (0x926C64, 0xE3A03007),
        'index_store': (0x926C6C, 0xE5853018),
        'index': 7,
    },
}
REFERENCE_COUNT_HELPER = 0xCD2BD4

SETTER_HELPER_CALL = 0x7A68B4
SETTER_HELPER_TARGET = 0xCB2E48


def static_evidence(blob, methods=METHODS, expected_sha=EXPECTED_SHA256):
    digest = hashlib.sha256(blob).hexdigest()
    if expected_sha is not None and digest != expected_sha:
        raise ValueError('Unexpected firmware SHA-256')
    sections = elf_sections(blob)
    for name, expected in [('setter', SETTER_WORDS), ('clear', CLEAR_WORDS),
                           ('getter_helper', HELPER_WORDS)]:
        for va, opcode in expected.items():
            actual = read_u32(blob, sections, va)
            if actual != opcode:
                raise ValueError(f'{name}: different instruction at 0x{va:08X}')
    if decode_bl(blob, sections, SETTER_HELPER_CALL) != SETTER_HELPER_TARGET:
        raise ValueError('Setter helper target changed')
    rows = []
    for name, method in methods.items():
        constructor = CONSTRUCTOR_INDEX_SITES.get(name)
        if constructor is None:
            raise ValueError(f'Unknown constructor layout: {name}')
        for field in ('source_load', 'object_stm', 'index_set', 'index_store'):
            va, opcode = constructor[field]
            if read_u32(blob,sections,va) != opcode:
                raise ValueError(f'{name}: altered constructor {field} at 0x{va:08X}')
        if decode_bl(blob,sections,constructor['refcount_call']) != REFERENCE_COUNT_HELPER:
            raise ValueError(f'{name}: altered reference-count helper')
        start = method['method_va']
        if read_u32(blob, sections, method['vtable_va']) != start:
            raise ValueError(f'First vtable method differs for {name}')
        for off, opcode in METHOD_WORDS.items():
            if read_u32(blob, sections, start+off) != opcode:
                raise ValueError(f'{name}: unexpected A32 opcode at +0x{off:03X}')
        rows.append({'connector':name,
                     'method_va':f'0x{start:08X}',
                     'object_pointer_offset':4,
                     'object_vfunc_index':8,
                     'controller_arg_register':'r5 (copied from r1)',
                     'controller_buffer_field_offset':'0xB8C',
                     'connector_index_field_offset':'0x18',
                     'constructor_confirmed_index':constructor['index'],
                     'confirmed_entry_offset_bytes':constructor['index']*8,
                     'constructor_object_store_va':f"0x{constructor['object_stm'][0]:08X}",
                     'reference_count_helper_va':f'0x{REFERENCE_COUNT_HELPER:08X}',
                     'entry_stride_bytes':8,
                     'entry_value_pointer_offset':4,
                     'byte_writes':[f'0x{start+off:08X}' for off in (0x10C,0x110,0x1B4,0x1B8)],
                     'flag_offset':'0xB6C',
                     'flag_write_va':f'0x{start+0x118:08X}',
                     'verified_instruction_checks':len(METHOD_WORDS)})
    return {'evil_sha256':digest,
            'verified_connectors':len(rows),
            'method_opcode_checks':len(rows)*len(METHOD_WORDS),
            'constructor_opcode_checks':len(rows)*5,
            'upstream_opcode_checks':len(SETTER_WORDS)+len(CLEAR_WORDS)+len(HELPER_WORDS)+1,
            'upstream_setter':{'entry_va':'0x007A68A0','helper_target_va':'0x00CB2E48',
                               'setter_va':'0x007A68BC','owner_field_offset':'0x534',
                               'stored_controller_field_offset':'0xB8C'},
            'clear_slot_va':'0x007D2098',
            'helper_virtual_method_index':47,
            'connectors':rows,
            'limitations':('A32 static instruction checks only. Actual object identity, '
                           'buffer lifetime, scheduling and any SESP audio DSP consumer '
                           'are not identified. The helper may have other return paths.')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=json.dumps(static_evidence(args.evil.read_bytes()),indent=2,ensure_ascii=False)+'\n'
    if args.output:args.output.write_text(result,encoding='utf-8')
    else:print(result,end='')

if __name__=='__main__': main()
