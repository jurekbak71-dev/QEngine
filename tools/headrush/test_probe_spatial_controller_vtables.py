"""Synthetic tests for read-only ARM32 controller-vtable inspector."""
import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from probe_spatial_controller_vtables import (
    parse_sections, pointer_refs, controller_vtables, inspect,
    find_names_in_code, c_string_at_va, va_to_off,
)

RTTI = 'N8EvilDSPs17ShimmerControllerE'


def fixture():
    blob = bytearray(0x1000)
    blob[:6] = b'\x7fELF\x01\x01'
    struct.pack_into('<H', blob, 18, 40)
    struct.pack_into('<I', blob, 32, 0xD00)
    struct.pack_into('<HHH', blob, 46, 40, 6, 5)
    names = b'\0.text\0.rodata\0.data.rel.ro.local\0.data.rel.ro\0.shstrtab\0'
    blob[0xC00:0xC00+len(names)] = names
    for idx, name, typ, va, off, size in [
        (1, b'.text', 1, 0x1000, 0x100, 0x200),
        (2, b'.rodata', 1, 0x3000, 0x400, 0x200),
        (3, b'.data.rel.ro.local', 1, 0x5000, 0x700, 0x300),
        (4, b'.data.rel.ro', 1, 0x6000, 0xA00, 0x200),
        (5, b'.shstrtab', 3, 0, 0xC00, len(names)),
    ]:
        struct.pack_into('<10I', blob, 0xD00+40*idx,
                         names.index(name), typ, 0, va, off, size, 0, 0, 4, 0)
    key = RTTI.encode() + b'\0'
    blob[0x420:0x420+len(key)] = key
    struct.pack_into('<II', blob, 0xA20, 0xAAAABBBB, 0x3020)
    struct.pack_into('<IIII', blob, 0x740, 0, 0x6020, 0x1100, 0x1104)
    struct.pack_into('<IIII', blob, 0x760, 0xFFFFFFD4, 0x6020, 0x1108, 0x110C)
    struct.pack_into('<IIII', blob, 0x780, 0xFFFFFF84, 0x6020, 0x1110, 0x1114)
    blob[0x480:0x484] = b'Mix\0'
    struct.pack_into('<I', blob, 0x200, 0xE59F2004)
    struct.pack_into('<I', blob, 0x204, 0xE08F2002)
    struct.pack_into('<i', blob, 0x20C, 0x3080 - 0x110C)
    return blob


class ControllerVTableTests(unittest.TestCase):
    def test_three_subobject_tables(self):
        blob = fixture()
        sec = parse_sections(blob)
        tables = controller_vtables(blob, sec, pointer_refs(blob, sec), RTTI)
        self.assertEqual([t['offset_to_top'] for t in tables], [0, -44, -124])
        self.assertEqual(tables[0]['function_va'][:2], [0x1100, 0x1104])

    def test_rtti_not_present(self):
        blob = fixture()
        sec = parse_sections(blob)
        with self.assertRaisesRegex(ValueError, 'RTTI name'):
            controller_vtables(blob, sec, pointer_refs(blob, sec),
                               'N8EvilDSPs14FakeControllerE')

    def test_incorrect_typeinfo_rejected(self):
        blob = fixture()
        struct.pack_into('<I', blob, 0x744, 0xDEADBEEF)
        sec = parse_sections(blob)
        result = controller_vtables(blob, sec, pointer_refs(blob, sec), RTTI)
        self.assertEqual([x['offset_to_top'] for x in result], [-44, -124])

    def test_non_code_vtable_pointer_rejected(self):
        blob = fixture()
        struct.pack_into('<I', blob, 0x748, 0x3000)
        sec = parse_sections(blob)
        result = controller_vtables(blob, sec, pointer_refs(blob, sec), RTTI)
        self.assertEqual([x['offset_to_top'] for x in result], [-44, -124])

    def test_literal_string_reference(self):
        blob = fixture()
        refs = find_names_in_code(blob, parse_sections(blob), 0x1100, 16)
        self.assertEqual([x['label'] for x in refs], ['Mix'])

    def test_corrupt_literal_does_not_match(self):
        blob = fixture()
        struct.pack_into('<i', blob, 0x20C, 0x3090 - 0x110C)
        self.assertEqual(find_names_in_code(blob, parse_sections(blob), 0x1100, 16), [])

    def test_invalid_elf(self):
        with self.assertRaisesRegex(ValueError, 'ELF32'):
            parse_sections(b'junk')

    def test_out_of_bounds_section_rejected(self):
        blob = fixture()
        struct.pack_into('<I', blob, 0xD00+40*2+20, 0x8000)
        with self.assertRaisesRegex(ValueError, 'beyond ELF'):
            parse_sections(blob)

    def test_full_report_and_factory_cross_reference(self):
        blob = fixture()
        inner = {'data': {'Patch': {'children': {
            'Shimmer': {'children': {'Mix': {'type': 0, 'value': 25}}}
        }}}}
        with tempfile.TemporaryDirectory() as tmp:
            dbpath = Path(tmp) / 'rigs.db'
            with sqlite3.connect(dbpath) as sql:
                sql.execute('create table rigs(content text)')
                sql.execute('insert into rigs values(?)', (json.dumps(inner),))
            report = inspect(blob, names={'Shimmer': RTTI}, db_path=dbpath)
            self.assertEqual(report['controllers']['Shimmer']['observed_rig_keys'], ['Mix'])
            self.assertEqual(report['controllers']['Shimmer']['vtables'][0]['virtual_functions'], 2)


if __name__ == '__main__':
    unittest.main()
