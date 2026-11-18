import struct
import unittest
from unittest.mock import patch
from probe_dsp_vtables import discover, file_to_va, sections, va_to_file


def make_fixture():
    data = bytearray(0x700)
    data[:6] = b'\x7fELF\x01\x01'
    struct.pack_into('<H', data, 18, 40)
    struct.pack_into('<I', data, 32, 0x500)
    struct.pack_into('<HHH', data, 46, 40, 5, 4)
    names = b'\0.text\0.rodata\0.data.rel.ro\0.shstrtab\0'
    data[0x400:0x400 + len(names)] = names
    def add(idx, name_off, addr, off, size):
        struct.pack_into('<10I', data, 0x500 + 40 * idx,
                         name_off, 1, 0, addr, off, size, 0, 0, 4, 0)
    add(1, 1, 0x1000, 0x100, 0x100)
    add(2, 7, 0x2000, 0x200, 0x100)
    add(3, 15, 0x3000, 0x300, 0x100)
    add(4, 28, 0x4000, 0x400, len(names))
    data[0x220:0x229] = b'FakeName\0'
    struct.pack_into('<II', data, 0x320, 0x8888, 0x2020)
    struct.pack_into('<III', data, 0x340, 0, 0x3020, 0x1010)
    return bytes(data)


class ProbeVtableTests(unittest.TestCase):
    def test_mapping(self):
        sec = sections(make_fixture())
        self.assertEqual(file_to_va(0x220, sec), 0x2020)
        self.assertEqual(va_to_file(0x3020, sec), 0x320)

    def test_rtti_vtable(self):
        with patch('probe_dsp_vtables.inspect_names',
                   return_value={'modules':[{'offset':0x220,'type':'EvilDSPs::Fake'}]}):
            report = discover(make_fixture())
        self.assertEqual(report['modules_with_typeinfo'], 1)
        self.assertEqual(report['modules_with_vtable'], 1)
        vt = report['results'][0]['typeinfo_candidates'][0]['candidate_vtables'][0]
        self.assertEqual(vt['vtable_va'], 0x3040)

    def test_bad_elf(self):
        with self.assertRaises(ValueError):
            sections(b'garbage')

    def test_false_positive_rejected(self):
        blob = bytearray(make_fixture())
        struct.pack_into('<I', blob, 0x348, 0x9000)
        with patch('probe_dsp_vtables.inspect_names',
                   return_value={'modules':[{'offset':0x220,'type':'EvilDSPs::Fake'}]}):
            report = discover(bytes(blob))
        self.assertEqual(report['modules_with_vtable'], 0)


if __name__ == '__main__':
    unittest.main()
