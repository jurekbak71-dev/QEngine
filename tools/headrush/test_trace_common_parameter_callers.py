import struct
import unittest
from trace_common_parameter_callers import direct_arm_bl_target, scan, text_span


def elf_fixture(calls=()):
    b = bytearray(0x600)
    b[:6] = b'\x7fELF\x01\x01'
    struct.pack_into('<H', b, 18, 40)  # EM_ARM
    struct.pack_into('<I', b, 32, 0x400)
    struct.pack_into('<HHH', b, 46, 40, 3, 2)
    b[0x300:0x311] = b'\x00.text\x00.shstrtab\x00'
    struct.pack_into('<10I', b, 0x400+40, 1, 1, 0, 0x1000, 0x100, 0x40, 0, 0, 4, 0)
    struct.pack_into('<10I', b, 0x400+80, 7, 3, 0, 0, 0x300, 17, 0, 0, 1, 0)
    for va, target in calls:
        imm = ((target - (va + 8)) // 4) & 0xFFFFFF
        struct.pack_into('<I', b, 0x100 + va - 0x1000, 0xEB000000 | imm)
    return bytes(b)


class DirectARMCallTests(unittest.TestCase):
    def test_sections(self):
        self.assertEqual(text_span(elf_fixture()), (0x1000, 0x100, 0x40))

    def test_two_direct_calls(self):
        blob = elf_fixture([(0x1000, 0x1010), (0x1004, 0x1010)])
        report = scan(blob, {0x1010: 'helper'}, {0x1010: (0x1000, 0x1004)})
        self.assertEqual(report['targets'][0]['direct_arm_bl_count'], 2)
        self.assertTrue(report['targets'][0]['known_sites_matched'])

    def test_wrong_target(self):
        blob = elf_fixture([(0x1000, 0x1010)])
        report = scan(blob, {0x1014: 'not called'}, {0x1014: (0x1000,)})
        self.assertEqual(report['targets'][0]['direct_arm_bl_count'], 0)
        self.assertFalse(report['targets'][0]['known_sites_matched'])

    def test_conditional_branch_not_counted(self):
        self.assertIsNone(direct_arm_bl_target(0x1B000000, 0x1000))
        self.assertIsNone(direct_arm_bl_target(0xFA000000, 0x1000))

    def test_negative_offset(self):
        self.assertEqual(direct_arm_bl_target(0xEBFFFFFE, 0x1000), 0x1000)

    def test_bad_elf(self):
        with self.assertRaisesRegex(ValueError, 'ELF'):
            scan(b'not an elf')

    def test_invalid_section(self):
        raw = bytearray(elf_fixture())
        struct.pack_into('<I', raw, 0x400 + 40 + 20, 0x10000)
        with self.assertRaisesRegex(ValueError, 'Invalid aligned'):
            scan(raw)


if __name__ == '__main__':
    unittest.main()
