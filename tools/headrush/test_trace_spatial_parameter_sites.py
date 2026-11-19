import struct
import unittest
from trace_spatial_parameter_sites import decode_branch, inspect, sections


def fixture():
    raw = bytearray(0x800)
    raw[:6] = b'\x7fELF\x01\x01'
    struct.pack_into('<H', raw, 18, 40)
    struct.pack_into('<I', raw, 32, 0x600)
    struct.pack_into('<HHH', raw, 46, 40, 4, 3)
    names = b'\0.text\0.rodata\0.shstrtab\0'
    raw[0x500:0x500+len(names)] = names
    for index, offset, address, location, size in (
            (1, 1, 0x1000, 0x100, 0x200),
            (2, 7, 0x3000, 0x300, 0x100),
            (3, 15, 0x5000, 0x500, len(names))):
        struct.pack_into('<10I', raw, 0x600 + index*40,
                         offset, 1, 0, address, location, size, 0, 0, 4, 0)
    raw[0x350:0x350+len(b'/Engine/Patch/AIR Delay/LFORate\0')] = b'/Engine/Patch/AIR Delay/LFORate\0'
    struct.pack_into('<I', raw, 0x140, 0xe59f3058)
    struct.pack_into('<I', raw, 0x144, 0xe08f3003)
    struct.pack_into('<i', raw, 0x1a0, 0x3050 - 0x104c)
    struct.pack_into('<I', raw, 0x148, 0xeb000004)
    return bytes(raw)


class ParameterSiteTests(unittest.TestCase):
    def test_verified_path(self):
        report = inspect(fixture())
        self.assertEqual(report['arm_refs_found'], 1)
        ref = report['references'][0]
        self.assertEqual(ref['path'], '/Engine/Patch/AIR Delay/LFORate')
        self.assertEqual(ref['add_va'], 0x1044)
        self.assertEqual(ref['next_arm_bl']['call_target_va'], 0x1060)

    def test_wrong_literal_target_rejected(self):
        data = bytearray(fixture())
        struct.pack_into('<i', data, 0x1a0, 0x3054-0x104c)
        self.assertEqual(inspect(data)['arm_refs_found'], 0)

    def test_branch_decoder(self):
        self.assertIsNone(decode_branch(0xe1a00000, 0x1000))
        self.assertEqual(decode_branch(0xeb000000, 0x1000), 0x1008)
        self.assertEqual(decode_branch(0xebfffffe, 0x1000), 0x1000)

    def test_invalid_elf(self):
        with self.assertRaisesRegex(ValueError, 'ELF'):
            sections(b'invalid')


if __name__ == '__main__':
    unittest.main()
