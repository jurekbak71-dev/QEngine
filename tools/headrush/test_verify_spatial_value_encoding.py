import struct
import unittest
from verify_spatial_value_encoding import check_instruction_set, verify


class ValueEncodingTests(unittest.TestCase):
    def setUp(self):
        self.sections = [{'type': 1, 'addr': 0x1000, 'offset': 0x100, 'size': 0x400}]
        self.blob = bytearray(0x600)
        self.mapping = {
            'byte': {'callee_va': 0x1000, 'source_kind': 'byte', 'observed_type_tag': 4,
                     'instructions': {0x1010: (0xE5D83000, 'ldrb r3,[r8]'),
                                      0x1014: (0xE3A02004, 'mov r2,#4')}},
            'float': {'callee_va': 0x1000, 'source_kind': 'float32 converted to float64',
                      'observed_type_tag': 7,
                      'instructions': {0x1020: (0xEDD87A00, 'vldr s15,[r8]'),
                                       0x1024: (0xEEF70AE7, 'vcvt.f64.f32 d16,s15'),
                                       0x1028: (0xE3A02007, 'mov r2,#7')}},
        }
        for meta in self.mapping.values():
            for va, (opcode, _) in meta['instructions'].items():
                struct.pack_into('<I', self.blob, 0x100 + va - 0x1000, opcode)

    def test_known_instruction_patterns(self):
        items = check_instruction_set(self.blob, self.sections, self.mapping)
        self.assertEqual(sum(x['instruction_matches'] for x in items), 5)
        self.assertEqual(sum(x['instruction_count'] for x in items), 5)

    def test_mutated_opcode_detected(self):
        struct.pack_into('<I', self.blob, 0x128, 0)
        items = check_instruction_set(self.blob, self.sections, self.mapping)
        self.assertEqual(sum(x['instruction_matches'] for x in items), 4)

    def test_unmapped_location_rejected(self):
        self.mapping['byte']['instructions'][0x5000] = (0xE5D83000, 'not mapped')
        items = check_instruction_set(self.blob, self.sections, self.mapping)
        self.assertEqual(items[0]['instruction_matches'], 2)
        self.assertEqual(items[0]['instruction_count'], 3)

    def test_reject_non_arm_elf(self):
        with self.assertRaisesRegex(ValueError, 'ARM32'):
            verify(b'not elf')


if __name__ == '__main__':
    unittest.main()
