import struct
import unittest
from verify_parameter_variant_sequence import inspect


class VariantSequenceTests(unittest.TestCase):
    def fixture(self):
        blob = bytearray(0x600)
        sec = [{'name': '.text', 'type': 1, 'addr': 0x1000,
                'offset': 0x100, 'size': 0x400}]
        desc = {'byte': {
            'function': 0x1000,
            'shared': {'tag_immediate': 0x1010,
                       'tag_store': 0x1014, 'helper_call': 0x1018},
            'value': {'load': 0x1020, 'helper_call': 0x1024,
                      'tag_immediate': 0x1028, 'tag_store': 0x102c},
            'load_opcode': 0xe5d83000, 'tag': 4}}
        instructions = {0x1010: 0xe3a02005, 0x1014: 0xe5c32000,
                        0x1018: 0xeb000000, 0x1020: 0xe5d83000,
                        0x1024: 0xeb000000, 0x1028: 0xe3a02004,
                        0x102c: 0xe5c32000}
        for address, opcode in instructions.items():
            struct.pack_into('<I', blob, 0x100 + address - 0x1000, opcode)
        return blob, sec, desc

    def test_two_tags_and_helper_calls(self):
        blob, sec, desc = self.fixture()
        result = inspect(blob, desc, sec)
        self.assertTrue(result['all_patterns_match'])
        self.assertEqual(result['variants'][0]['helper_targets'],
                         {'shared': 0x1020, 'value': 0x102c})

    def test_changed_tag_rejected(self):
        blob, sec, desc = self.fixture()
        struct.pack_into('<I', blob, 0x128, 0xe3a02007)
        self.assertFalse(inspect(blob, desc, sec)['all_patterns_match'])

    def test_unmapped_instruction_rejected(self):
        blob, sec, desc = self.fixture()
        desc['byte']['value']['tag_store'] = 0x6000
        self.assertFalse(inspect(blob, desc, sec)['all_patterns_match'])

    def test_invalid_image(self):
        with self.assertRaisesRegex(ValueError, 'ARM32'):
            inspect(b'not elf')


if __name__ == '__main__':
    unittest.main()
