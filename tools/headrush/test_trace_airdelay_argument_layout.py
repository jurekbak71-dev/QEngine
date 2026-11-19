import struct
import unittest
from unittest.mock import patch
from trace_airdelay_argument_layout import trace


class AIRDelayArgumentLayoutTests(unittest.TestCase):
    def fixture(self):
        blob = bytearray(0x500)
        name = b'/Engine/Patch/AIR Delay/LFORate\x00'
        blob[0x300:0x300 + len(name)] = name
        instructions = [
            0xe3a07020, 0xe59f3034, 0xe08f3003, 0xe58d7004,
            0xe58d3008, 0xe3a0a000, 0xe58da000, 0xeb000000,
        ]
        for index, word in enumerate(instructions):
            struct.pack_into('<I', blob, 0x100 + 4 * index, word)
        struct.pack_into('<i', blob, 0x140, 0x3000 - 0x1010)
        sections = [
            {'name': '.text', 'type': 1, 'addr': 0x1000,
             'offset': 0x100, 'size': 0x100},
            {'name': '.rodata', 'type': 1, 'addr': 0x3000,
             'offset': 0x300, 'size': 0x100},
        ]
        return bytes(blob), sections

    def test_named_stack_arguments(self):
        blob, sections = self.fixture()
        with patch('trace_airdelay_argument_layout.sections', return_value=sections):
            result = trace(blob, 0x1000, 0x101c, {0x1024})
        self.assertEqual(result['calls'], 1)
        entry = result['rows'][0]
        self.assertEqual(entry['parameter_path'], '/Engine/Patch/AIR Delay/LFORate')
        self.assertEqual(entry['stack_slots']['0']['value_bits'], 0)
        self.assertEqual(entry['stack_slots']['4']['value_bits'], 32)
        self.assertEqual(entry['stack_slots']['8']['value_bits'], 0x3000)

    def test_wrong_call_target(self):
        blob, sections = self.fixture()
        with patch('trace_airdelay_argument_layout.sections', return_value=sections):
            result = trace(blob, 0x1000, 0x101c, {0x1000})
        self.assertEqual(result['calls'], 0)

    def test_unmapped_instruction(self):
        blob, sections = self.fixture()
        with patch('trace_airdelay_argument_layout.sections', return_value=sections):
            with self.assertRaisesRegex(ValueError, 'Unmapped'):
                trace(blob, 0x5000, 0x5000, {0x1024})


if __name__ == '__main__':
    unittest.main()
