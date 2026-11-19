import struct
import unittest
from trace_airdelay_call_constants import arm_imm12, classify_immediate, find_argument_at_call


def fixture(*instructions):
    raw = bytearray(0x400)
    for i, word in enumerate(instructions):
        struct.pack_into('<I', raw, 0x100 + 4*i, word)
    sec = [{'name': '.text', 'type': 1, 'addr': 0x1000, 'offset': 0x100, 'size': 0x100}]
    return raw, sec


class CallConstantsTests(unittest.TestCase):
    def test_float_literals(self):
        self.assertEqual(arm_imm12(0xF0), 240)
        self.assertEqual(classify_immediate(0xe309399a), ('movw', 3, 0x999a))
        self.assertEqual(classify_immediate(0xe3433e99), ('movt', 3, 0x3e99))
        self.assertEqual(classify_immediate(0xe3a035fd), ('mov', 3, 0x3f400000))

    def test_inline_float_argument(self):
        blob, sec = fixture(0xe3a035fd, 0xe58d3000, 0xeb000000)
        value = find_argument_at_call(blob, sec, 0x1000, 0x1008)
        self.assertEqual(value['value_bits'], 0x3f400000)

    def test_movw_movt_float(self):
        blob, sec = fixture(0xe309399a, 0xe3433e99, 0xe58d3000, 0xeb000000)
        value = find_argument_at_call(blob, sec, 0x1000, 0x100c)
        self.assertEqual(value['value_bits'], 0x3e99999a)

    def test_previous_call_does_not_reuse_stack_argument(self):
        blob, sec = fixture(0xe3a035fd, 0xe58d3000, 0xeb000000,
                            0xe1a00000, 0xeb000000)
        self.assertIsNone(find_argument_at_call(blob, sec, 0x1000, 0x1010))

    def test_unknown_register_reports_unknown(self):
        blob, sec = fixture(0xe58d7000, 0xeb000000)
        self.assertIsNone(find_argument_at_call(blob, sec, 0x1000, 0x1004)['value_bits'])


if __name__ == '__main__':
    unittest.main()
