import struct
import unittest
from probe_dsp_vtables import sections
from test_probe_dsp_vtables import make_fixture
from verify_vtable_code_refs import arm_pc_literal_vtable_reference


class ArmCodeRefTests(unittest.TestCase):
    def test_pc_relative_reference(self):
        blob = bytearray(make_fixture())
        struct.pack_into('<I', blob, 0x110, 0xe59f3050)
        struct.pack_into('<I', blob, 0x118, 0xe08f3003)
        struct.pack_into('<i', blob, 0x168, 0x3040 - 0x1020)
        self.assertTrue(arm_pc_literal_vtable_reference(bytes(blob), 0x1010, 0x3040, sections(blob)))
        self.assertFalse(arm_pc_literal_vtable_reference(bytes(blob), 0x1010, 0x3070, sections(blob)))

    def test_out_of_range_rejected(self):
        blob = make_fixture()
        self.assertFalse(arm_pc_literal_vtable_reference(blob, 0x999999, 0x3040, sections(blob)))


if __name__ == '__main__':
    unittest.main()
