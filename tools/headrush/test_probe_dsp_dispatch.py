import struct
import unittest
from unittest.mock import patch
from probe_dsp_dispatch import decode_branch, locate_dispatch, PATTERN


class DispatchTests(unittest.TestCase):
    def test_decode_branch(self):
        self.assertEqual(decode_branch(0xea000002, 0x1000), 0x1010)
        with self.assertRaises(ValueError):
            decode_branch(0xe1a00000, 0x1000)

    def test_locate_dispatch(self):
        binary = bytearray(0x800)
        struct.pack_into('<II', binary, 0x100, *PATTERN)
        struct.pack_into('<I', binary, 0x108, 0xea000000)
        for index in range(139):
            struct.pack_into('<I', binary, 0x10c + index * 4, 0xea000000)
        fake_sections = [{'name': '.text', 'addr': 0x1000,
                          'offset': 0x100, 'size': 0x500, 'type': 1}]
        with patch('probe_dsp_dispatch.sections', return_value=fake_sections):
            result = locate_dispatch(bytes(binary))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['dispatch_va'], 0x1000)
        self.assertEqual(len(result[0]['targets']), 139)
        self.assertEqual(result[0]['targets'][0], 0x1014)


if __name__ == '__main__':
    unittest.main()
