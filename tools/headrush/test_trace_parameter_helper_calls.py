import struct
import unittest
from trace_parameter_helper_calls import analyze, arm_bl_target

def elf():
    raw=bytearray(0x500)
    raw[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',raw,18,40)
    struct.pack_into('<I',raw,32,0x300)
    struct.pack_into('<HHH',raw,46,40,2,0)
    struct.pack_into('<10I',raw,0x328,0,1,0,0x1000,0x100,0x100,0,0,4,0)
    return raw

class HelperCallsTests(unittest.TestCase):
    def test_real_branch(self):
        d=elf()
        struct.pack_into('<I',d,0x110,0xeb000002)
        self.assertTrue(analyze(d,{'mock':[(0x1010,0x1020,'helper')]})['all_verified'])
    def test_mutated_branch(self):
        d=elf()
        struct.pack_into('<I',d,0x110,0xeb000002)
        self.assertFalse(analyze(d,{'mock':[(0x1010,0x1024,'helper')]})['all_verified'])
    def test_non_branch(self):
        self.assertIsNone(arm_bl_target(0xe1a00000,0x1000))
    def test_backwards_branch(self):
        self.assertEqual(arm_bl_target(0xebfffffe,0x1000),0x1000)
    def test_bad_image(self):
        with self.assertRaisesRegex(ValueError,'ARM32'):analyze(b'bad')

if __name__=='__main__':unittest.main()
