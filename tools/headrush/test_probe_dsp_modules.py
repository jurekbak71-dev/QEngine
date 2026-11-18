import unittest
from probe_dsp_modules import inspect


class ProbeDSPModuleTests(unittest.TestCase):
    def setUp(self):
        self.head = b'\x7fELF' + bytes([1, 1]) + bytes(12) + b'\x28\x00' + bytes(64)

    def test_rtti(self):
        binary = (self.head +
                  b'\x00N8EvilDSPs9DSPModuleINS_7OctFuzzENS_17OctFuzzControllerEN4Evil13Serialization13DSPSerializerEEE\x00')
        result = inspect(binary)
        self.assertEqual(result['module_count'], 1)
        self.assertEqual(result['modules'][0]['type'], 'EvilDSPs::OctFuzz')

    def test_invalid_image(self):
        with self.assertRaisesRegex(ValueError, 'ELF'):
            inspect(b'wrong')

    def test_wrong_arch(self):
        with self.assertRaisesRegex(ValueError, 'ARM'):
            inspect(self.head[:18] + b'\x3e\x00' + self.head[20:])


if __name__ == '__main__':
    unittest.main()
