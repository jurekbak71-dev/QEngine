import unittest
from inspect_core_registration import inspect


class CoreRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.elf = b'\x7fELF' + bytes([1, 1]) + bytes(12) + b'\x28\x00' + bytes(64)
        self.js = b'/Evil/API/Blocks /Evil/Engine/Patch/Chain ModuleTypes'

    def test_basic_analysis(self):
        result = inspect(self.elf, self.js)
        self.assertEqual(result['elf']['machine'], 'ARM')
        self.assertEqual(result['api_identifiers']['ModuleTypes']['remote_js_count'], 1)

    def test_non_elf_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ELF'):
            inspect(b'invalid', self.js)

    def test_wrong_architecture_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ARM'):
            inspect(self.elf[:18] + b'\x3e\x00' + self.elf[20:], self.js)

    def test_unrecognized_bundle_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Blocks API'):
            inspect(self.elf, b'different frontend')


if __name__ == '__main__':
    unittest.main()
