import unittest
from unittest.mock import patch
from probe_spatial_fx import inspect


def fake_elf(body=b''):
    return b'\x7fELF\x01\x01' + bytes(12) + b'\x28\x00' + bytes(8) + body


class SpatialFXTests(unittest.TestCase):
    def test_separates_code_ui_and_parameters(self):
        blob = fake_elf(b'C-Verb/\x00/Engine/Patch/AIR Delay/LFODepth\x00ReverbFile\x00ModuleType%1')
        with patch('probe_spatial_fx.rtti_names', return_value={'AIRDelay'}):
            result = inspect(blob)
        delay = next(x for x in result['families']['delay'] if x['label'] == 'AIR Delay')
        self.assertTrue(delay['dsp_rtti_found'])
        self.assertFalse(delay['ui_label_found'])
        self.assertEqual(delay['parameter_paths'], ['/Engine/Patch/AIR Delay/LFODepth'])
        cverb = next(x for x in result['families']['reverb'] if x['label'] == 'C-Verb')
        self.assertTrue(cverb['ui_label_found'])
        self.assertFalse(cverb['dsp_rtti_found'])
        self.assertTrue(result['additional_observations']['reverb_file_string'])

    def test_unsupported_image_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ARM ELF'):
            inspect(b'not elf')

    def test_no_rtti_does_not_imply_unavailable(self):
        with patch('probe_spatial_fx.rtti_names', return_value=set()):
            result = inspect(fake_elf(b'Grain Delay/\x00'))
        row = next(x for x in result['families']['delay'] if x['label'] == 'Grain Delay')
        self.assertTrue(row['ui_label_found'])
        self.assertFalse(row['dsp_rtti_found'])


if __name__ == '__main__':
    unittest.main()
