import unittest
from trace_spatial_controllers import inspect


def elf(body=b''):
    return b'\x7fELF\x01\x01' + bytes(12) + b'\x28\x00' + bytes(8) + body


def quartet(controller=b'N8EvilDSPs18AIRDelayControllerE', algorithm=b'8AIRDelay'):
    return (b'N8EvilDSPs4DSPs16SespAdapterTypesIfN4SESP6Effect5Delay'
            + algorithm + b'EEE\0\0'
            + b'N8EvilDSPs4DSPs17SespAdapterStereoIfN4SESP6Effect5Delay'
            + algorithm + b'EEE\0'
            + b'N8EvilDSPs8AIRDelayE\0\0\0' + controller + b'\0')


class ControllerTraceTests(unittest.TestCase):
    def test_matching_rtti_quartet(self):
        report = inspect(elf(quartet()))
        self.assertEqual(report['matching_quartets'], 1)
        item = report['focus']['EvilDSPs::AIRDelay'][0]
        self.assertEqual(item['algorithm'], 'SESP::Effect::Delay::AIRDelay')

    def test_wrong_controller_rejected(self):
        report = inspect(elf(quartet(controller=b'N8EvilDSPs18BBDDelayControllerE')))
        self.assertEqual(report['matching_quartets'], 0)

    def test_unrelated_string_breaks_quartet(self):
        data = quartet().replace(b'EEE\0\0N8EvilDSPs4DSPs17', b'EEE\0other\0N8EvilDSPs4DSPs17')
        self.assertEqual(inspect(elf(data))['matching_quartets'], 0)

    def test_unsupported_image(self):
        with self.assertRaisesRegex(ValueError, 'ARM32'):
            inspect(b'not an elf')


if __name__ == '__main__':
    unittest.main()
