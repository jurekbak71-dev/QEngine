import tempfile
import unittest
import wave
from pathlib import Path
from generate_spatial_ir import build_ir, save_wav


class IRGeneratorTests(unittest.TestCase):
    def test_stereo_and_length(self):
        ir = build_ir('dark_hall', rate=1000)
        self.assertEqual(len(ir), 2)
        self.assertEqual(len(ir[0]), 6000)
        self.assertLess(max(abs(v) for ch in ir for v in ch), 1.0)

    def test_echo_and_wave_header(self):
        ir = build_ir('multitap_ambient', rate=1000)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 't.wav'
            save_wav(path, ir, rate=1000)
            with wave.open(str(path), 'rb') as f:
                self.assertEqual(f.getnchannels(), 2)
                self.assertEqual(f.getsampwidth(), 2)
                self.assertEqual(f.getnframes(), 4000)

    def test_invalid_style(self):
        with self.assertRaises(ValueError):
            build_ir('flanger')


if __name__ == '__main__':
    unittest.main()
