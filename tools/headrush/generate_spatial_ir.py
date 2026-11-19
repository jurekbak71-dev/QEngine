#!/usr/bin/env python3
"""Generate original experimental stereo impulse responses for C-Verb.

Synthetic reverb / echo, not measured physical spaces. No proprietary DSP.
Standard library only. Sample output is WAV PCM16 stereo at 48 kHz.
"""
import argparse
import math
import random
import struct
import wave
from pathlib import Path

RATE = 48000


def build_ir(style='dark_hall', rate=RATE):
    if style not in ('dark_hall', 'multitap_ambient'):
        raise ValueError('unknown IR style')
    duration = 6.0 if style == 'dark_hall' else 4.0
    n = int(rate * duration)
    rng = random.Random(20261119 if style == 'dark_hall' else 20261120)
    data = [[0.0] * n, [0.0] * n]
    if style == 'dark_hall':
        t60 = 3.8
        for ch in range(2):
            state1 = state2 = 0.0
            for i in range(int(0.052 * rate), n):
                t = i / rate
                noise = rng.uniform(-1.0, 1.0)
                state1 += 0.075 * (noise - state1)
                state2 += 0.11 * (state1 - state2)
                diffuse = min(1.0, max(0.0, (t - 0.052) / 0.22))
                data[ch][i] += 0.36 * diffuse * state2 * 10 ** (-3 * t / t60)
        reflections = [(0.037, 0.30, 0.10), (0.067, 0.22, -0.11),
                       (0.103, -0.21, 0.18), (0.139, 0.16, -0.17),
                       (0.203, -0.15, 0.12), (0.273, 0.10, -0.09),
                       (0.355, 0.07, 0.05)]
        for t, a, b in reflections:
            k = int(t * rate)
            data[0][k] += a
            data[1][min(n - 1, k + int(0.009 * rate))] += a + b
    else:
        taps = [(0.125, 0.45), (0.250, 0.32), (0.375, 0.25),
                (0.500, 0.19), (0.750, 0.14), (1.000, 0.10),
                (1.250, 0.075), (1.500, 0.055), (2.000, 0.035),
                (2.500, 0.020)]
        for j, (t, gain) in enumerate(taps):
            k = int(t * rate)
            data[j % 2][k] += gain
            data[1 - (j % 2)][min(n - 1, k + int(0.013 * rate))] += gain * 0.55
        for ch in range(2):
            state = 0.0
            for i in range(int(0.15 * rate), n):
                t = i / rate
                state += 0.04 * (rng.uniform(-1.0, 1.0) - state)
                data[ch][i] += 0.045 * state * math.exp(-2.5 * t)
    fade = int(0.25 * rate)
    for ch in range(2):
        for i in range(n - fade, n):
            data[ch][i] *= (n - 1 - i) / fade
    peak = max(abs(x) for channel in data for x in channel)
    assert peak > 0.0
    scale = 0.90 / peak
    return [[max(-1.0, min(1.0, x * scale)) for x in channel] for channel in data]


def save_wav(path, samples, rate=RATE):
    if len(samples) != 2 or len(samples[0]) != len(samples[1]):
        raise ValueError('expected stereo channels of equal length')
    with wave.open(str(path), 'wb') as out:
        out.setnchannels(2)
        out.setsampwidth(2)
        out.setframerate(rate)
        buf = bytearray()
        for left, right in zip(*samples):
            buf += struct.pack('<hh', int(left * 32767), int(right * 32767))
            if len(buf) > 1_000_000:
                out.writeframesraw(buf)
                buf.clear()
        out.writeframesraw(buf)
        out.writeframes(b'')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for style, filename in [('dark_hall', 'Core_Dark_Hall_6s.wav'),
                            ('multitap_ambient', 'Core_MultiTap_Ambient_4s.wav')]:
        dest = args.output_dir / filename
        save_wav(dest, build_ir(style))
        print(dest)


if __name__ == '__main__':
    main()
