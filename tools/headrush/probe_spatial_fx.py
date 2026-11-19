#!/usr/bin/env python3
"""Read-only ARM ELF inventory: reverb, delay and modulation evidence.

RTTI, UI strings and parameter paths are distinct evidence classes. Their
presence does not demonstrate a loadable DSP plugin interface.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

FAMILIES = {
    'reverb': {
        'AIR Reverb': 'AIRReverb', 'Eleven Reverb': 'ElevenReverb',
        'Spring Reverb': 'SpringReverb', 'Spring Pro': 'SpringPro',
        'Shimmer': 'Shimmer', 'Party Verb': 'PartyVerb',
        'Ambi Verb': None, 'C-Verb': None,
    },
    'delay': {
        'AIR Delay': 'AIRDelay', 'BBD Delay': 'BBDDelay',
        'Dyn Delay': 'DynDelay', 'Time Warp': 'WarpDelay',
        'Pitch Delay': 'PitchDelay', 'Reverse Delay': 'Reverse',
        'Tape Echo': 'TapeEcho', 'Multi Delay': None,
        'Grain Delay': None, 'Reso Delay': None,
    },
    'modulation': {
        'Chorus': 'Chorus', 'Multi Chorus': 'MultiChorus',
        'Dim Chorus': 'DimChorus', 'Flanger': 'Flanger',
        'AIR Flanger': 'AIRFlanger', 'Orange Phaser': 'OrangePhaser',
        'Tron Phaser': 'TronPhaser', 'Stone Phaser': 'StonePhaser',
        'Vibe Phaser': 'VibePhaser', 'Rotary': 'Rotary',
        'Tremolo': 'GreenTremolo', 'Vibrato': 'Vibrato',
        'Analog Flanger': None, 'Digital Flanger': None,
    },
}
RTTI_REGEX = re.compile(rb'(?<![A-Za-z0-9_])N8EvilDSPs9DSPModule[^\x00\n\r\t ]{5,440}')


def rtti_names(blob):
    names = [m.group().decode('ascii', 'replace') for m in RTTI_REGEX.finditer(blob)]
    if not names:
        return set()
    proc = subprocess.run(['c++filt', '-t'], input='\n'.join(names) + '\n',
                          capture_output=True, text=True, check=True)
    return set(re.findall(r'^EvilDSPs::DSPModule<EvilDSPs::([A-Za-z0-9_]+),',
                          proc.stdout, re.M))


def inspect(blob):
    if len(blob) < 20 or blob[:6] != b'\x7fELF\x01\x01' or blob[18:20] != b'\x28\x00':
        raise ValueError('Expected 32-bit little-endian ARM ELF')
    names = rtti_names(blob)
    groups = {}
    for family, mapping in FAMILIES.items():
        rows = []
        for label, typename in mapping.items():
            label_hits = list(re.finditer(
                rb'(?<![A-Za-z0-9/])' + re.escape((label + '/').encode()), blob))
            prefix = re.escape(('/Engine/Patch/' + label + '/').encode())
            paths = sorted({m.group().decode() for m in re.finditer(
                prefix + rb'[A-Za-z0-9_]+', blob)})
            rows.append({'label': label, 'expected_dsp_class': typename,
                         'dsp_rtti_found': bool(typename and typename in names),
                         'ui_label_found': bool(label_hits),
                         'parameter_paths': paths})
        groups[family] = rows
    return {'evil_sha256': hashlib.sha256(blob).hexdigest(),
            'all_dsp_rtti_types': len(names), 'families': groups,
            'additional_observations': {
                'reverb_file_string': b'ReverbFile\x00' in blob,
                'cverb_string': b'C-Verb' in blob,
                'module_type_selector_string': b'ModuleType%1' in blob,
            },
            'limitations': [
                'RTTI proves a compiled C++ type name, not direct .so loading.',
                'Absence of RTTI does not mean the effect is unavailable.',
                'UI labels and API paths do not establish a safe patch interface.',
            ]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil', required=True, type=Path)
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    result = inspect(args.evil.read_bytes())
    data = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.out:
        args.out.write_text(data, encoding='utf-8')
    else:
        print(data, end='')


if __name__ == '__main__':
    main()
