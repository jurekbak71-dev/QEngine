#!/usr/bin/env python3
"""Read-only extraction of adjacent SESP / EvilDSPs RTTI type quartets.

RTTI strings are evidence of linked C++ types, NOT of a runtime call path,
parameter bounds, or an external DSP plugin ABI.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

PATTERN = re.compile(
    rb'(N8EvilDSPs4DSPs16SespAdapterTypes[^\x00]{8,260})\x00{1,12}'
    rb'(N8EvilDSPs4DSPs17SespAdapterStereo[^\x00]{8,260})\x00{1,12}'
    rb'(N8EvilDSPs(?:[0-9]{1,3})[A-Za-z][A-Za-z0-9_]*E)\x00{1,12}'
    rb'(N8EvilDSPs(?:[0-9]{1,3})[A-Za-z][A-Za-z0-9_]*ControllerE)\x00'
)
FOCUS = ('AIRDelay', 'AIRReverb', 'MultiChorus', 'Shimmer', 'BBDDelay',
         'AIRFlanger', 'ElevenReverb', 'Chorus', 'TapeEcho')


def demangle_all(mangled):
    p = subprocess.run(['c++filt', '-t'], input='\n'.join(mangled)+'\n',
                       capture_output=True, text=True, check=True)
    return p.stdout.splitlines()


def inspect(blob):
    if len(blob) < 20 or blob[:6] != b'\x7fELF\x01\x01' or blob[18:20] != b'\x28\x00':
        raise ValueError('Expected ARM32 little-endian ELF')
    matches = list(PATTERN.finditer(blob))
    all_names = [group.decode('ascii') for match in matches for group in match.groups()]
    demangled = demangle_all(all_names) if all_names else []
    rows = []
    for i, match in enumerate(matches):
        adapter_types, adapter_stereo, effect, controller = demangled[4*i:4*i+4]
        if not (adapter_types.startswith('EvilDSPs::DSPs::SespAdapterTypes<float, SESP::Effect::')
                and adapter_stereo.startswith('EvilDSPs::DSPs::SespAdapterStereo<float, SESP::Effect::')
                and effect.startswith('EvilDSPs::') and controller == effect+'Controller'):
            continue
        algorithm = adapter_types.removeprefix('EvilDSPs::DSPs::SespAdapterTypes<float, ')
        algorithm = algorithm.removesuffix('>')
        if adapter_stereo != f'EvilDSPs::DSPs::SespAdapterStereo<float, {algorithm}>':
            continue
        rows.append({'elf_file_offset':match.start(), 'wrapper':effect,
                     'controller':controller, 'algorithm':algorithm,
                     'evidence':'adjacent matching RTTI quartet'})
    return {'sha256':hashlib.sha256(blob).hexdigest(), 'matching_quartets':len(rows),
            'focus':{f'EvilDSPs::{name}':[row for row in rows if row['wrapper']==f'EvilDSPs::{name}']
                     for name in FOCUS}, 'all':rows,
            'caveat':'RTTI linkage only. No proof of adjustable internal parameters or .so support.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',required=True,type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    report=json.dumps(inspect(a.evil.read_bytes()),indent=2,ensure_ascii=False)+'\n'
    if a.out: a.out.write_text(report,encoding='utf-8')
    else: print(report,end='')


if __name__=='__main__': main()
