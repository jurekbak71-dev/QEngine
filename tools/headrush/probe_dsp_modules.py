#!/usr/bin/env python3
"""Read-only extraction of EvilDSPs::DSPModule RTTI names from an ELF image.

Requires Python 3 and c++filt (binutils); does not execute vendor code.
RTTI is evidence of compiled types, not an interface for loading .so plugins.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

PATTERN = re.compile(rb'(?<![A-Za-z0-9_])N8EvilDSPs9DSPModule[^\x00\n\r\t ]{5,440}')


def inspect(data: bytes):
    if data[:4] != b'\x7fELF' or len(data) < 20:
        raise ValueError('Not an ELF image')
    if data[4] != 1 or data[5] != 1 or data[18:20] != b'\x28\x00':
        raise ValueError('Not a 32-bit, little-endian ARM ELF image')
    entries = []
    for hit in PATTERN.finditer(data):
        mangled = hit.group().decode('ascii', 'replace')
        demangled = subprocess.run(['c++filt', '-t', mangled], check=True,
                                  capture_output=True, text=True).stdout.strip()
        if not demangled.startswith('EvilDSPs::DSPModule<'):
            continue
        parts = [x.strip() for x in demangled[len('EvilDSPs::DSPModule<'):-1].split(',')]
        if len(parts) != 3 or not parts[0].startswith('EvilDSPs::'):
            continue
        entries.append({'offset': hit.start(), 'type': parts[0],
                        'controller': parts[1], 'serializer': parts[2],
                        'mangled': mangled})
    return {'sha256': hashlib.sha256(data).hexdigest(),
            'module_count': len(entries), 'modules': entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect(args.evil.read_bytes())
    output = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(output, encoding='utf-8')
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
