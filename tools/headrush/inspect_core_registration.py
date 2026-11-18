#!/usr/bin/env python3
"""Offline, read-only inventory of HeadRush Core firmware registration clues.

Accepts an extracted Evil ELF and Remote Editor JavaScript bundle. It never
executes firmware, contacts a device, or modifies the supplied inputs.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

KNOWN_API = (
    'ModuleTypes', 'BlockSelectorCategories', 'BlockSelectorCategoriesForDisplay',
    'categoryBlocks', 'categoryBlocksFlags', 'categoryOfBlock',
    'setModuleTypeInternal', 'serializeBlock', 'deserializeBlock',
)
KNOWN_PATHS = ('/Evil/API/Blocks', '/Evil/Engine/Patch/Chain')
DYNAMIC_SYMBOLS = ('dlopen', 'dlsym', 'dlclose')


def occurrences(data: bytes, word: str):
    needle = word.encode('utf-8')
    at = 0
    found = []
    while (at := data.find(needle, at)) >= 0:
        found.append(at)
        at += len(needle)
    return found


def inspect(elf: bytes, bundle: bytes):
    if elf[:4] != b'\x7fELF':
        raise ValueError('Evil is not an ELF file')
    if not (elf[4] == 1 and elf[5] == 1 and elf[18:20] == b'\x28\x00'):
        raise ValueError('Expected little-endian, 32-bit ARM ELF')
    content = bundle.decode('utf-8')
    if '/Evil/API/Blocks' not in content:
        raise ValueError('Bundle does not expose expected Blocks API')
    result = {
        'evil_sha256': hashlib.sha256(elf).hexdigest(),
        'remote_js_sha256': hashlib.sha256(bundle).hexdigest(),
        'elf': {'machine': 'ARM', 'bits': 32, 'little_endian': True},
        'api_identifiers': {
            k: {'evil_offsets': occurrences(elf, k),
                'remote_js_count': content.count(k)}
            for k in KNOWN_API
        },
        'api_paths': {
            p: {'evil_offsets': occurrences(elf, p),
                'remote_js_count': content.count(p)}
            for p in KNOWN_PATHS
        },
        'dynamic_loader_strings': {
            k: occurrences(elf, k) for k in DYNAMIC_SYMBOLS
        },
        'plugin_error_context': [],
        'interpretation': [
            'Remote Editor selects model IDs exposed by the on-device API; not installation of DSP code.',
            'Textual references to dlopen/dlsym alone do not establish DSP loading.',
            'Plugin-error context must be classified before attribution to audio.'
        ],
    }
    for off in occurrences(elf, 'Failed loading plugin %s at %s'):
        context = elf[max(0, off-160):off+80]
        strings = [x.decode('utf-8', 'replace')
                   for x in re.findall(rb'[\x20-\x7e]{5,}', context)]
        result['plugin_error_context'].append({
            'offset': off, 'nearby_strings': strings
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', required=True, type=Path)
    parser.add_argument('--remote-js', required=True, type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    data = inspect(args.evil.read_bytes(), args.remote_js.read_bytes())
    report = json.dumps(data, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(report + '\n', encoding='utf-8')
    else:
        print(report)


if __name__ == '__main__':
    main()
