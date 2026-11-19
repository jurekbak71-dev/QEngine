#!/usr/bin/env python3
"""Enumerate *direct ARM-state BL* call sites of parameter-data helpers.

This is a read-only structural inventory of one ELF, not a DSP execution
trace. BLX, PLT indirection, Thumb code, virtual dispatch and data references
are outside this scan. Do not infer a native plugin ABI from call counts.
"""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

TARGETS = {
    0x0069C0E0: 'shared_tagged_value_helper',
    0x009F43F8: 'shared_string_key_helper',
    0x009F4DE4: 'shared_structure_combiner',
    0x014CDA18: 'AIRDelay_byte_path',
    0x014CD12C: 'AIRDelay_float_path',
}
KNOWN_SITES = {
    0x0069C0E0: (0x014CDB28, 0x014CDB74, 0x014CD230, 0x014CD280),
    0x009F43F8: (0x014CDABC, 0x014CDAE8, 0x014CD1D0, 0x014CD1FC),
    0x009F4DE4: (0x014CDAFC, 0x014CD210),
}


def text_span(blob):
    if len(blob) < 52 or blob[:6] != b'\x7fELF\x01\x01':
        raise ValueError('Expected little-endian ELF32')
    if struct.unpack_from('<H', blob, 18)[0] != 40:
        raise ValueError('Expected ARM machine type')
    shoff = struct.unpack_from('<I', blob, 32)[0]
    entsize, count, name_index = struct.unpack_from('<HHH', blob, 46)
    if entsize < 40 or not count or name_index >= count or shoff + entsize * count > len(blob):
        raise ValueError('Invalid section headers')
    headers = [struct.unpack_from('<10I', blob, shoff + i * entsize) for i in range(count)]
    labels = headers[name_index]
    if labels[4] + labels[5] > len(blob):
        raise ValueError('Invalid section name table')
    names = blob[labels[4]:labels[4] + labels[5]]
    for header in headers:
        idx = header[0]
        if idx >= len(names):
            continue
        end = names.find(b'\x00', idx)
        if end < 0:
            continue
        if names[idx:end] == b'.text':
            address, offset, size = header[3], header[4], header[5]
            if (header[1] == 8 or offset + size > len(blob) or
                    address % 4 or offset % 4 or size % 4):
                raise ValueError('Invalid aligned .text section')
            return address, offset, size
    raise ValueError('No .text section')


def direct_arm_bl_target(word, call_va):
    # Only unconditional A32 BL, not BLX or conditionally executed branches.
    if (word & 0xFF000000) != 0xEB000000:
        return None
    displacement = word & 0x00FFFFFF
    if displacement & 0x00800000:
        displacement -= 0x01000000
    return (call_va + 8 + 4 * displacement) & 0xFFFFFFFF


def scan(blob, targets=TARGETS, known=KNOWN_SITES):
    base, offset, size = text_span(blob)
    gathered = {address: [] for address in targets}
    for file_off in range(offset, offset + size, 4):
        instruction = struct.unpack_from('<I', blob, file_off)[0]
        if instruction & 0xFF000000 != 0xEB000000:
            continue
        call_va = base + file_off - offset
        destination = direct_arm_bl_target(instruction, call_va)
        if destination in gathered:
            gathered[destination].append(call_va)
    rows = []
    for target, label in targets.items():
        sites = gathered[target]
        expected = known.get(target, ())
        rows.append({'target_va': f'0x{target:08X}', 'label': label,
                     'direct_arm_bl_count': len(sites),
                     'call_sites_va': [f'0x{site:08X}' for site in sites],
                     'known_sites_matched': all(site in sites for site in expected),
                     'known_sites_missing': [f'0x{s:08X}' for s in expected if s not in sites]})
    return {'text_va': f'0x{base:08X}', 'text_size': size,
            'scanned_instruction_words': size // 4, 'targets': rows,
            'scope': 'Unconditional ARM32 BL only; indirect/virtual calls excluded; no runtime DSP proof'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    with args.evil.open('rb') as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as binary:
            result = scan(binary)
    # Checksum deliberately calculated by streaming, to avoid a second huge copy.
    sha256 = hashlib.sha256()
    with args.evil.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha256.update(block)
    result['evil_sha256'] = sha256.hexdigest()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('Saved', args.out)


if __name__ == '__main__':
    main()
