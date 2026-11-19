#!/usr/bin/env python3
"""Read-only comparison of three SESP typed-connector vtable methods.

The 0x338-byte span is the candidate instruction region; the .ARM.exidx
span also contains literal data. Matching code and call targets does not
establish a runtime audio callback or any native plugin API.
"""
import argparse
import collections
import hashlib
import json
import mmap
import struct
from pathlib import Path

from trace_spatial_connector_objects import EXPECTED_SHA256, elf_sections, read_u32
from trace_spatial_indirect_calls import parse_sections, exidx_starts, method_bounds

METHODS = {
    'ShimmerIntervalKind': {'method_va': 0x00946668, 'vtable_va': 0x02EB29F0,
                            'end_va': 0x00946A10},
    'ChorusMultiVoiceKind': {'method_va': 0x00948AF8, 'vtable_va': 0x02EB2A7C,
                             'end_va': 0x00948EA0},
    'ChorusMultiWaveformKind': {'method_va': 0x009484E0, 'vtable_va': 0x02EB2A98,
                                'end_va': 0x00948888},
}
CODE_BYTES = 0x338
LITERAL_WORDS = (0x2, 0x0)
BLX_SIGNATURE = [(0x4C, 3), (0x74, 1), (0xB8, 3), (0x17C, 3)]


def decode_arm_bl(word, address):
    if word & 0xFF000000 != 0xEB000000:
        return None
    delta = word & 0xFFFFFF
    if delta & 0x800000:
        delta -= 0x1000000
    return (address + 8 + (delta << 2)) & 0xFFFFFFFF


def reg_blx(word):
    if word & 0x0FFFFFF0 == 0x012FFF30:
        return word & 0xF
    return None


def analyze(blob, methods=METHODS, expected_sha=EXPECTED_SHA256,
            code_bytes=CODE_BYTES, expected_bl=24, blx_signature=BLX_SIGNATURE):
    sha = hashlib.sha256(blob).hexdigest()
    if expected_sha is not None and sha != expected_sha:
        raise ValueError('Firmware SHA-256 mismatch')
    if len(methods) < 2 or code_bytes % 4:
        raise ValueError('Need at least two methods and aligned instruction span')
    sec = elf_sections(blob)
    exidx = exidx_starts(blob, parse_sections(blob))
    words = {}
    pool_values = {}
    for name, entry in methods.items():
        start = entry['method_va']
        vtable = entry['vtable_va']
        if read_u32(blob, sec, vtable) != start:
            raise ValueError('Vtable method mismatch: '+name)
        begin, end = method_bounds(exidx, start)
        if end != entry['end_va'] or end-begin < code_bytes+8:
            raise ValueError('Unwind region bounds disagree: '+name)
        instructions = [read_u32(blob, sec, start+offset)
                        for offset in range(0, code_bytes, 4)]
        if tuple(read_u32(blob, sec, start+code_bytes+4*i)
                 for i in range(len(LITERAL_WORDS))) != LITERAL_WORDS:
            raise ValueError('Literal-pool boundary mismatch: '+name)
        got_blx = [(offset, reg_blx(instructions[offset//4]))
                   for offset in range(0, code_bytes, 4)
                   if reg_blx(instructions[offset//4]) is not None]
        if blx_signature is not None and got_blx != blx_signature:
            raise ValueError('BLX signature mismatch: '+name)
        words[name] = instructions
        pool_values[name] = [read_u32(blob, sec, start+offset)
                             for offset in range(code_bytes, end-start, 4)]
    names=list(methods)
    code_counts = collections.Counter()
    common_direct_calls=[]
    for i in range(code_bytes//4):
        values = [words[name][i] for name in names]
        offset=4*i
        if len(set(values)) == 1:
            if decode_arm_bl(values[0], methods[names[0]]['method_va']+offset) is not None:
                raise ValueError('Identical BL encodings imply different destinations across distinct methods')
            code_counts['identical_words'] += 1
            continue
        targets=[decode_arm_bl(word, methods[name]['method_va']+offset)
                 for name,word in zip(names,values)]
        if any(target is None for target in targets) or len(set(targets)) != 1:
            raise ValueError('Non-relocation instruction difference at +0x%X'%offset)
        code_counts['relocated_direct_bl_words']+=1
        common_direct_calls.append({'offset': f'0x{offset:03X}',
                                    'target_va': f'0x{targets[0]:08X}'})
    if expected_bl is not None and len(common_direct_calls) != expected_bl:
        raise ValueError('Unexpected number of relocated BL words')
    if len({len(v) for v in pool_values.values()}) != 1:
        raise ValueError('Different literal-pool length')
    pool_same = sum(len({pool_values[name][i] for name in names}) == 1
                    for i in range(len(pool_values[names[0]])))
    return {
        'sha256':sha,
        'verified_methods': {name:{'start_va':f"0x{entry['method_va']:08X}",
                                   'end_va':f"0x{entry['end_va']:08X}",
                                   'vtable_va':f"0x{entry['vtable_va']:08X}"}
                             for name,entry in methods.items()},
        'candidate_code_bytes':code_bytes,
        'identical_instruction_words':code_counts['identical_words'],
        'relocated_bl_instruction_words':code_counts['relocated_direct_bl_words'],
        'shared_direct_call_targets': common_direct_calls,
        'blx_register_sites': [{'offset':f'0x{o:03X}','register':f'r{r}'}
                               for o,r in (blx_signature or [])],
        'literal_pool_words_per_method':len(pool_values[names[0]]),
        'literal_pool_words_identical':pool_same,
        'literal_pool_words_different':len(pool_values[names[0]])-pool_same,
        'caution':('These are identical A32 instruction templates after BL relocation. '
                   'The EHABI region includes literal data; neither code similarity nor '
                   'the shared callees prove an audio DSP update.')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',type=Path,required=True)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    with a.evil.open('rb') as source,mmap.mmap(source.fileno(),0,access=mmap.ACCESS_READ) as blob:
        report=analyze(blob)
    result=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(result,encoding='utf-8')
    else:
        print(result,end='')

if __name__=='__main__':
    main()
