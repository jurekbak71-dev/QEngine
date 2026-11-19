#!/usr/bin/env python3
"""Verify construction, RTTI, registration and vtable identity of SESP connectors.

Read-only static analysis of original HeadRush Core 5.2.0 ARM32 Evil.
Object registration is NOT proof of runtime DSP audio updates.
"""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

EXPECTED_SHA256 = '1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631'
REGISTRATION_HELPER = 0x007ED7E4
CONNECTORS = {
    'ShimmerIntervalKind': {
        'mangled': 'N8EvilDSPs11Controllers13DSPController24DspPropertyConnectorImplI20StringListTranslatorSt7_Mem_fnIMS3_FivEES4_IMS3_FviEEN4SESP6Effect6Reverb19ShimmerIntervalKindEEE',
        'vtable_va': 0x02EB29F0,
        'constructor': (0x0092BA28, 0x0092BA30, 0x0092BA34, 0x0092BA38, 0xE8850108),
        'registration': (0x0092BA78, 0x0092BA80, 0xE5805000),
        'fastpath': (0x0092BA84, 0xE5953000, 0x0092BA88, 0x0092BA8C, 0x0092BA90, 0x0092BA94),
    },
    'ChorusMultiVoiceKind': {
        'mangled': 'N8EvilDSPs11Controllers13DSPController24DspPropertyConnectorImplI20StringListTranslatorSt7_Mem_fnIMS3_FivEES4_IMS3_FviEEN4SESP6Effect10Modulation20ChorusMultiVoiceKindEEE',
        'vtable_va': 0x02EB2A7C,
        'constructor': (0x009269E8, 0x009269F0, 0x009269F4, 0x009269F8, 0xE8880208),
        'registration': (0x00926A3C, 0x00926A44, 0xE5808000),
        'fastpath': (0x00926A48, 0xE5983000, 0x00926A4C, 0x00926A50, 0x00926A54, 0x00926A58),
    },
    'ChorusMultiWaveformKind': {
        'mangled': 'N8EvilDSPs11Controllers13DSPController24DspPropertyConnectorImplI20StringListTranslatorSt7_Mem_fnIMS3_FivEES4_IMS3_FviEEN4SESP6Effect10Modulation23ChorusMultiWaveformKindEEE',
        'vtable_va': 0x02EB2A98,
        'constructor': (0x00926C3C, 0x00926C44, 0x00926C48, 0x00926C4C, 0xE8850088),
        'registration': (0x00926C8C, 0x00926C94, 0xE5805000),
        'fastpath': (0x00926C98, 0xE5953000, 0x00926C9C, 0x00926CA0, 0x00926CA4, 0x00926CA8),
    },
}

def elf_sections(blob):
    if len(blob) < 52 or blob[:6] != b'\x7fELF\x01\x01' or struct.unpack_from('<H', blob, 18)[0] != 40:
        raise ValueError('Expected ARM32 little-endian ELF')
    shoff = struct.unpack_from('<I', blob, 32)[0]
    size, count, name_idx = struct.unpack_from('<HHH', blob, 46)
    if size < 40 or count == 0 or name_idx >= count or shoff + size*count > len(blob):
        raise ValueError('Invalid ELF section headers')
    heads = [struct.unpack_from('<10I', blob, shoff+i*size) for i in range(count)]
    strings = heads[name_idx]
    if strings[4]+strings[5] > len(blob):
        raise ValueError('Invalid section name table')
    table = blob[strings[4]:strings[4]+strings[5]]
    results = []
    for h in heads:
        end = table.find(b'\x00', h[0]) if h[0] < len(table) else -1
        name = table[h[0]:end].decode('ascii','replace') if end >= 0 else '?'
        if h[1] != 8 and h[4]+h[5] > len(blob):
            raise ValueError('ELF section extends beyond file')
        results.append((name, h[3], h[4], h[5], h[1]))
    return results

def offset_of(va, sections):
    for name, address, off, size, typ in sections:
        if typ != 8 and address <= va < address + size:
            return off+va-address
    raise ValueError('Unmapped virtual address 0x%08X' % va)

def read_u32(blob, sec, va):
    off=offset_of(va, sec)
    if off+4 > len(blob):
        raise ValueError('Truncated word')
    return struct.unpack_from('<I', blob, off)[0]

def read_i32(blob, sec, va):
    return struct.unpack('<i', struct.pack('<I', read_u32(blob,sec,va)))[0]

def pc_literal_plus_add(blob, sec, ldr_va, add_va, reg):
    ldr = read_u32(blob,sec,ldr_va)
    if (ldr & 0xFFFFF000) not in (0xE59F0000 | (reg<<12), 0xE51F0000 | (reg<<12)):
        raise ValueError('Bad PC-relative LDR at 0x%08X' % ldr_va)
    add = read_u32(blob,sec,add_va)
    if add != (0xE08F0000 | (reg<<12) | reg):
        raise ValueError('Bad ADD PC at 0x%08X' % add_va)
    add_direction = 1 if ldr & (1<<23) else -1
    pool_va = ldr_va + 8 + add_direction*(ldr & 0xFFF)
    delta = read_i32(blob,sec,pool_va)
    return (add_va + 8 + delta) & 0xFFFFFFFF, pool_va

def decode_bl(blob,sec,va):
    op=read_u32(blob,sec,va)
    if op & 0xFF000000 != 0xEB000000:
        raise ValueError('Not unconditional ARM BL at 0x%08X'%va)
    d=op & 0xFFFFFF
    if d & 0x800000: d-=0x1000000
    return (va + 8 + 4*d)&0xffffffff

def cstr(blob, sec, va):
    off = offset_of(va,sec)
    end=blob.find(b'\x00',off,min(off+512,len(blob)))
    if end < 0:
        raise ValueError('Unterminated RTTI name')
    return blob[off:end].decode('ascii')

def verify(blob, configs=CONNECTORS, expected_sha256=EXPECTED_SHA256):
    sha=hashlib.sha256(blob).hexdigest()
    if expected_sha256 is not None and sha != expected_sha256:
        raise ValueError('Firmware SHA-256 mismatch')
    sec=elf_sections(blob)
    result=[]
    for label,item in configs.items():
        vtable=item['vtable_va']
        if read_u32(blob,sec,vtable-8) != 0:
            raise ValueError('Unexpected vtable offset_to_top for '+label)
        typeinfo=read_u32(blob,sec,vtable-4)
        rtti_name=cstr(blob,sec,read_u32(blob,sec,typeinfo+4))
        if rtti_name != item['mangled']:
            raise ValueError('Unexpected RTTI name for '+label)
        first_method=read_u32(blob,sec,vtable)
        constructor_ldr, constructor_add, add8_va, store_va, expected_store=item['constructor']
        base,pool_vptr=pc_literal_plus_add(blob,sec,constructor_ldr,constructor_add,3)
        if read_u32(blob,sec,add8_va)!=0xE2833008 or (base+8)&0xffffffff!=vtable:
            raise ValueError('Constructor does not construct expected vptr for '+label)
        if read_u32(blob,sec,store_va)!=expected_store:
            raise ValueError('Constructor does not store expected object vptr for '+label)
        registration_call,registration_store,expected_str=item['registration']
        if decode_bl(blob,sec,registration_call)!=REGISTRATION_HELPER:
            raise ValueError('Unexpected registration helper target for '+label)
        if read_u32(blob,sec,registration_store)!=expected_str:
            raise ValueError('Registration does not store expected connector pointer for '+label)
        object_load,expected_object_load,cmp_ldr,deref,cmp_add,cmp_va=item['fastpath']
        if read_u32(blob,sec,object_load)!=expected_object_load:
            raise ValueError('Unexpected object load for '+label)
        if read_u32(blob,sec,deref)!=0xE5933000 or read_u32(blob,sec,cmp_va)!=0xE1530002:
            raise ValueError('Unexpected first-virtual-method comparison for '+label)
        cmp_value,pool_cmp=pc_literal_plus_add(blob,sec,cmp_ldr,cmp_add,2)
        if cmp_value!=first_method:
            raise ValueError('Fast-path method pointer does not match vtable for '+label)
        result.append({'connector':label,'typeinfo_va':f'0x{typeinfo:08X}',
                       'rtti_name':rtti_name,'vtable_va':f'0x{vtable:08X}',
                       'first_virtual_method_va':f'0x{first_method:08X}',
                       'construct_vptr_va':f'0x{(base+8)&0xffffffff:08X}',
                       'constructor_store_va':f'0x{store_va:08X}',
                       'registration_helper_va':f'0x{REGISTRATION_HELPER:08X}',
                       'registration_store_va':f'0x{registration_store:08X}',
                       'fastpath_compared_first_method_va':f'0x{cmp_value:08X}',
                       'compare_va':f'0x{cmp_va:08X}',
                       'literal_pools_va':[f'0x{pool_vptr:08X}',f'0x{pool_cmp:08X}']})
    return {'evil_sha256':sha,'verified_connector_links':len(result),
            'results':result,
            'limitations':('Static instruction and RTTI verification. This shows vptr installation, '
                           'storage in a helper-returned slot, and matching first-method comparisons. '
                           'The helper owner, runtime target identity, and actual DSP signal-path are unverified.')}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',type=Path,required=True)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    with a.evil.open('rb') as source,mmap.mmap(source.fileno(),0,access=mmap.ACCESS_READ) as blob:
        result=verify(blob)
    rendered=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if a.out:
        a.out.write_text(rendered,encoding='utf-8')
    else:
        print(rendered,end='')

if __name__ == '__main__':
    main()
