#!/usr/bin/env python3
"""Read-only ARM32 DSP factory incoming-edge / constructor-case verifier.

Find all *direct unconditional A32 BL* callers of the constructor-dispatch
candidate, and validate selected ID source and resulting virtual-call sites.
This does not establish a dynamic plugin registration ABI.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED_SHA = '1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631'
FACTORY_VA = 0x00812570
SWITCH_CMP_VA = 0x008125A8
JUMP_TABLE_VA = 0x008125B4
KNOWN_CALLERS = {
    0x01633488: {'selector_va':0x01633484,'selector_opcode':0xE5980044,
                 'provenance':'ldr r0,[r8,#0x44] (dynamic table value)'},
    0x016565B4: {'selector_va':0x016565AC,'selector_opcode':0xE3A0004B,
                 'provenance':'mov r0,#75'},
    0x016565F8: {'selector_va':0x016565F4,'selector_opcode':0xE3A0004B,
                 'provenance':'mov r0,#75'},
}
KNOWN_RESULT_USES = {
    0x016565B4: {'store_va':0x016565BC,'store_opcode':0xE584023C,
                 'vcall_load_va':0x016565C4,'vcall_opcode':0xE5936050,
                 'slot_offset':0x23c},
    0x016565F8: {'store_va':0x01656600,'store_opcode':0xE5840240,
                 'vcall_load_va':0x01656608,'vcall_opcode':0xE5936050,
                 'slot_offset':0x240},
}
CASE75_TARGET = 0x00812A40

def decode_bl(word, va):
    if (word & 0xFF000000) != 0xEB000000:
        return None
    d = word & 0xFFFFFF
    if d & 0x800000:
        d -= 0x1000000
    return (va + 8 + 4*d) & 0xFFFFFFFF

def decode_arm_b(word, va):
    if (word & 0xFF000000) != 0xEA000000:
        raise ValueError('Expected unconditional ARM B')
    d = word & 0xFFFFFF
    if d & 0x800000:
        d -= 0x1000000
    return (va + 8 + 4*d) & 0xFFFFFFFF

def section_ranges(blob):
    if len(blob)<52 or blob[:6]!=b'\x7fELF\x01\x01' or struct.unpack_from('<H',blob,18)[0]!=40:
        raise ValueError('Expected ARM32 little-endian ELF')
    shoff=struct.unpack_from('<I',blob,32)[0]
    stride,count,strings_idx=struct.unpack_from('<HHH',blob,46)
    if stride<40 or not count or strings_idx>=count or shoff+count*stride>len(blob):
        raise ValueError('Invalid ELF section headers')
    entries=[struct.unpack_from('<10I',blob,shoff+i*stride) for i in range(count)]
    shstr=entries[strings_idx]
    if shstr[4]+shstr[5]>len(blob):
        raise ValueError('Invalid section-name string table')
    labels=blob[shstr[4]:shstr[4]+shstr[5]]
    out={}
    for e in entries:
        idx=e[0];end=labels.find(b'\0',idx) if idx<len(labels) else -1
        if end<0:continue
        name=labels[idx:end].decode('ascii','replace')
        if e[1]!=8 and e[4]+e[5]>len(blob):
            raise ValueError('Truncated section '+name)
        out[name]=(e[3],e[4],e[5],e[1])
    if '.text' not in out:
        raise ValueError('No executable .text')
    return out

def u32_va(blob, ranges, va):
    for start,off,size,typ in ranges.values():
        if typ!=8 and start<=va and va+4<=start+size:
            return struct.unpack_from('<I',blob,off+va-start)[0]
    raise ValueError(f'Unmapped VA 0x{va:08X}')

def direct_call_sites(blob, va, off, size, target):
    if va%4 or off%4 or size%4:
        raise ValueError('Unaligned .text')
    hits=[]
    for pos in range(off,off+size,4):
        word=struct.unpack_from('<I',blob,pos)[0]
        if word & 0xFF000000 != 0xEB000000:
            continue
        site=va+pos-off
        if decode_bl(word,site)==target:
            hits.append(site)
    return hits

def analyze(blob, expected_sha=EXPECTED_SHA, factory_va=FACTORY_VA,
            expected_sites=KNOWN_CALLERS, results=KNOWN_RESULT_USES,
            case_index=75, case_target=CASE75_TARGET):
    digest=hashlib.sha256(blob).hexdigest()
    if expected_sha is not None and digest!=expected_sha:
        raise ValueError('Firmware SHA-256 mismatch')
    ranges=section_ranges(blob)
    text_va,text_off,text_size,text_type=ranges['.text']
    calls=direct_call_sites(blob,text_va,text_off,text_size,factory_va)
    if expected_sites is not None and set(calls)!=set(expected_sites):
        raise ValueError('DSP factory caller sites differ from baseline')
    records=[]
    for site in calls:
        if decode_bl(u32_va(blob,ranges,site),site)!=factory_va:
            raise ValueError('Wrong factory branch')
        record={'call_va':f'0x{site:08X}'}
        if expected_sites is not None:
            entry=expected_sites[site]
            if u32_va(blob,ranges,entry['selector_va'])!=entry['selector_opcode']:
                raise ValueError('Factory selector witness changed')
            record.update({'selector_va':f"0x{entry['selector_va']:08X}",
                           'selector_source':entry['provenance']})
        if site in results:
            item=results[site]
            if u32_va(blob,ranges,item['store_va'])!=item['store_opcode']:
                raise ValueError('Result store changed')
            if u32_va(blob,ranges,item['vcall_load_va'])!=item['vcall_opcode']:
                raise ValueError('Result vtable slot changed')
            record.update({'result_store_va':f"0x{item['store_va']:08X}",
                           'result_field_offset':hex(item['slot_offset']),
                           'virtual_slot_offset':'0x50',
                           'virtual_slot_index':20})
        records.append(record)
    if factory_va==FACTORY_VA:
        if u32_va(blob,ranges,SWITCH_CMP_VA)!=0xE350008A:
            raise ValueError('Factory selector range guard changed')
        if u32_va(blob,ranges,SWITCH_CMP_VA+4)!=0x908FF100:
            raise ValueError('Factory branch dispatch changed')
        jump=JUMP_TABLE_VA+4*case_index
        actual=decode_arm_b(u32_va(blob,ranges,jump),jump)
        if actual!=case_target:
            raise ValueError('Factory case target changed')
    else:
        jump=None;actual=None
    return {'elf_sha256':digest,'factory_va':f'0x{factory_va:08X}',
            'direct_unconditional_bl_callers':len(calls),
            'caller_sites':records,
            'case_index':case_index if jump is not None else None,
            'case_jump_va':f'0x{jump:08X}' if jump is not None else None,
            'case_branch_target_va':f'0x{actual:08X}' if actual is not None else None,
            'scope':'Only direct unconditional ARM BL; no proof of indirect callers, plugin ABI, GUI-to-DSP ID equivalence or device safety.'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',required=True,type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    report=analyze(a.evil.read_bytes())
    data=json.dumps(report,ensure_ascii=False,indent=2)+'\n'
    if a.out:a.out.write_text(data,encoding='utf-8')
    else:print(data,end='')

if __name__=='__main__':main()
