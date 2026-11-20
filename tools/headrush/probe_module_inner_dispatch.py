#!/usr/bin/env python3
"""Read-only scan of DSPModule wrapper -> inner vtable dispatches.

Reports verified A32 load chains, NOT verified audio processing methods.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ELF_SHA = '1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631'
VTABLES = {'AIRDelay': 0x02EA8950, 'Shimmer': 0x02EA8008, 'MultiChorus': 0x02EA8740}
SLOTS = {3:(0x40,0x0c),5:(0x40,0x14),7:(0x40,0x1c),
         10:(0x40,0x28),11:(0x40,0x2c),12:(0x40,0x30),
         13:(0x40,0x34),14:(0x40,0x38),15:(0x40,0x3c),
         16:(0x40,0x40),17:(0x40,0x44),18:(0x40,0x48),
         21:(0x40,0x54),25:(0x4c,0x60),27:(0x40,0x6c),
         28:(0x40,0x70),30:(0x4c,0x70)}


def parse(blob):
    if len(blob)<52 or blob[:6]!=b'\x7fELF\x01\x01' or struct.unpack_from('<H',blob,18)[0]!=40:
        raise ValueError('Expected ELF32 ARM little endian')
    shoff=struct.unpack_from('<I',blob,32)[0]
    size,count,index=struct.unpack_from('<HHH',blob,46)
    if size<40 or count<1 or index>=count or shoff+size*count>len(blob):
        raise ValueError('Invalid section headers')
    heads=[struct.unpack_from('<10I',blob,shoff+i*size) for i in range(count)]
    names_hdr=heads[index]
    if names_hdr[4]+names_hdr[5]>len(blob):raise ValueError('Invalid section names')
    names=blob[names_hdr[4]:names_hdr[4]+names_hdr[5]]
    sections=[]
    for h in heads:
        end=names.find(b'\x00',h[0]) if h[0]<len(names) else -1
        if end<0:continue
        if h[1]!=8 and h[4]+h[5]>len(blob):raise ValueError('Invalid section bounds')
        sections.append((names[h[0]:end].decode('ascii','replace'),h[3],h[4],h[5],h[1]))
    return sections


def at(sections, address):
    for _,va,off,size,typ in sections:
        if typ!=8 and va<=address<va+size:return off+address-va
    raise ValueError('Unmapped VA 0x%08X'%address)


def read_u32(blob,sections,address):
    off=at(sections,address)
    if off+4>len(blob):raise ValueError('Truncated word')
    return struct.unpack_from('<I',blob,off)[0]


def ldr_immediate(word):
    # A32: unconditional word LDR Rt,[Rn,#positive immediate] (no writeback).
    if (word&0xfff00000)!=0xe5900000:return None
    return ((word>>16)&15,(word>>12)&15,word&4095)


def find_chain(blob, sections, function_va, object_field, virtual_offset, limit=17):
    """Return specific 3-load chain in a short wrapper region (no semantic inference)."""
    words=[read_u32(blob,sections,function_va+4*i) for i in range(limit)]
    loads=[ldr_immediate(x) for x in words]
    for a in range(min(11,limit-2)):
        l1=loads[a]
        if not l1 or l1[0]!=0 or l1[2]!=object_field:continue
        for b in range(a+1,min(a+8,limit-1)):
            l2=loads[b]
            if not l2 or l2[0]!=l1[1] or l2[2]!=0:continue
            for c in range(b+1,min(b+5,limit)):
                l3=loads[c]
                if l3 and l3[0]==l2[1] and l3[2]==virtual_offset:
                    return {'object_load_va':f'0x{function_va+4*a:08X}',
                            'vptr_load_va':f'0x{function_va+4*b:08X}',
                            'method_load_va':f'0x{function_va+4*c:08X}',
                            'method_register':f'r{l3[1]}' }
    raise ValueError('No verified A32 pointer-load chain at 0x%08X'%function_va)


def inspect(blob,vtables=VTABLES,slots=SLOTS,expected_sha=ELF_SHA):
    sha=hashlib.sha256(blob).hexdigest()
    if expected_sha is not None and sha!=expected_sha:raise ValueError('Unexpected ELF SHA-256')
    sections=parse(blob)
    text=next((s for s in sections if s[0]=='.text'),None)
    if text is None:raise ValueError('Missing .text')
    results={}
    for name,vtable in vtables.items():
        record=[]
        for slot,(obj_field,method_field) in slots.items():
            function=read_u32(blob,sections,vtable+4*slot)
            if function%4 or not text[1]<=function<text[1]+text[3]:
                raise ValueError('Vtable slot not executable '+name+' '+str(slot))
            proof=find_chain(blob,sections,function,obj_field,method_field)
            record.append({'slot':slot,'wrapper_method_va':f'0x{function:08X}',
                           'inner_object_field':f'0x{obj_field:X}',
                           'inner_vtable_byte_offset':f'0x{method_field:X}',
                           'inner_vtable_slot':method_field//4,**proof})
        results[name]=record
    return {'sha256':sha,'verified_slots_per_model':len(slots),
            'verified_load_chains':len(slots)*len(vtables),'models':results,
            'limitations':('Only exact A32 LDR pointer chains are proven. '
                           'No runtime vtable owners, method signatures, audio block callbacks, '
                           'or user .so plugin registration are established.')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',type=Path,required=True)
    p.add_argument('--output',type=Path)
    args=p.parse_args()
    report=inspect(args.evil.read_bytes())
    result=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
    if args.output:args.output.write_text(result,encoding='utf-8')
    else:print(result,end='')


if __name__=='__main__':main()
