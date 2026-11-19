#!/usr/bin/env python3
"""Read-only candidate DSP module lifecycle evidence: vtable slots 20 and 21.

The observed slot20 allocation is not a confirmed audio process() callback.
"""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
from verify_spatial_factory_paths import ELF_SHA256, section_map, u32

ALLOCATOR=0x0015BAF4
MODELS={
 'AIRDelay': {'vtable':0x02EA8950,'slot20':0x0097EAB8,'slot21':0x0095EDF8,'allocation_load':0x0097EB00,'allocation_bl':0x0097EB14,'expected_allocation':4376},
 'Shimmer': {'vtable':0x02EA8008,'slot20':0x00955FF0,'slot21':0x00935C68,'allocation_load':0x0095604C,'allocation_bl':0x00956050,'expected_allocation':8272},
 'MultiChorus': {'vtable':0x02EA8740,'slot20':0x0097CD58,'slot21':0x0095E278,'allocation_load':0x0097CDA0,'allocation_bl':0x0097CDB4,'expected_allocation':3776},
}
# Thirteen instructions shared bit-for-bit by three known slot-21 methods.
SLOT21_OPCODES=(
 0xe52d4008,0xe1a04000,0xe5900040,0xe5903000,0xe5933054,
 0xe58de004,0xe12fff33,0xe3500000,0x1594304c,0xe59d4000,
 0xe28dd004,0x15d30125,0xe49df004,
)

def ror32(value,rotate):
    shift=rotate%32
    return ((value>>shift)|(value<<(32-shift)))&0xffffffff if shift else value&0xffffffff

def immediate_r0(insn):
    # MOVW r0,#imm16 (A32); or MOV r0,#rotated_imm8.
    if (insn&0xfff0f000)==0xe3000000:
        return (((insn>>16)&15)<<12)|(insn&0xfff)
    if (insn&0xfffff000)==0xe3a00000:
        return ror32(insn&0xff,2*((insn>>8)&15))
    raise ValueError('Not a supported A32 immediate assignment to r0')

def bl_target(insn,where):
    if insn&0xff000000!=0xeb000000:raise ValueError('Not an unconditional A32 BL')
    d=insn&0xffffff
    if d&0x800000:d-=0x1000000
    return (where+8+d*4)&0xffffffff

def inspect(blob,entries=MODELS,expected_sha=ELF_SHA256):
    sha=hashlib.sha256(blob).hexdigest()
    if expected_sha is not None and sha!=expected_sha:raise ValueError('Original ELF SHA-256 mismatch')
    sec=section_map(blob)
    rows=[]
    for name,ref in entries.items():
        vtable=ref['vtable'];slot20=ref['slot20'];slot21=ref['slot21']
        if u32(blob,sec,vtable+20*4)!=slot20 or u32(blob,sec,vtable+21*4)!=slot21:
            raise ValueError(f'Wrong DSPModule vtable slots for {name}')
        actual_size=immediate_r0(u32(blob,sec,ref['allocation_load']))
        if actual_size!=ref['expected_allocation']:
            raise ValueError(f'Unexpected allocation size for {name}')
        target=bl_target(u32(blob,sec,ref['allocation_bl']),ref['allocation_bl'])
        if target!=ALLOCATOR:raise ValueError(f'Unexpected allocation call for {name}')
        actual_21=tuple(u32(blob,sec,slot21+i*4) for i in range(len(SLOT21_OPCODES)))
        if actual_21!=SLOT21_OPCODES:raise ValueError(f'Slot 21 A32 body changed for {name}')
        rows.append({'module':name,'vtable_va':f'0x{vtable:08X}',
                     'slot20_va':f'0x{slot20:08X}','slot21_va':f'0x{slot21:08X}',
                     'slot20_allocation_request_bytes':actual_size,
                     'slot20_allocator_va':f'0x{target:08X}',
                     'slot21_shared_words':len(actual_21),
                     'slot21_reads_object_at_offset':'0x40',
                     'slot21_virtual_call_offset':'0x54',
                     'slot21_reads_state_byte_offset':'0x125'})
    return {'evil_sha256':sha,'modules':rows,
            'limitation':'The allocator request and shared status-like function are static; no live audio callback or plugin ABI is proven.'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evil',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    a=parser.parse_args()
    with a.evil.open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as data:
        result=inspect(data)
    text=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if a.output:a.output.write_text(text,encoding='utf-8')
    else:print(text,end='')

if __name__=='__main__':main()
