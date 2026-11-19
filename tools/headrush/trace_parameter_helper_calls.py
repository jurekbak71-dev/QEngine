#!/usr/bin/env python3
"""Check direct ARM32 calls in parameter construction; read-only, offline."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

PATHS = {
 'byte_state': [(0x14CDABC,0x9F43F8,'type_key'),(0x14CDAE8,0x9F43F8,'state_key'),
                (0x14CDAFC,0x9F4DE4,'combine'),(0x14CDB28,0x69C0E0,'stage_one'),
                (0x14CDB74,0x69C0E0,'stage_two')],
 'float_value':[(0x14CD1D0,0x9F43F8,'type_key'),(0x14CD1FC,0x9F43F8,'value_key'),
                (0x14CD210,0x9F4DE4,'combine'),(0x14CD230,0x69C0E0,'stage_one'),
                (0x14CD280,0x69C0E0,'stage_two')]
}

def elf_sections(blob):
    if len(blob)<52 or blob[:6]!=b'\x7fELF\x01\x01' or struct.unpack_from('<H',blob,18)[0]!=40:
        raise ValueError('Expected ARM32 ELF')
    off=struct.unpack_from('<I',blob,32)[0]
    stride,count,_=struct.unpack_from('<HHH',blob,46)
    if stride<40 or count<1 or off+count*stride>len(blob):
        raise ValueError('Invalid section table')
    return [(x[3],x[4],x[5]) for i in range(count)
            for x in [struct.unpack_from('<10I',blob,off+i*stride)]
            if x[1]!=8 and x[4]+x[5]<=len(blob)]

def arm_bl_target(word,va):
    if word is None or word&0xff000000!=0xeb000000:
        return None
    delta=word&0xffffff
    if delta&0x800000: delta-=0x1000000
    return (va+8+4*delta)&0xffffffff

def analyze(blob, paths=PATHS):
    sections=elf_sections(blob)
    rows=[]
    for variant,items in paths.items():
        calls=[]
        for va,want,purpose in items:
            raw=next((struct.unpack_from('<I',blob,off+va-start)[0]
                      for start,off,size in sections
                      if start<=va and va+4<=start+size),None)
            actual=arm_bl_target(raw,va)
            calls.append({'role':purpose,'call_va':hex(va),'expected_target':hex(want),
                          'actual_target':hex(actual) if actual is not None else None,
                          'verified':actual==want})
        rows.append({'variant':variant,'calls':calls})
    total=sum(len(row['calls']) for row in rows)
    valid=sum(x['verified'] for row in rows for x in row['calls'])
    return {'sha256':hashlib.sha256(blob).hexdigest(),'verified':valid,'total':total,
            'all_verified':valid==total,'paths':rows,
            'caution':'Only static direct-call evidence; final DSP consumer and plugin API unverified.'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',required=True,type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    out=json.dumps(analyze(a.evil.read_bytes()),indent=2)+'\n'
    if a.out:a.out.write_text(out,encoding='utf-8')
    else:print(out,end='')

if __name__=='__main__':main()
