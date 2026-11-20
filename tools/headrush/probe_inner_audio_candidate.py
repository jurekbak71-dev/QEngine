#!/usr/bin/env python3
"""Read-only proof of DSPModule slot-3 tail dispatch into specialized effect code.

Identical NEON/VFP instruction sites are evidence of buffer arithmetic; they do
not establish an ALSA-to-effect runtime path or a stable processAudio ABI.
"""
import argparse
import bisect
import hashlib
import json
import mmap
import struct
from pathlib import Path

SHA='1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631'
MODELS={
 'AIR Delay': {'wrapper':0x02EA8950,'effect':0x02EB3880,'name':'N8EvilDSPs8AIRDelayE',
   'slot3':0x0099CA50,'end':0x0099E638,'flag':0x0099CA9C,'vld':0x0099D350,'vst':0x0099D35C,
   'vmul':0x0099CC30,'calls':(0x0099CB20,0x0099CB98,0x0099CC44)},
 'Shimmer': {'wrapper':0x02EA8008,'effect':0x02EB5F7C,'name':'N8EvilDSPs7ShimmerE',
   'slot3':0x00977CA8,'end':0x00978A98,'flag':0x00977CF4,'vld':0x009785B8,'vst':0x009785C4,
   'vmul':0x00977E88,'calls':(0x00977D74,0x00977DEC,0x00977E9C)},
 'Multi Chorus': {'wrapper':0x02EA8740,'effect':0x02EB45BC,'name':'N8EvilDSPs11MultiChorusE',
   'slot3':0x00991CE8,'end':0x00992C30,'flag':0x00991D34,'vld':0x00992684,'vst':0x00992690,
   'vmul':0x00991EBC,'calls':(0x00991DB8,0x00991E30,0x00991ED0)},
}
COMMON_CALLS=(0x01538A80,0x00C2A6E4,0x00C198CC)
SPECIAL_SLOTS=(0,1,3,7,32,33)
TAIL_OPCODES=(0xE5900040,0xE52DE004,0xE590C000,0xE59CE00C,
              0xE1A0C00E,0xE49DE004,0xE12FFF1C)


def parse_elf(blob):
    if len(blob)<52 or blob[:6]!=b'\x7fELF\x01\x01' or struct.unpack_from('<H',blob,18)[0]!=40:
        raise ValueError('Expected ARM ELF32 little endian')
    head=struct.unpack_from('<I',blob,32)[0]
    step,count,idx=struct.unpack_from('<HHH',blob,46)
    if step<40 or not count or idx>=count or head+step*count>len(blob):
        raise ValueError('Malformed ELF section table')
    headers=[struct.unpack_from('<10I',blob,head+i*step) for i in range(count)]
    shstr=headers[idx]
    if shstr[4]+shstr[5]>len(blob):raise ValueError('Malformed section names')
    names=blob[shstr[4]:shstr[4]+shstr[5]]
    output={}
    for h in headers:
        p=h[0];end=names.find(b'\0',p) if p<len(names) else -1
        if end<0:continue
        key=names[p:end].decode('ascii','replace')
        if h[1]!=8 and h[4]+h[5]>len(blob):raise ValueError('Section outside file')
        output[key]=(h[3],h[4],h[5],h[1])
    return output


def file_offset(sections,va):
    for address,offset,size,typ in sections.values():
        if typ!=8 and address<=va<address+size:
            if va+4>address+size:raise ValueError('Unaligned boundary word')
            return offset+va-address
    raise ValueError(f'Unmapped address 0x{va:08X}')


def word(blob,sections,va):
    return struct.unpack_from('<I',blob,file_offset(sections,va))[0]


def string_at(blob,sections,va):
    off=file_offset(sections,va)
    end=blob.find(b'\0',off,min(len(blob),off+500))
    if end<0:raise ValueError('Unterminated RTTI string')
    return blob[off:end].decode('ascii')


def exidx_entries(blob,sections):
    if '.ARM.exidx' not in sections or '.text' not in sections:
        raise ValueError('No EHABI or text section')
    va,off,size,_=sections['.ARM.exidx']
    tva,_,tsize,_=sections['.text']
    if size<16 or size%8:raise ValueError('Malformed EHABI index')
    out=[]
    for pos in range(0,size,8):
        disp=struct.unpack_from('<I',blob,off+pos)[0]&0x7fffffff
        if disp&0x40000000:disp-=0x80000000
        addr=(va+pos+disp)&0xffffffff
        if not tva<=addr<=tva+tsize or (out and addr<=out[-1]):
            raise ValueError('Invalid EHABI function entry')
        out.append(addr)
    return out


def target_bl(op,va):
    if op&0xff000000!=0xeb000000:raise ValueError('Not unconditional A32 BL')
    delta=op&0xffffff
    if delta&0x800000:delta-=0x1000000
    return (va+8+4*delta)&0xffffffff


def inspect(blob,models=MODELS,required_sha=SHA,expected_unique=SPECIAL_SLOTS,expected_callees=COMMON_CALLS):
    digest=hashlib.sha256(blob).hexdigest()
    if required_sha is not None and digest!=required_sha:raise ValueError('Source SHA-256 mismatch')
    sections=parse_elf(blob)
    tva,_,tsize,_=sections['.text']
    exidx=exidx_entries(blob,sections)
    tables={}
    results={}
    for name,model in models.items():
        effect,wrapper=model['effect'],model['wrapper']
        if word(blob,sections,effect-8)!=0:raise ValueError('Bad vtable header '+name)
        ti=word(blob,sections,effect-4)
        if string_at(blob,sections,word(blob,sections,ti+4))!=model['name']:
            raise ValueError('Effect RTTI mismatch '+name)
        ptrs=[word(blob,sections,effect+4*i) for i in range(36)]
        if any(not tva<=(p&~1)<tva+tsize for p in ptrs):
            raise ValueError('Expected 36 executable virtual method pointers')
        if tva<=word(blob,sections,effect+36*4)<tva+tsize:
            raise ValueError('Too many consecutive vtable pointers')
        if ptrs[3]!=model['slot3']:
            raise ValueError('Specialized slot3 differs')
        tables[name]=ptrs
        caller=word(blob,sections,wrapper+3*4)
        ops=tuple(word(blob,sections,caller+4*i) for i in range(len(TAIL_OPCODES)))
        if ops!=TAIL_OPCODES:
            raise ValueError('Wrapper slot3 tail-call sequence changed '+name)
        at=bisect.bisect_left(exidx,model['slot3'])
        if at>=len(exidx)-1 or exidx[at]!=model['slot3'] or exidx[at+1]!=model['end']:
            raise ValueError('Slot3 EHABI bounds differ '+name)
        expected_opcodes={model['flag']:0xE5D03B6C,model['vld']:0xF4604A8F,
                          model['vst']:0xF4400A8D,model['vmul']:0xEE277A87}
        for addr,value in expected_opcodes.items():
            if not model['slot3']<=addr<model['end']:
                raise ValueError('Instruction anchor outside function')
            if word(blob,sections,addr)!=value:
                raise ValueError('Slot3 instruction anchor changed '+name+f' 0x{addr:08X}')
        targets=[target_bl(word(blob,sections,site),site) for site in model['calls']]
        if expected_callees is not None and tuple(targets)!=tuple(expected_callees):
            raise ValueError('Slot3 common callee mismatch '+name)
        results[name]={
            'effect_vptr':f'0x{effect:08X}','wrapper_vptr':f'0x{wrapper:08X}',
            'wrapper_slot3_tail_entry':f'0x{caller:08X}',
            'inner_slot3_entry':f"0x{model['slot3']:08X}",
            'next_exidx_entry':f"0x{model['end']:08X}",
            'ehabi_bounded_bytes':model['end']-model['slot3'],
            'flag_read':f"0x{model['flag']:08X}",
            'neon_vld1':f"0x{model['vld']:08X}",
            'neon_vst1':f"0x{model['vst']:08X}",
            'vfp_vmul':f"0x{model['vmul']:08X}",
            'shared_direct_bl_callees':[f'0x{x:08X}' for x in targets],
        }
    names=list(tables)
    varying=[i for i in range(36) if len({tables[n][i] for n in names})>1]
    if expected_unique is not None and tuple(varying)!=tuple(expected_unique):
        raise ValueError('Unexpected distinct virtual method slots')
    return {'source_sha256':digest,'ehabi_entries':len(exidx),
            'methods_per_effect':36,'shared_method_slots':36-len(varying),
            'effect_specific_slots':varying,'effects':results,
            'limitations':('Static proof of wrapper tail call and specialized inner slot3 with '
                           'float and NEON operations. No verified host ALSA callback-to-slot3 '
                           'edge, exact C++ signature, or runtime user-effect loader.')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',required=True,type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    with a.evil.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        result=inspect(data)
    rendered=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if a.out:a.out.write_text(rendered,encoding='utf-8')
    else:print(rendered,end='')

if __name__=='__main__':main()
