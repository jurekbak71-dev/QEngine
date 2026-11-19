#!/usr/bin/env python3
"""Offline ARM32 factory audit for Core 5.2.0 spatial DSP modules.

Read-only. Verifies two-stage switches, constructor vptr installation and RTTI.
No firmware patch, plugin loader, audio processing, or device test is implied.
"""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

ELF_SHA256='1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631'
PRIMARY_TABLE=0x008125B4
PRIMARY_DEFAULT_CODE=0x008127E0
SECONDARY_TABLE=0x008127F0
SECONDARY_DEFAULT=0x008146C0
MODELS={
    32: ('TapeEcho', 0x00814834),
    35: ('BBDDelay', 0x00814A50),
    37: ('AIRReverb', 0x008149D8),
    38: ('ElevenReverb', 0x0081499C),
    42: ('Chorus', 0x008148E8),
    43: ('MultiChorus', 0x008148AC),
    84: ('AIRDelay', 0x00814B04),
    85: ('Shimmer', 0x00814AC8),
}

def section_map(blob):
    if len(blob)<52 or blob[:6]!=b'\x7fELF\x01\x01' or struct.unpack_from('<H',blob,18)[0]!=40:
        raise ValueError('Expected little-endian ELF32 ARM')
    shoff=struct.unpack_from('<I',blob,32)[0]
    step,total,shstr=struct.unpack_from('<HHH',blob,46)
    if step<40 or total<1 or shstr>=total or shoff+step*total>len(blob):
        raise ValueError('Invalid ELF section table')
    headers=[struct.unpack_from('<10I',blob,shoff+i*step) for i in range(total)]
    strings=headers[shstr]
    if strings[4]+strings[5]>len(blob):raise ValueError('Out-of-range section-name table')
    names=blob[strings[4]:strings[4]+strings[5]]
    result={}
    for h in headers:
        nameoff=h[0]
        if nameoff>=len(names):continue
        end=names.find(b'\0',nameoff)
        if end<0:continue
        name=names[nameoff:end].decode('ascii','replace')
        if h[1]!=8 and h[4]+h[5]>len(blob):raise ValueError('Section extends beyond ELF')
        result[name]={'va':h[3],'off':h[4],'size':h[5],'type':h[1]}
    return result

def off_for(sections,va):
    for sec in sections.values():
        if sec['type']!=8 and sec['va']<=va<sec['va']+sec['size']:
            return sec['off']+va-sec['va']
    raise ValueError('Unmapped VA 0x%08X'%va)

def u32(blob,sec,va):
    pos=off_for(sec,va)
    if pos+4>len(blob):raise ValueError('Truncated 32-bit word')
    return struct.unpack_from('<I',blob,pos)[0]

def arm_b(op,pc):
    if op&0xff000000!=0xea000000:raise ValueError('Not an unconditional A32 B')
    val=op&0xffffff
    if val&0x800000:val-=0x1000000
    return (pc+8+4*val)&0xffffffff

def read_string(blob,sec,va):
    f=off_for(sec,va)
    end=blob.find(b'\0',f,min(len(blob),f+400))
    if end<0:raise ValueError('Unterminated C++ RTTI string')
    return blob[f:end].decode('ascii')

def verify_handler(blob,sec,name,handler):
    ldr_va=handler+0x14
    add_va=handler+0x24
    insn=u32(blob,sec,ldr_va)
    if insn&0xff7ff000 not in (0xe51f3000,0xe59f3000):
        raise ValueError('Handler LDR r3 PC-relative differs')
    if u32(blob,sec,add_va)!=0xe08f3003 or u32(blob,sec,add_va+4)!=0xe2833008:
        raise ValueError('Handler vptr arithmetic differs')
    if u32(blob,sec,add_va+8)!=0xe482303c:
        raise ValueError('Handler vptr store differs')
    displacement=u32(blob,sec,ldr_va+8+(insn&4095)*(1 if insn&(1<<23) else -1))
    if displacement&0x80000000:displacement-=0x100000000
    vptr=(add_va+8+displacement+8)&0xffffffff
    off_top=struct.unpack_from('<i',blob,off_for(sec,vptr-8))[0]
    if off_top!=0:raise ValueError('Unexpected vtable offset-to-top')
    ti=u32(blob,sec,vptr-4)
    raw_name=read_string(blob,sec,u32(blob,sec,ti+4))
    if 'N8EvilDSPs9DSPModule' not in raw_name or name not in raw_name:
        raise ValueError('Module type mismatch in original RTTI: '+name)
    first=u32(blob,sec,vptr)
    text=sec['.text']
    if not (text['va']<=first<text['va']+text['size']):
        raise ValueError('vtable first method not inside .text')
    return {'module':name,'handler_va':f'0x{handler:08X}','vtable_va':f'0x{vptr:08X}',
            'typeinfo_va':f'0x{ti:08X}','rtti':raw_name,'first_virtual_va':f'0x{first:08X}'}

def analyze(blob,required_sha=ELF_SHA256,models=MODELS):
    digest=hashlib.sha256(blob).hexdigest()
    if required_sha is not None and digest!=required_sha:
        raise ValueError('Firmware SHA-256 does not match known Core 5.2.0 ELF')
    sec=section_map(blob)
    signature={0x8125a8:0xe350008a,0x8125ac:0x908ff100,
               0x8127e0:0xe240301b,0x8127e4:0xe353004f,0x8127e8:0x908ff103}
    for va,expected in signature.items():
        if u32(blob,sec,va)!=expected:raise ValueError('Unexpected factory switch opcode at '+hex(va))
    if arm_b(u32(blob,sec,0x8125b0),0x8125b0)!=PRIMARY_DEFAULT_CODE:
        raise ValueError('Primary default does not reach secondary switch')
    if arm_b(u32(blob,sec,0x8127ec),0x8127ec)!=SECONDARY_DEFAULT:
        raise ValueError('Secondary default target changed')
    primary=[arm_b(u32(blob,sec,PRIMARY_TABLE+4*i),PRIMARY_TABLE+4*i) for i in range(139)]
    secondary=[arm_b(u32(blob,sec,SECONDARY_TABLE+4*i),SECONDARY_TABLE+4*i) for i in range(80)]
    result=[]
    for index,(name,handler) in models.items():
        if not 27<=index<=106:raise ValueError('Model outside secondary selector 27..106')
        if primary[index]!=PRIMARY_DEFAULT_CODE:
            raise ValueError('Model does not enter secondary dispatch: '+name)
        if secondary[index-27]!=handler:
            raise ValueError('Model secondary target mismatch: '+name)
        row=verify_handler(blob,sec,name,handler)
        row.update({'module_index':index,'primary_target_va':f'0x{PRIMARY_DEFAULT_CODE:08X}',
                    'secondary_entry_va':f'0x{SECONDARY_TABLE+4*(index-27):08X}'})
        result.append(row)
    return {'evil_sha256':digest,'primary_entries':len(primary),'primary_default_count':primary.count(PRIMARY_DEFAULT_CODE),
            'secondary_entries':len(secondary),'secondary_default_count':secondary.count(SECONDARY_DEFAULT),
            'verified_spatial_modules':result,
            'limitation':('These are factory selector and C++ constructor evidence. '
                          'Adding a new effect may require UI model IDs, serializer compatibility, '
                          'ABI-compatible construction and DSP algorithms. No external plugin API proven.')}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',type=Path,required=True)
    p.add_argument('--output',type=Path)
    a=p.parse_args()
    with a.evil.open('rb') as file,mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as image:
        result=analyze(image)
    rendered=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if a.output:a.output.write_text(rendered,encoding='utf-8')
    else:print(rendered,end='')

if __name__=='__main__':main()
