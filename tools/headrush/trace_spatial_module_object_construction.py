#!/usr/bin/env python3
"""Read-only verification of Core 5.2.0 DSPModule inner DSP and controller objects.

Proves static allocation, vptr initialization, and storage at wrapper offsets
+0x40/+0x4C. Does NOT prove runtime audio processing or external plugin ABI.
"""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

EXPECTED_SHA='1e3afa27eafc0097e867e220fb1c74af5eb1954bd590ec7bb5816f25d2464631'
ALLOCATOR=0x0015BAF4
# PCs are from the original ELF; both literal pools and construction sites are version-pinned.
MODELS={
    'AIR Delay': {
        'wrapper_vtable':0x02EA8950,'slot20':0x0097EAB8,'wrapper_reg':7,
        'inner':{'size':4376,'alloc_arg':0x0097EB00,'alloc_bl':0x0097EB14,
            'capture':0x0097EB18,'store':0x0097F080,'vptr_store':0x0097F088,
            'ldr':0x0097EBB4,'add':0x0097EC50,'increment':0x0097EC5C,
            'rtti':'N8EvilDSPs8AIRDelayE'},
        'controller':{'size':392,'alloc_arg':0x0097F06C,'alloc_bl':0x0097F08C,
            'capture':0x0097F104,'store':0x0097F1C4,'vptr_store':0x0097F164,
            'ldr':0x0097F154,'add':0x0097F15C,'increment':0x0097F160,
            'rtti':'N8EvilDSPs18AIRDelayControllerE'}},
    'Shimmer': {
        'wrapper_vtable':0x02EA8008,'slot20':0x00955FF0,'wrapper_reg':7,
        'inner':{'size':8272,'alloc_arg':0x0095604C,'alloc_bl':0x00956050,
            'capture':0x00956054,'store':0x00956E10,'vptr_store':0x00956E14,
            'ldr':0x00956DE4,'add':0x00956DFC,'increment':0x00956E04,
            'rtti':'N8EvilDSPs7ShimmerE'},
        'controller':{'size':392,'alloc_arg':0x00956DEC,'alloc_bl':0x00956E18,
            'capture':0x00956E30,'store':0x00956EF8,'vptr_store':0x00956E98,
            'ldr':0x00956E88,'add':0x00956E90,'increment':0x00956E94,
            'rtti':'N8EvilDSPs17ShimmerControllerE'}},
    'Multi Chorus': {
        'wrapper_vtable':0x02EA8740,'slot20':0x0097CD58,'wrapper_reg':6,
        'inner':{'size':3776,'alloc_arg':0x0097CDA0,'alloc_bl':0x0097CDB4,
            'capture':0x0097CDB8,'store':0x0097D034,'vptr_store':0x0097D0AC,
            'ldr':0x0097CDC4,'add':0x0097CDF8,'increment':0x0097CE00,
            'rtti':'N8EvilDSPs11MultiChorusE'},
        'controller':{'size':392,'alloc_arg':0x0097D08C,'alloc_bl':0x0097D0B0,
            'capture':0x0097D0C8,'store':0x0097D19C,'vptr_store':0x0097D13C,
            'ldr':0x0097D12C,'add':0x0097D134,'increment':0x0097D138,
            'rtti':'N8EvilDSPs21MultiChorusControllerE'}},
}


def sections(blob):
    if len(blob)<52 or blob[:6]!=b'\x7fELF\x01\x01' or struct.unpack_from('<H',blob,18)[0]!=40:
        raise ValueError('Expected ARM ELF32 little endian')
    start=struct.unpack_from('<I',blob,32)[0]
    step,count,index=struct.unpack_from('<HHH',blob,46)
    if step<40 or not count or index>=count or start+step*count>len(blob):
        raise ValueError('Broken section headers')
    heads=[struct.unpack_from('<10I',blob,start+i*step) for i in range(count)]
    string_hdr=heads[index]
    if string_hdr[4]+string_hdr[5]>len(blob):raise ValueError('Broken section names')
    raw=blob[string_hdr[4]:string_hdr[4]+string_hdr[5]]
    result=[]
    for h in heads:
        end=raw.find(b'\0',h[0]) if h[0]<len(raw) else -1
        name=raw[h[0]:end].decode('ascii','replace') if end!=-1 else '?'
        if h[1]!=8 and h[4]+h[5]>len(blob):raise ValueError('Out-of-bounds ELF section')
        result.append((name,h[3],h[4],h[5],h[1]))
    return result


def mapped_offset(sec,va):
    for _,addr,off,size,kind in sec:
        if kind!=8 and addr<=va<addr+size:return off+va-addr
    raise ValueError(f'Unmapped VA 0x{va:08X}')


def u32(blob,sec,va):
    off=mapped_offset(sec,va)
    if off+4>len(blob):raise ValueError('Truncated ELF word')
    return struct.unpack_from('<I',blob,off)[0]


def cstr(blob,sec,va):
    off=mapped_offset(sec,va)
    end=blob.find(b'\0',off,min(len(blob),off+350))
    if end<0:raise ValueError('RTTI string is not terminated')
    return blob[off:end].decode('ascii')


def arg_immediate(word):
    if (word&0xfff0f000)==0xe3000000: return ((word>>4)&0xF000)|(word&0xFFF)
    if (word&0xfffff000)==0xe3a00000:
        value=word&0xff;shift=2*((word>>8)&15)
        return (value>>shift)|(value<<(32-shift)&0xffffffff) if shift else value
    raise ValueError('Allocation argument not immediate MOV/MOVW r0')


def bl_dest(word,va):
    if word&0xff000000!=0xeb000000:raise ValueError('Allocator call is not BL')
    disp=word&0xffffff
    if disp&0x800000:disp-=0x1000000
    return (va+8+4*disp)&0xffffffff


def pc_relative_vptr(blob,sec,config,extra):
    ldr=config['ldr'];add=config['add'];inc=config['increment']
    op=u32(blob,sec,ldr)
    if (op&0xff7ff000) not in (0xe59f3000,0xe51f3000):
        raise ValueError('Unexpected PC-relative LDR r3')
    pc_lit=ldr+8+(op&0xfff)*(1 if op&(1<<23) else -1)
    delta=u32(blob,sec,pc_lit)
    if delta&0x80000000:delta-=1<<32
    if u32(blob,sec,add)!=0xe08f3003:raise ValueError('Unexpected ADD r3,pc,r3')
    if u32(blob,sec,inc)!=(0xe2833000|extra if extra==8 else 0xe283100c):
        raise ValueError('Unexpected vptr increment')
    return (add+8+delta+extra)&0xffffffff


def verify(blob,models=MODELS,expected_sha=EXPECTED_SHA):
    digest=hashlib.sha256(blob).hexdigest()
    if expected_sha is not None and digest!=expected_sha:raise ValueError('Wrong firmware SHA-256')
    sec=sections(blob)
    text=next((r for r in sec if r[0]=='.text'),None)
    if text is None:raise ValueError('No .text')
    result=[]
    for model,config in models.items():
        wrapper_vtable=config['wrapper_vtable'];method=config['slot20'];wrapper_reg=config['wrapper_reg']
        if u32(blob,sec,wrapper_vtable+4*20)!=method:
            raise ValueError('Wrapper slot20 mismatch '+model)
        obj_rows=[]
        for field_name,offset,alloc_reg in (('inner',0x40,4),('controller',0x4c,6 if wrapper_reg==7 else 7)):
            obj=config[field_name]
            amount=arg_immediate(u32(blob,sec,obj['alloc_arg']))
            if amount!=obj['size']:
                raise ValueError('Allocation size changed '+model+' '+field_name)
            if bl_dest(u32(blob,sec,obj['alloc_bl']),obj['alloc_bl'])!=ALLOCATOR:
                raise ValueError('Allocator address changed '+model+' '+field_name)
            if u32(blob,sec,obj['capture']) != (0xe1a00000 | (alloc_reg<<12)):
                raise ValueError('Allocation result capture changed '+model+' '+field_name)
            expected_store=0xe5800000 | (wrapper_reg<<16) | (alloc_reg<<12) | offset
            if u32(blob,sec,obj['store'])!=expected_store:
                raise ValueError('Wrapper inner pointer store changed '+model+' '+field_name)
            vptr=pc_relative_vptr(blob,sec,obj,8 if field_name=='inner' else 12)
            register=3 if field_name=='inner' else 1
            expected_vptr_store=0xe5800000 | (alloc_reg<<16) | (register<<12)
            if u32(blob,sec,obj['vptr_store'])!=expected_vptr_store:
                raise ValueError('Inner object vptr store changed '+model+' '+field_name)
            if u32(blob,sec,vptr-8)!=0:raise ValueError('Unexpected RTTI offset-to-top')
            ti=u32(blob,sec,vptr-4)
            name=cstr(blob,sec,u32(blob,sec,ti+4))
            if name!=obj['rtti']:
                raise ValueError('Wrong RTTI for '+model+' '+field_name)
            first=u32(blob,sec,vptr)
            if not text[1]<=first<text[1]+text[3]:raise ValueError('First virtual method outside .text')
            obj_rows.append({'role':field_name,'wrapper_offset':f'0x{offset:X}',
                'allocated_bytes':amount,'allocator_va':f'0x{ALLOCATOR:08X}',
                'wrapper_store_va':f"0x{obj['store']:08X}",
                'vptr_store_va':f"0x{obj['vptr_store']:08X}",
                'vtable_va':f'0x{vptr:08X}','typeinfo_va':f'0x{ti:08X}',
                'rtti_name':name,'first_virtual_method_va':f'0x{first:08X}'})
        result.append({'effect':model,'wrapper_slot20_va':f'0x{method:08X}',
                        'objects':obj_rows})
    return {'evil_sha256':digest,'verified_effects':len(result),
        'verified_objects':2*len(result),'effects':result,
        'limitations':('Static ELF proof: allocation, vptr RTTI and wrapper stores. '
                       'No runtime callback ABI, signal processing, automatic .so loader or physical Core test verified.')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',required=True,type=Path)
    p.add_argument('--out',type=Path)
    args=p.parse_args()
    with args.evil.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        report=verify(data)
    result=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
    if args.out:args.out.write_text(result,encoding='utf-8')
    else:print(result,end='')

if __name__=='__main__':main()
