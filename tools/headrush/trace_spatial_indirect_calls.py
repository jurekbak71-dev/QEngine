#!/usr/bin/env python3
"""Read-only A32 indirect-call classification in selected Core 5.2.0 controller methods.

Only exact original ELF, RTTI-vtable pointers, and .ARM.exidx-bounded methods
are scanned. Neither a DSP callback nor native plugin ABI is implied.
"""
import argparse
import bisect
import collections
import hashlib
import json
import mmap
import struct
from pathlib import Path

MODELS = ('AIR Delay', 'Shimmer', 'Multi Chorus')
SLOTS = (25, 26)


def parse_sections(blob):
    if len(blob) < 52 or blob[:6] != b'\x7fELF\x01\x01' or struct.unpack_from('<H', blob, 18)[0] != 40:
        raise ValueError('Expected little-endian ELF32 ARM')
    shoff = struct.unpack_from('<I', blob, 32)[0]
    size, count, name_idx = struct.unpack_from('<HHH', blob, 46)
    if size < 40 or not count or name_idx >= count or shoff + size * count > len(blob):
        raise ValueError('Invalid ELF section table')
    headers = [struct.unpack_from('<10I', blob, shoff + i*size) for i in range(count)]
    strings = headers[name_idx]
    if strings[4] + strings[5] > len(blob):
        raise ValueError('Invalid section string table')
    names = blob[strings[4]:strings[4]+strings[5]]
    sections = []
    for h in headers:
        off = h[0]
        end = names.find(b'\x00', off) if off < len(names) else -1
        label = names[off:end].decode('ascii','replace') if end>=0 else '?'
        if h[1] != 8 and h[4]+h[5] > len(blob):
            raise ValueError('Invalid section size')
        sections.append({'name': label, 'type': h[1], 'va': h[3], 'off': h[4], 'size':h[5]})
    return sections


def va_off(sections, address):
    for sec in sections:
        if sec['type'] != 8 and sec['va'] <= address < sec['va']+sec['size']:
            return sec['off']+address-sec['va']
    return None


def word_va(blob, sections, address):
    off = va_off(sections, address)
    if off is None or off+4 > len(blob):
        raise ValueError('Unmapped A32 instruction or pointer 0x%08X'%address)
    return struct.unpack_from('<I',blob,off)[0]


def prel31(word, address):
    diff = word & 0x7fffffff
    if diff & 0x40000000:
        diff -= 0x80000000
    return (address + diff) & 0xffffffff


def exidx_starts(blob, sections):
    index = next((s for s in sections if s['name']=='.ARM.exidx'), None)
    text = next((s for s in sections if s['name']=='.text'), None)
    if not index or not text or index['size']<16 or index['size']%8:
        raise ValueError('Missing valid .ARM.exidx')
    output = []
    for i in range(0,index['size'],8):
        pos=index['off']+i
        raw=struct.unpack_from('<I',blob,pos)[0]
        va=prel31(raw,index['va']+i)
        if va<text['va'] or va>text['va']+text['size']:
            raise ValueError('Unwind pointer outside executable .text')
        if output and va<=output[-1]:
            raise ValueError('Unsorted or repeated unwind entries')
        output.append(va)
    return output


def method_bounds(starts, address):
    i=bisect.bisect_left(starts,address)
    if i>=len(starts)-1 or starts[i]!=address:
        raise ValueError('Method not exact EHABI entry 0x%08X'%address)
    return (address,starts[i+1])


def reg_blx(word):
    return word & 15 if (word & 0x0ffffff0)==0x012fff30 else None


def immediate_blx_target(word, va):
    if (word & 0xfe000000)!=0xfa000000:
        return None
    delta=word & 0x00ffffff
    if delta & 0x00800000:
        delta -= 0x01000000
    return (va+8+delta*4+((word>>24)&1)*2) & 0xffffffff


def conditional_bne_target(word, va):
    if (word & 0xff000000)!=0x1a000000:
        return None
    delta=word & 0x00ffffff
    if delta & 0x00800000:
        delta -= 0x01000000
    return (va+8+delta*4) & 0xffffffff


def load_vptr_into_r3(word):
    # LDR r3,[rN] with any base Rn and no displacement; no condition.
    return (word & 0xfff0ffff)==0xe5903000


def classify(blob, sections, begin, end, location, target_reg):
    before=word_va(blob, sections, location-4) if location-4>=begin else None
    if target_reg==3 and before in (0xe5933008,0xe5933020):
        offset=before & 0xfff
        witnesses=[a for a in range(max(begin,location-20),location-4,4)
                   if load_vptr_into_r3(word_va(blob,sections,a))]
        if witnesses:
            return {'kind':'vtable_slot_call','entry_index':offset//4,
                    'vptr_loaded_at_va':'0x%08X'%witnesses[-1],
                    'vfunc_loaded_at_va':'0x%08X'%(location-4)}
    if target_reg==1 and before==0x17931001:
        return {'kind':'indexed_function_pointer','pointer_load_va':'0x%08X'%(location-4),
                'note':'LDRNE r1,[r3,r1] before BLX r1; actual target unresolved'}
    if target_reg==3 and location>=begin+8:
        for bne in range(begin,location-8,4):
            if conditional_bne_target(word_va(blob,sections,bne),bne)==location-8:
                r3loads=[a for a in range(max(begin,bne-28),bne,4)
                         if word_va(blob,sections,a)==0xe5933000]
                if r3loads:
                    return {'kind':'conditional_vtable_first_entry_fallback',
                            'bne_va':'0x%08X'%bne,
                            'vptr_first_entry_load_va':'0x%08X'%r3loads[-1],
                            'note':'Branch preserves an indirect function pointer; identity unresolved'}
    return {'kind':'unresolved_register_target', 'note':'Static trace cannot identify the function'}


def inspect(blob, vtables, bounds, models=MODELS):
    sha=hashlib.sha256(blob).hexdigest()
    if sha!=vtables.get('source_sha256') or sha!=bounds.get('source_sha256'):
        raise ValueError('Source SHA-256 mismatch with supplied analysis reports')
    sec=parse_sections(blob)
    starts=exidx_starts(blob,sec)
    outputs={}
    summary=collections.Counter()
    for model in models:
        primary=vtables['controllers'][model]['vtables'][0]
        if primary['offset_to_top']!=0:
            raise ValueError('Missing primary vtable for '+model)
        vtable_va=int(primary['vtable_va'],16)
        data=bounds['models'][model]
        outputs[model]={}
        for slot in SLOTS:
            method=int(primary['function_va'][slot],16)
            if word_va(blob,sec,vtable_va+8+4*slot)!=method:
                raise ValueError('Vtable function pointer mismatch')
            begin,end=method_bounds(starts,method&~1)
            earlier=data[str(slot)]
            if begin!=int(earlier['method_start_va'],16) or end!=int(earlier['exidx_next_start_va'],16):
                raise ValueError('Bounds disagree with EHABI source')
            sites=[];blx_imm=[]
            for va in range(begin,end,4):
                opcode=word_va(blob,sec,va)
                reg=reg_blx(opcode)
                if reg is not None:
                    detail=classify(blob,sec,begin,end,va,reg)
                    summary[detail['kind']]+=1
                    sites.append({'call_va':'0x%08X'%va,'opcode':'0x%08X'%opcode,
                                  'register':f'r{reg}',**detail})
                else:
                    target=immediate_blx_target(opcode,va)
                    if target is not None:
                        blx_imm.append({'call_va':'0x%08X'%va,'target_va':'0x%08X'%target})
                        summary['immediate_blx']+=1
            outputs[model][str(slot)]={'method_va':'0x%08X'%begin,'end_va':'0x%08X'%end,
                                       'register_blx_count':len(sites),
                                       'immediate_blx_count':len(blx_imm),
                                       'calls':sites,'immediate_blx':blx_imm}
    return {'sha256':sha,'exidx_entry_count':len(starts),
            'register_blx_total':sum(x['register_blx_count'] for obj in outputs.values() for x in obj.values()),
            'classification_totals':dict(summary), 'models':outputs,
            'caution':'Pattern matching only. Indexed call targets and vtable owners are unresolved; no audio DSP path or external .so ABI is established.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',type=Path,required=True)
    p.add_argument('--vtables',type=Path,required=True)
    p.add_argument('--bounds',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    with a.evil.open('rb') as source, mmap.mmap(source.fileno(),0,access=mmap.ACCESS_READ) as blob:
        report=inspect(blob,json.loads(a.vtables.read_text()),json.loads(a.bounds.read_text()))
    a.out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('Saved',a.out,'BLX',report['register_blx_total'],report['classification_totals'])


if __name__=='__main__':
    main()
