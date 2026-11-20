"""Synthetic ELF tests for wrapper-to-inner slot3 and A32 NEON evidence."""
import struct
import unittest

from probe_inner_audio_candidate import (MODELS, SPECIAL_SLOTS,
                                         TAIL_OPCODES, inspect as original_inspect,
                                         target_bl)


def fixture():
    names=b'\0.text\0.rodata\0.data.rel.ro\0.data.rel.ro.local\0.ARM.exidx\0.shstrtab\0'
    places={
        '.text':(0x1000,0x100,0x6000,1),
        '.rodata':(0x9000,0x6B00,0x400,1),
        '.data.rel.ro.local':(0x8000,0x6200,0x800,1),
        '.data.rel.ro':(0xA000,0x7000,0x100,1),
        '.ARM.exidx':(0xB000,0x7200,64,0x70000001),
        '.shstrtab':(0,0x7300,len(names),3),
    }
    blob=bytearray(0x7600)
    blob[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',blob,18,40)
    struct.pack_into('<I',blob,32,0x7400)
    struct.pack_into('<HHH',blob,46,40,7,6)
    blob[0x7300:0x7300+len(names)]=names
    for i,(name,(va,off,size,typ)) in enumerate(places.items(),1):
        struct.pack_into('<10I',blob,0x7400+i*40,names.index(name.encode()),typ,0,va,off,size,0,0,4,8 if name=='.ARM.exidx' else 0)
    def offset(va):
        for address,off,size,typ in places.values():
            if typ!=8 and address<=va<address+size and va+4<=address+size:
                return off+va-address
        raise ValueError(hex(va))
    def w(va,value):struct.pack_into('<I',blob,offset(va),value&0xffffffff)
    def branch(va,dest):return 0xEB000000|(((dest-va-8)//4)&0xffffff)
    starts=[0x1000,0x1400,0x2000,0x2400,0x3000,0x3400,0x4000,0x5000]
    for i,va in enumerate(starts):
        at=0xB000+i*8
        w(at,(va-at)&0x7fffffff)
        w(at+4,1)
    cfg={}
    for mi,(name,original) in enumerate(MODELS.items()):
        start=0x1000+mi*0x1000
        end=start+0x400
        vptr=0x8008+mi*0x200
        wrapper=0x8608+mi*0x80
        ti=0xA000+mi*0x20
        nameloc=0x9000+mi*0x80
        nameval=original['name'].encode()+b'\0'
        blob[offset(nameloc):offset(nameloc)+len(nameval)]=nameval
        w(ti+4,nameloc)
        w(vptr-8,0);w(vptr-4,ti)
        for index in range(36):
            v=0x5000+index*4
            if index in SPECIAL_SLOTS:v=0x5400+mi*0x100+index*4
            if index==3:v=start
            w(vptr+4*index,v)
        w(vptr+36*4,0)
        caller=0x4800+mi*0x80
        w(wrapper+12,caller)
        for i,op in enumerate(TAIL_OPCODES):w(caller+4*i,op)
        anchors={'flag':start+0x4c,'vld':start+0x80,'vst':start+0x8c,'vmul':start+0x90}
        for a,op in (('flag',0xE5D03B6C),('vld',0xF4604A8F),('vst',0xF4400A8D),('vmul',0xEE277A87)):
            w(anchors[a],op)
        calls=(start+0x100,start+0x110,start+0x120)
        for va,dest in zip(calls,(0x5100,0x5200,0x5300)):w(va,branch(va,dest))
        cfg[name]={'wrapper':wrapper,'effect':vptr,'name':original['name'],
                   'slot3':start,'end':end,**anchors,'calls':calls}
    return blob,cfg,offset


def inspect(blob,cfg,required_sha=None):
    return original_inspect(blob,cfg,required_sha,expected_callees=(0x5100,0x5200,0x5300))


class InnerAudioCandidateTests(unittest.TestCase):
    def test_valid_synthetic_elf(self):
        blob,cfg,_=fixture();r=inspect(blob,cfg,required_sha=None)
        self.assertEqual(r['methods_per_effect'],36)
        self.assertEqual(r['shared_method_slots'],30)
        self.assertEqual(r['effect_specific_slots'],list(SPECIAL_SLOTS))
        self.assertEqual(len(r['effects']),3)
        self.assertEqual(r['effects']['Shimmer']['ehabi_bounded_bytes'],0x400)

    def test_sha_guard(self):
        blob,cfg,_=fixture()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            inspect(blob,cfg,required_sha='0'*64)

    def test_invalid_elf(self):
        with self.assertRaisesRegex(ValueError,'ARM ELF32'):
            inspect(b'broken',{},required_sha=None)

    def test_rtti_changed(self):
        blob,cfg,off=fixture();blob[off(0x9000)]=ord('X')
        with self.assertRaisesRegex(ValueError,'RTTI'):
            inspect(blob,cfg,None)

    def test_vtable_header_changed(self):
        blob,cfg,off=fixture();struct.pack_into('<I',blob,off(cfg['Shimmer']['effect']-8),5)
        with self.assertRaisesRegex(ValueError,'vtable header'):
            inspect(blob,cfg,None)

    def test_effect_slot3_changed(self):
        blob,cfg,off=fixture();struct.pack_into('<I',blob,off(cfg['AIR Delay']['effect']+12),0x5500)
        with self.assertRaisesRegex(ValueError,'slot3 differs'):
            inspect(blob,cfg,None)

    def test_wrapper_call_guard(self):
        blob,cfg,off=fixture();fn=0x4800
        struct.pack_into('<I',blob,off(fn+24),0xE12FFF3C)
        with self.assertRaisesRegex(ValueError,'tail-call'):
            inspect(blob,cfg,None)

    def test_flag_mutation(self):
        blob,cfg,off=fixture();blob[off(cfg['Multi Chorus']['flag'])]^=1
        with self.assertRaisesRegex(ValueError,'instruction anchor'):
            inspect(blob,cfg,None)

    def test_vector_load_mutation(self):
        blob,cfg,off=fixture();blob[off(cfg['Shimmer']['vld'])]^=1
        with self.assertRaisesRegex(ValueError,'instruction anchor'):
            inspect(blob,cfg,None)

    def test_vector_store_mutation(self):
        blob,cfg,off=fixture();blob[off(cfg['AIR Delay']['vst'])]^=1
        with self.assertRaisesRegex(ValueError,'instruction anchor'):
            inspect(blob,cfg,None)

    def test_float_mul_mutation(self):
        blob,cfg,off=fixture();blob[off(cfg['AIR Delay']['vmul'])]^=1
        with self.assertRaisesRegex(ValueError,'instruction anchor'):
            inspect(blob,cfg,None)

    def test_one_call_target_mutation(self):
        blob,cfg,off=fixture();va=cfg['Shimmer']['calls'][1]
        x=struct.unpack_from('<I',blob,off(va))[0]
        struct.pack_into('<I',blob,off(va),x+1)
        with self.assertRaisesRegex(ValueError,'common callee'):
            inspect(blob,cfg,None)

    def test_wrong_ehabi_end(self):
        blob,cfg,off=fixture();cfg['AIR Delay']['end']+=4
        with self.assertRaisesRegex(ValueError,'EHABI'):
            inspect(blob,cfg,None)

    def test_shared_slot_mutation(self):
        blob,cfg,off=fixture();vptr=cfg['Shimmer']['effect']
        struct.pack_into('<I',blob,off(vptr+12*4),0x5900)
        with self.assertRaisesRegex(ValueError,'distinct virtual'):
            inspect(blob,cfg,None)

    def test_unmapped_vtable_member(self):
        blob,cfg,off=fixture();vptr=cfg['Shimmer']['effect']
        struct.pack_into('<I',blob,off(vptr+8*4),0x8000)
        with self.assertRaisesRegex(ValueError,'36 executable'):
            inspect(blob,cfg,None)

    def test_extra_virtual_entry(self):
        blob,cfg,off=fixture();vptr=cfg['AIR Delay']['effect']
        struct.pack_into('<I',blob,off(vptr+36*4),0x5100)
        with self.assertRaisesRegex(ValueError,'Too many'):
            inspect(blob,cfg,None)

    def test_branch_negative_disp(self):
        self.assertEqual(target_bl(0xEBFFFFFE,0x1000),0x1000)
        with self.assertRaisesRegex(ValueError,'Not unconditional'):
            target_bl(0xE12FFF1C,0x1000)


if __name__=='__main__':unittest.main()
