"""Synthetic regression tests for the two-stage HeadRush spatial DSP factory."""
import struct
import unittest

from verify_spatial_factory_paths import (
    analyze, arm_b, MODELS, PRIMARY_TABLE, SECONDARY_TABLE,
    SECONDARY_DEFAULT, PRIMARY_DEFAULT_CODE,
)


def synthetic_elf():
    blocks=[('.text',0x812570,0x4200),('.rodata',0x1900000,0x2000),
            ('.data.rel.ro.local',0x2ea8000,0x1000),('.data.rel.ro',0x2f50000,0x1000)]
    off=0x200; areas={}
    for name,va,size in blocks:areas[name]=(va,off,size);off+=size
    # Put .data.rel.ro before .data.rel.ro.local to avoid a name-prefix collision.
    shnames=b'\0.text\0.rodata\0.data.rel.ro\0.data.rel.ro.local\0.shstrtab\0'
    names_off=off;off+=len(shnames)
    shoff=(off+3)&~3
    data=bytearray(shoff+40*6)
    data[:6]=b'\x7fELF\x01\x01';struct.pack_into('<H',data,18,40)
    struct.pack_into('<I',data,32,shoff);struct.pack_into('<HHH',data,46,40,6,5)
    data[names_off:names_off+len(shnames)]=shnames
    for idx,(name,va,size) in enumerate(blocks,1):
        _,f_off,_=areas[name]
        struct.pack_into('<10I',data,shoff+40*idx,
                         shnames.index(name.encode()),1,0,va,f_off,size,0,0,4,0)
    struct.pack_into('<10I',data,shoff+5*40,shnames.index(b'.shstrtab'),
                     3,0,0,names_off,len(shnames),0,0,1,0)
    def at(va):
        for _,(start,file_off,size) in areas.items():
            if start<=va<start+size:return file_off+va-start
        raise ValueError(hex(va))
    def word(va,x):struct.pack_into('<I',data,at(va),x&0xffffffff)
    def branch(va,dest):return 0xea000000|(((dest-va-8)//4)&0xffffff)
    for va,x in [(0x8125a8,0xe350008a),(0x8125ac,0x908ff100),
                 (0x8127e0,0xe240301b),(0x8127e4,0xe353004f),
                 (0x8127e8,0x908ff103)]:word(va,x)
    word(0x8125b0,branch(0x8125b0,PRIMARY_DEFAULT_CODE))
    word(0x8127ec,branch(0x8127ec,SECONDARY_DEFAULT))
    for idx in range(139):
        va=PRIMARY_TABLE+4*idx;word(va,branch(va,PRIMARY_DEFAULT_CODE))
    for idx in range(80):
        va=SECONDARY_TABLE+4*idx;word(va,branch(va,SECONDARY_DEFAULT))
    names={}
    for i,(index,(name,handler)) in enumerate(MODELS.items()):
        va=SECONDARY_TABLE+4*(index-27);word(va,branch(va,handler))
        vptr=0x2ea8000+(index*16)
        ti=0x2f50000+(index*16)
        nameva=0x1900000+(i*128)
        rtti=f'N8EvilDSPs9DSPModuleINS_{len(name)}{name}ENS_1AE'.encode()+b'\0'
        data[at(nameva):at(nameva)+len(rtti)]=rtti
        word(ti+4,nameva)
        word(vptr-8,0);word(vptr-4,ti);word(vptr,0x812570)
        word(handler+0x14,0xe59f3000)
        word(handler+0x1c,vptr-(handler+0x34))
        word(handler+0x24,0xe08f3003)
        word(handler+0x28,0xe2833008)
        word(handler+0x2c,0xe482303c)
        names[index]=(vptr,ti,nameva)
    return data,at,names


class TwoStageFactoryTests(unittest.TestCase):
    def test_two_stage_eight_spatial_models(self):
        blob,*_=synthetic_elf()
        report=analyze(blob,required_sha=None)
        self.assertEqual((report['primary_entries'],report['secondary_entries']),(139,80))
        self.assertEqual(len(report['verified_spatial_modules']),8)
        self.assertEqual({x['module_index'] for x in report['verified_spatial_modules']},
                         {32,35,37,38,42,43,84,85})

    def test_secondary_wrong_target(self):
        blob,at,*_=synthetic_elf()
        va=SECONDARY_TABLE+4*(85-27)
        struct.pack_into('<I',blob,at(va),0xea000000)
        with self.assertRaisesRegex(ValueError,'secondary target mismatch'):
            analyze(blob,None)

    def test_first_switch_short_circuit(self):
        blob,at,*_=synthetic_elf()
        va=PRIMARY_TABLE+4*43
        struct.pack_into('<I',blob,at(va),0xea000000)
        with self.assertRaisesRegex(ValueError,'secondary dispatch'):
            analyze(blob,None)

    def test_wrong_rtti_rejected(self):
        blob,at,names=synthetic_elf()
        nameva=names[85][2]
        blob[at(nameva)+len(b'N8EvilDSPs9DSPModuleINS_')+1]=ord('Z')
        with self.assertRaisesRegex(ValueError,'Module type mismatch'):
            analyze(blob,None)

    def test_wrong_vptr_rejected(self):
        blob,at,names=synthetic_elf()
        vptr=names[84][0];struct.pack_into('<i',blob,at(vptr-8),4)
        with self.assertRaisesRegex(ValueError,'offset-to-top'):
            analyze(blob,None)

    def test_modified_constructor_rejected(self):
        blob,at,*_=synthetic_elf()
        blob[at(MODELS[43][1]+0x28)]=0
        with self.assertRaisesRegex(ValueError,'arithmetic'):
            analyze(blob,None)

    def test_bad_first_dispatch_opcode(self):
        blob,at,*_=synthetic_elf();blob[at(0x8125ac)]=0xFF
        with self.assertRaisesRegex(ValueError,'switch opcode'):
            analyze(blob,None)

    def test_bad_second_dispatch_opcode(self):
        blob,at,*_=synthetic_elf();blob[at(0x8127e8)]=0
        with self.assertRaisesRegex(ValueError,'switch opcode'):
            analyze(blob,None)

    def test_no_required_original_sha(self):
        blob,*_=synthetic_elf()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            analyze(blob,'0'*64)

    def test_non_branch_rejected(self):
        with self.assertRaisesRegex(ValueError,'Not an unconditional'):
            arm_b(0xe1a00000,0x1000)

    def test_backward_branch(self):
        self.assertEqual(arm_b(0xeafffffe,0x1000),0x1000)

    def test_corrupt_elf(self):
        with self.assertRaisesRegex(ValueError,'ELF32'):
            analyze(b'garbage',None)


if __name__=='__main__':unittest.main()
