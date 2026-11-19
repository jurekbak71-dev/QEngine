"""Synthetic regression tests for read-only vtable/BLX call analysis."""
import hashlib
import struct
import unittest

from trace_spatial_indirect_calls import (
    classify, conditional_bne_target, exidx_starts, immediate_blx_target,
    inspect, method_bounds, parse_sections, reg_blx,
)


def make_fixture():
    blob=bytearray(0xC00)
    blob[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',blob,18,40)
    struct.pack_into('<I',blob,32,0xA00)
    struct.pack_into('<HHH',blob,46,40,5,4)
    names=b'\x00.text\x00.data.rel.ro.local\x00.ARM.exidx\x00.shstrtab\x00'
    blob[0x900:0x900+len(names)]=names
    for i,name,typ,va,off,size in [
        (1,b'.text',1,0x1000,0x100,0x400),
        (2,b'.data.rel.ro.local',1,0x5000,0x600,0x100),
        (3,b'.ARM.exidx',0x70000001,0x8000,0x800,0x30),
        (4,b'.shstrtab',3,0,0x900,len(names)),
    ]:
        struct.pack_into('<10I',blob,0xA00+40*i,names.index(name),typ,0,va,off,size,0,0,4,0)
    for va in range(0x1000,0x1400,4):
        struct.pack_into('<I',blob,0x100+va-0x1000,0xE1A00000)
    starts=(0x1000,0x1040,0x1080,0x10c0,0x1100,0x1200)
    for i,va in enumerate(starts):
        pos=0x8000+i*8
        struct.pack_into('<II',blob,0x800+i*8,(va-pos)&0x7fffffff,1)
    struct.pack_into('<I',blob,0x600+8+25*4,0x1040)
    struct.pack_into('<I',blob,0x600+8+26*4,0x1080)
    inst={
        0x1040:0xE5903000, 0x1044:0xE5933008, 0x1048:0xE12FFF33,
        0x1050:0x17931001, 0x1054:0xE12FFF31,
        0x1060:0xE5933000, 0x1064:0x1A000002,
        0x1074:0xE1A01006, 0x1078:0xE1A00005, 0x107C:0xE12FFF33,
        0x1080:0xE5903000, 0x1084:0xE5933020, 0x1088:0xE12FFF33,
    }
    for va,word in inst.items():
        struct.pack_into('<I',blob,0x100+va-0x1000,word)
    def reports():
        sha=hashlib.sha256(blob).hexdigest()
        vt={'source_sha256':sha,'controllers':{'Shimmer':{'vtables':[{'offset_to_top':0,
            'vtable_va':'0x00005000','function_va':['0']*25+['0x00001040','0x00001080']}]}}}
        bd={'source_sha256':sha,'models':{'Shimmer':{
            '25':{'method_start_va':'0x00001040','exidx_next_start_va':'0x00001080'},
            '26':{'method_start_va':'0x00001080','exidx_next_start_va':'0x000010C0'},
        }}}
        return vt,bd
    return blob,reports


class IndirectCallTests(unittest.TestCase):
    def test_arm_blx_register_vs_branch(self):
        self.assertEqual(reg_blx(0xE12FFF33),3)
        self.assertEqual(reg_blx(0x112FFF31),1)
        self.assertIsNone(reg_blx(0xE12FFF13))  # BX, not BLX
        self.assertIsNone(reg_blx(0xEB000000))

    def test_blx_immediate(self):
        self.assertEqual(immediate_blx_target(0xFA000000,0x1000),0x1008)
        self.assertEqual(immediate_blx_target(0xFB000000,0x1000),0x100A)
        self.assertIsNone(immediate_blx_target(0xEB000000,0x1000))

    def test_bne_target(self):
        self.assertEqual(conditional_bne_target(0x1A000002,0x1064),0x1074)
        self.assertIsNone(conditional_bne_target(0xEA000002,0x1064))

    def test_verified_method_bounds(self):
        raw,_=make_fixture();sections=parse_sections(raw)
        starts=exidx_starts(raw,sections)
        self.assertEqual(starts,[0x1000,0x1040,0x1080,0x10c0,0x1100,0x1200])
        self.assertEqual(method_bounds(starts,0x1040),(0x1040,0x1080))
        with self.assertRaisesRegex(ValueError,'not exact'):
            method_bounds(starts,0x1044)

    def test_classify_three_call_styles(self):
        raw,_=make_fixture();sec=parse_sections(raw)
        self.assertEqual(classify(raw,sec,0x1040,0x1080,0x1048,3)['entry_index'],2)
        self.assertEqual(classify(raw,sec,0x1040,0x1080,0x1054,1)['kind'],
                         'indexed_function_pointer')
        kind=classify(raw,sec,0x1040,0x1080,0x107C,3)
        self.assertEqual(kind['kind'],'conditional_vtable_first_entry_fallback')
        self.assertEqual(kind['bne_va'],'0x00001064')

    def test_full_classification(self):
        raw,make_reports=make_fixture(); vt,bd=make_reports()
        result=inspect(raw,vt,bd,models=('Shimmer',))
        self.assertEqual(result['register_blx_total'],4)
        self.assertEqual(result['classification_totals'],{
            'vtable_slot_call':2,'indexed_function_pointer':1,
            'conditional_vtable_first_entry_fallback':1})
        self.assertEqual(result['models']['Shimmer']['25']['register_blx_count'],3)

    def test_hash_guard(self):
        raw,make_reports=make_fixture();vt,bd=make_reports()
        bd['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            inspect(raw,vt,bd,models=('Shimmer',))

    def test_vtable_guard(self):
        raw,make_reports=make_fixture();vt,bd=make_reports()
        raw=bytearray(raw)
        struct.pack_into('<I',raw,0x600+8+25*4,0x1090)
        vt['source_sha256']=bd['source_sha256']=hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError,'Vtable'):
            inspect(raw,vt,bd,models=('Shimmer',))

    def test_ehabi_guard(self):
        raw,make_reports=make_fixture();vt,bd=make_reports()
        bd['models']['Shimmer']['25']['exidx_next_start_va']='0x000010C0'
        with self.assertRaisesRegex(ValueError,'Bounds'):
            inspect(raw,vt,bd,models=('Shimmer',))

    def test_unresolved_without_witness(self):
        raw,_=make_fixture();sec=parse_sections(raw)
        self.assertEqual(classify(raw,sec,0x1040,0x1080,0x1054,3)['kind'],
                         'unresolved_register_target')

    def test_reject_bad_elf(self):
        with self.assertRaisesRegex(ValueError,'ELF32'):
            parse_sections(b'junk')


if __name__=='__main__':
    unittest.main()
