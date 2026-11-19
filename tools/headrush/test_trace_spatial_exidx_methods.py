"""Regression tests for ARM EHABI-bounded spatial controller methods."""
import hashlib
import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from test_probe_spatial_controller_vtables import fixture as original_fixture
from trace_spatial_exidx_methods import (
    prel31, exidx_starts, exact_range, direct_bl_target, inspect,
)
from probe_spatial_controller_vtables import parse_sections


def sample():
    blob=original_fixture()
    original=b'\0.text\0.rodata\0.data.rel.ro.local\0.data.rel.ro\0.shstrtab\0'
    suffix=b'.ARM.exidx\0'
    blob[0xC00:0xC00+len(original)+len(suffix)]=original+suffix
    struct.pack_into('<HHH',blob,46,40,7,5)
    struct.pack_into('<I',blob,0xD00+5*40+20,len(original)+len(suffix))
    struct.pack_into('<10I',blob,0xD00+6*40,
                     len(original),0x70000001,0,0x8000,0xE80,32,0,0,4,8)
    for i,va in enumerate((0x1000,0x1100,0x1110,0x1200)):
        where=0x8000+i*8
        struct.pack_into('<II',blob,0xE80+i*8,(va-where)&0x7fffffff,1)
    # Replace the original Mix reference in slot25 with NOPs.
    for off in (0x200,0x204,0x20C):
        struct.pack_into('<I',blob,off,0xE1A00000)
    # slot26 contains a verified code reference to Mix.
    struct.pack_into('<I',blob,0x210,0xE59F2004)
    struct.pack_into('<I',blob,0x214,0xE08F2002)
    struct.pack_into('<I',blob,0x21C,0x3080-(0x1114+8))
    struct.pack_into('<I',blob,0x218,0xEB000000)
    # The original RTTI fixture has vtable header at file offset 0x740.
    struct.pack_into('<I',blob,0x740+8+25*4,0x1100)
    struct.pack_into('<I',blob,0x740+8+26*4,0x1110)
    report={'source_sha256':hashlib.sha256(blob).hexdigest(),
            'controllers':{'Shimmer':{'vtables':[{
                'vtable_va':'0x00005040','offset_to_top':0,
                'function_va':['0x0']*25+['0x00001100','0x00001110']
            }]}}}
    return blob,report


class ExidxMethodTests(unittest.TestCase):
    def test_signed_prel31(self):
        self.assertEqual(prel31((-0x1000)&0x7fffffff,0x2000),0x1000)
        self.assertEqual(prel31(32,0x2000),0x2020)

    def test_all_start_entries(self):
        b,_=sample()
        starts=exidx_starts(b,parse_sections(b))
        self.assertEqual(starts,[0x1000,0x1100,0x1110,0x1200])
        self.assertEqual(exact_range(starts,0x1110),(0x1110,0x1200))

    def test_non_entry_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'not an exact'):
            exact_range([0x1000,0x1020,0x1040],0x1024)

    def test_branch_detection(self):
        self.assertEqual(direct_bl_target(0xEBFFFFFE,0x1000),0x1000)
        self.assertIsNone(direct_bl_target(0x1B000000,0x1000))
        self.assertIsNone(direct_bl_target(0xFA000000,0x1000))

    def test_bounded_method_and_vtable(self):
        b,report=sample()
        result=inspect(b,report,models=('Shimmer',))
        one=result['methods']['Shimmer']
        self.assertEqual(one['25']['bounded_bytes'],16)
        self.assertEqual(one['25']['literal_refs'],[])
        self.assertEqual(one['26']['bounded_bytes'],0xF0)
        self.assertEqual([x['label'] for x in one['26']['literal_refs']],['Mix'])
        self.assertEqual(one['26']['direct_unconditional_arm_bl_count'],1)

    def test_factory_key_crosscheck_readonly(self):
        b,report=sample()
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'test.db'
            rig={'data':{'Patch':{'children':{
                'Shimmer':{'children':{'Mix':{'type':0,'value':5},
                                        'HighCut':{'type':0,'value':1000}}}}}}}
            with sqlite3.connect(p) as db:
                db.execute('create table rigs(content text)')
                db.execute('insert into rigs values(?)',(json.dumps(rig),))
            out=inspect(b,report,p,models=('Shimmer',))
            v=out['methods']['Shimmer']['26']
            self.assertEqual(v['factory_key_matches'],['Mix'])
            self.assertEqual(v['factory_keys_not_literal_in_method'],['HighCut'])

    def test_vtable_modified_rejected(self):
        b,report=sample();b=bytearray(b)
        struct.pack_into('<I',b,0x740+8+26*4,0x1180)
        report['source_sha256']=hashlib.sha256(b).hexdigest()
        with self.assertRaisesRegex(ValueError,'differs'):
            inspect(b,report,models=('Shimmer',))

    def test_wrong_binary_checksum_rejected(self):
        b,report=sample(); report['source_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'hash'):
            inspect(b,report,models=('Shimmer',))

    def test_corrupt_exidx_order_rejected(self):
        b,report=sample();b=bytearray(b)
        where=0x8000+2*8
        struct.pack_into('<I',b,0xE80+2*8,(0x1050-where)&0x7fffffff)
        with self.assertRaisesRegex(ValueError,'Unsorted'):
            exidx_starts(b,parse_sections(b))


if __name__=='__main__':
    unittest.main()
