"""Synthetic regression tests for verified SESP property connector object lifecycle."""
import hashlib
import struct
import unittest
from trace_spatial_connector_objects import (
    verify, pc_literal_plus_add, elf_sections, REGISTRATION_HELPER,
)

def fixture():
    data=bytearray(0x1200)
    data[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',data,18,40)
    struct.pack_into('<I',data,32,0xE00)
    struct.pack_into('<HHH',data,46,40,6,5)
    names=b'\0.text\0.rodata\0.data.rel.ro.local\0.data.rel.ro\0.shstrtab\0'
    data[0xD00:0xD00+len(names)]=names
    for ix,name,ty,va,off,size in [
        (1,b'.text',1,0x1000,0x100,0x400),
        (2,b'.rodata',1,0x2000,0x600,0x180),
        (3,b'.data.rel.ro.local',1,0x3000,0x800,0x100),
        (4,b'.data.rel.ro',1,0x4000,0xA00,0x100),
        (5,b'.shstrtab',3,0,0xD00,len(names)),
    ]:
        struct.pack_into('<10I',data,0xE00+ix*40,names.index(name),ty,0,va,off,size,0,0,4,0)
    mangled='N8EvilDSPs11Controllers13DSPController24DspPropertyConnectorImplI4TestE'
    data[0x600:0x600+len(mangled)+1]=mangled.encode()+b'\0'
    def text(va,word):struct.pack_into('<I',data,0x100+va-0x1000,word)
    text(0x1000,0xE59F30B8)
    text(0x1008,0xE08F3003)
    text(0x100C,0xE2833008)
    text(0x1010,0xE8850108)
    text(0x1020,0xEB000000 | (((REGISTRATION_HELPER-0x1028)//4)&0xffffff))
    text(0x1024,0xE5805000)
    text(0x1030,0xE5953000)
    text(0x1034,0xE59F2088)
    text(0x1038,0xE5933000)
    text(0x103C,0xE08F2002)
    text(0x1040,0xE1530002)
    text(0x10C0,0x3000 - 0x1010)
    text(0x10C4,0x1070 - 0x1044)
    struct.pack_into('<III',data,0x800,0,0x4000,0x1070)
    struct.pack_into('<II',data,0xA00,0,0x2000)
    cfg={'SyntheticTest':{
        'mangled':mangled,'vtable_va':0x3008,
        'constructor':(0x1000,0x1008,0x100C,0x1010,0xE8850108),
        'registration':(0x1020,0x1024,0xE5805000),
        'fastpath':(0x1030,0xE5953000,0x1034,0x1038,0x103C,0x1040),
    }}
    return data,cfg

def record(data,cfg):
    return verify(data,cfg,expected_sha256=None)

class ConnectorObjectTests(unittest.TestCase):
    def test_verified_chain(self):
        raw,cfg=fixture()
        report=record(raw,cfg)
        self.assertEqual(report['verified_connector_links'],1)
        r=report['results'][0]
        self.assertEqual(r['vtable_va'],r['construct_vptr_va'])
        self.assertEqual(r['first_virtual_method_va'],r['fastpath_compared_first_method_va'])
        self.assertEqual(r['registration_helper_va'],f'0x{REGISTRATION_HELPER:08X}')

    def test_reject_changed_vptr_delta(self):
        raw,cfg=fixture()
        struct.pack_into('<I',raw,0x100+0x10C0-0x1000,0)
        with self.assertRaisesRegex(ValueError,'expected vptr'):
            record(raw,cfg)

    def test_reject_changed_method_literal(self):
        raw,cfg=fixture()
        struct.pack_into('<I',raw,0x100+0x10C4-0x1000,8)
        with self.assertRaisesRegex(ValueError,'does not match vtable'):
            record(raw,cfg)

    def test_reject_wrong_rtti(self):
        raw,cfg=fixture()
        raw[0x600]=ord('Z')
        with self.assertRaisesRegex(ValueError,'RTTI'):
            record(raw,cfg)

    def test_reject_wrong_registration_destination(self):
        raw,cfg=fixture()
        struct.pack_into('<I',raw,0x120,0xEB000000)
        with self.assertRaisesRegex(ValueError,'registration helper'):
            record(raw,cfg)

    def test_reject_wrong_object_store(self):
        raw,cfg=fixture()
        struct.pack_into('<I',raw,0x124,0)
        with self.assertRaisesRegex(ValueError,'Registration'):
            record(raw,cfg)

    def test_reject_wrong_constructor_store(self):
        raw,cfg=fixture()
        struct.pack_into('<I',raw,0x110,0)
        with self.assertRaisesRegex(ValueError,'Constructor'):
            record(raw,cfg)

    def test_reject_invalid_executable(self):
        with self.assertRaisesRegex(ValueError,'ARM32'):
            verify(b'wrong',{},None)

    def test_sha256_guard(self):
        raw,cfg=fixture()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            verify(raw,cfg,'0'*64)

    def test_negative_pc_literal_pool(self):
        raw,cfg=fixture()
        struct.pack_into('<I',raw,0x100+0x1100-0x1000,0xE51F3018)
        struct.pack_into('<I',raw,0x100+0x1104-0x1000,0xE08F3003)
        struct.pack_into('<i',raw,0x100+0x10F0-0x1000,0x234)
        computed,pool=pc_literal_plus_add(raw,elf_sections(raw),0x1100,0x1104,3)
        self.assertEqual(computed,0x1104+8+0x234)
        self.assertEqual(pool,0x10F0)

    def test_different_typeinfo_rejected(self):
        raw,cfg=fixture()
        struct.pack_into('<I',raw,0x804,0xdeadbeef)
        with self.assertRaisesRegex(ValueError,'Unmapped'):
            record(raw,cfg)

if __name__ == '__main__':
    unittest.main()
