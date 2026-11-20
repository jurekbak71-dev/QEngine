"""Synthetic ARM32 ELF tests for typed DSPModule internal object allocation."""
import struct
import unittest
from trace_spatial_module_object_construction import (
    verify, ALLOCATOR,
)


def synthetic_elf():
    b=bytearray(0x5000)
    b[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',b,18,40)
    struct.pack_into('<I',b,32,0x4800)
    struct.pack_into('<HHH',b,46,40,5,4)
    names=b'\0.text\0.rodata\0.data.rel.ro.local\0.shstrtab\0'
    b[0x4700:0x4700+len(names)]=names
    ranges=[('.text',0x1000,0x100,0x1000),
            ('.rodata',0x2000,0x1400,0x200),
            ('.data.rel.ro.local',0x3000,0x1700,0x800),
            ('.shstrtab',0,0x4700,len(names))]
    for i,(name,va,off,size) in enumerate(ranges,1):
        struct.pack_into('<10I',b,0x4800+i*40,names.index(name.encode()),3 if name=='.shstrtab' else 1,0,va,off,size,0,0,4,0)
    def at(va):
        for _,start,off,size in ranges:
            if start<=va<start+size and start!=0:return off+va-start
        raise ValueError(hex(va))
    def word(va,value):struct.pack_into('<I',b,at(va),value&0xffffffff)
    def bl(va,target):return 0xeb000000|(((target-va-8)//4)&0xffffff)
    def string(va,val):b[at(va):at(va)+len(val)+1]=val.encode()+b'\0'
    inner_name='N8EvilDSPs8AIRDelayE'
    ctrl_name='N8EvilDSPs18AIRDelayControllerE'
    string(0x2000,inner_name);string(0x2060,ctrl_name)
    word(0x3404,0x2000);word(0x3434,0x2060)
    for vptr,ti in ((0x3100,0x3400),(0x3200,0x3430)):
        word(vptr-8,0);word(vptr-4,ti);word(vptr,0x1300)
    word(0x3000+20*4,0x1100)
    model={'Demo Delay':{'wrapper_vtable':0x3000,'slot20':0x1100,'wrapper_reg':7,
        'inner':{'size':4376,'alloc_arg':0x1150,'alloc_bl':0x1154,'capture':0x1158,
                 'store':0x1190,'vptr_store':0x11a0,'ldr':0x1160,'add':0x1170,
                 'increment':0x1174,'rtti':inner_name},
        'controller':{'size':392,'alloc_arg':0x1200,'alloc_bl':0x1204,'capture':0x1208,
                      'store':0x1280,'vptr_store':0x12a0,'ldr':0x1210,'add':0x1220,
                      'increment':0x1224,'rtti':ctrl_name}}}
    word(0x1150,0xe3010118);word(0x1154,bl(0x1154,ALLOCATOR))
    word(0x1158,0xe1a04000);word(0x1190,0xe5874040);word(0x11a0,0xe5843000)
    word(0x1160,0xe59f3000);word(0x1168,0x3100-(0x1170+8+8))
    word(0x1170,0xe08f3003);word(0x1174,0xe2833008)
    word(0x1200,0xe3a00f62);word(0x1204,bl(0x1204,ALLOCATOR))
    word(0x1208,0xe1a06000);word(0x1280,0xe587604c);word(0x12a0,0xe5861000)
    word(0x1210,0xe59f3000);word(0x1218,0x3200-(0x1220+8+12))
    word(0x1220,0xe08f3003);word(0x1224,0xe283100c)
    return b,at,model


class TypedInnerObjectsTests(unittest.TestCase):
    def test_two_typed_objects(self):
        blob,_,models=synthetic_elf()
        r=verify(blob,models,expected_sha=None)
        self.assertEqual((r['verified_effects'],r['verified_objects']),(1,2))
        effects=r['effects'][0]['objects']
        self.assertEqual([(x['wrapper_offset'],x['vtable_va']) for x in effects],
                         [('0x40','0x00003100'),('0x4C','0x00003200')])
        self.assertEqual([x['allocated_bytes'] for x in effects],[4376,392])

    def test_sha_guard(self):
        blob,_,models=synthetic_elf()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            verify(blob,models,expected_sha='0'*64)

    def test_wrapper_vtable_guard(self):
        blob,at,models=synthetic_elf();struct.pack_into('<I',blob,at(0x3100),0)
        # Mutating inner first method triggers code-location guard.
        with self.assertRaisesRegex(ValueError,'First virtual method'):
            verify(blob,models,None)

    def test_wrong_wrapper_slot20(self):
        blob,at,models=synthetic_elf();struct.pack_into('<I',blob,at(0x3000+20*4),0)
        with self.assertRaisesRegex(ValueError,'Wrapper slot20'):
            verify(blob,models,None)

    def test_changed_inner_allocation(self):
        blob,at,models=synthetic_elf();blob[at(0x1150)]=0
        with self.assertRaisesRegex(ValueError,'Allocation'):
            verify(blob,models,None)

    def test_changed_controller_allocation(self):
        blob,at,models=synthetic_elf();blob[at(0x1200)]=0
        with self.assertRaisesRegex(ValueError,'Allocation'):
            verify(blob,models,None)

    def test_modified_allocator_target(self):
        blob,at,models=synthetic_elf();blob[at(0x1154)]=0
        with self.assertRaisesRegex(ValueError,'Allocator'):
            verify(blob,models,None)

    def test_changed_pointer_store(self):
        blob,at,models=synthetic_elf();blob[at(0x1190)]=0
        with self.assertRaisesRegex(ValueError,'Wrapper inner pointer'):
            verify(blob,models,None)

    def test_changed_controller_pointer_store(self):
        blob,at,models=synthetic_elf();blob[at(0x1280)]=0
        with self.assertRaisesRegex(ValueError,'Wrapper inner pointer'):
            verify(blob,models,None)

    def test_wrong_type_info(self):
        blob,at,models=synthetic_elf();blob[at(0x2060)]=ord('X')
        with self.assertRaisesRegex(ValueError,'Wrong RTTI'):
            verify(blob,models,None)

    def test_changed_vptr_expression(self):
        blob,at,models=synthetic_elf();blob[at(0x1174)]=0
        with self.assertRaisesRegex(ValueError,'vptr increment'):
            verify(blob,models,None)

    def test_changed_source_capture(self):
        blob,at,models=synthetic_elf();struct.pack_into('<I',blob,at(0x1158),0)
        with self.assertRaisesRegex(ValueError,'result capture'):
            verify(blob,models,None)

    def test_corrupt_elf(self):
        with self.assertRaisesRegex(ValueError,'ELF32'):
            verify(b'invalid ELF',expected_sha=None)

    def test_vptr_first_method_validation(self):
        blob,at,models=synthetic_elf();struct.pack_into('<I',blob,at(0x3200),0x3000)
        with self.assertRaisesRegex(ValueError,'First virtual method'):
            verify(blob,models,None)

    def test_literal_delta_mutation(self):
        blob,at,models=synthetic_elf();struct.pack_into('<I',blob,at(0x1168),0)
        with self.assertRaises((ValueError, UnicodeError)):
            verify(blob,models,None)


if __name__=='__main__':unittest.main()
