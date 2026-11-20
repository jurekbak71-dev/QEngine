"""Synthetic tests of read-only DSPModule -> inner method load-chain detector."""
import struct
import unittest
from probe_module_inner_dispatch import inspect, ldr_immediate, parse, find_chain, SLOTS


def make_elf():
    data=bytearray(0x8000)
    data[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',data,18,40)
    struct.pack_into('<I',data,32,0x7E00)
    struct.pack_into('<HHH',data,46,40,4,3)
    names=b'\0.text\0.data.rel.ro.local\0.shstrtab\0'
    data[0x7D00:0x7D00+len(names)]=names
    for idx,name,va,off,size,typ in [
        (1,b'.text',0x1000,0x100,0x2000,1),
        (2,b'.data.rel.ro.local',0x4000,0x2200,0x800,1),
        (3,b'.shstrtab',0,0x7D00,len(names),3),
    ]:
        struct.pack_into('<10I',data,0x7E00+idx*40,names.index(name),typ,0,va,off,size,0,0,4,0)
    def off(address):
        if 0x1000<=address<0x3000:return 0x100+address-0x1000
        if 0x4000<=address<0x4800:return 0x2200+address-0x4000
        raise ValueError(hex(address))
    def word(addr,value):struct.pack_into('<I',data,off(addr),value)
    tables={'AIRDelay':0x4000,'Shimmer':0x4200,'MultiChorus':0x4400}
    for mi,(name,vt) in enumerate(tables.items()):
        for si,(slot,(field,offset)) in enumerate(SLOTS.items()):
            fn=0x1100+mi*0x600+si*0x50
            word(vt+4*slot,fn)
            for j in range(17):word(fn+j*4,0xE1A00000)
            word(fn,0xE5900000|field)
            word(fn+4,0xE5903000)
            word(fn+8,0xE5933000|offset)
            word(fn+12,0xE12FFF13)
    return data,off,tables


class DSPModuleInnerDispatchTests(unittest.TestCase):
    def test_all_three_models_verified(self):
        data,_,tables=make_elf()
        report=inspect(data,vtables=tables,expected_sha=None)
        self.assertEqual(report['verified_slots_per_model'],17)
        self.assertEqual(report['verified_load_chains'],51)
        self.assertEqual(report['models']['AIRDelay'][0]['inner_vtable_slot'],3)
        self.assertEqual(report['models']['Shimmer'][-1]['inner_vtable_slot'],28)

    def test_reject_wrong_source_checksum(self):
        data,_,tables=make_elf()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            inspect(data,vtables=tables,expected_sha='0'*64)

    def test_reject_wrong_wrapper_field(self):
        data,off,tables=make_elf()
        first=struct.unpack_from('<I',data,off(tables['AIRDelay']+3*4))[0]
        struct.pack_into('<I',data,off(first),0xE5900050)
        with self.assertRaisesRegex(ValueError,'No verified'):
            inspect(data,vtables=tables,expected_sha=None)

    def test_reject_changed_vtable_offset(self):
        data,off,tables=make_elf()
        fn=struct.unpack_from('<I',data,off(tables['Shimmer']+18*4))[0]
        struct.pack_into('<I',data,off(fn+8),0xE593304C)
        with self.assertRaisesRegex(ValueError,'No verified'):
            inspect(data,vtables=tables,expected_sha=None)

    def test_reject_non_executable_vtable(self):
        data,off,tables=make_elf()
        struct.pack_into('<I',data,off(tables['MultiChorus']+25*4),0x4000)
        with self.assertRaisesRegex(ValueError,'not executable'):
            inspect(data,vtables=tables,expected_sha=None)

    def test_reject_broken_intermediate_register(self):
        data,off,tables=make_elf()
        fn=struct.unpack_from('<I',data,off(tables['AIRDelay']+5*4))[0]
        struct.pack_into('<I',data,off(fn+4),0xE5913000)
        with self.assertRaisesRegex(ValueError,'No verified'):
            inspect(data,vtables=tables,expected_sha=None)

    def test_delegation_can_use_different_registers(self):
        data,off,tables=make_elf()
        fn=struct.unpack_from('<I',data,off(tables['AIRDelay']+3*4))[0]
        struct.pack_into('<I',data,off(fn),0xE5905040)
        struct.pack_into('<I',data,off(fn+4),0xE595C000)
        struct.pack_into('<I',data,off(fn+8),0xE59CE00C)
        sec=parse(data)
        row=find_chain(data,sec,fn,0x40,12)
        self.assertEqual(row['method_register'],'r14')

    def test_load_decoder_rejects_store(self):
        self.assertIsNone(ldr_immediate(0xE5803000))
        self.assertIsNone(ldr_immediate(0x05903014))
        self.assertEqual(ldr_immediate(0xE5933020),(3,3,32))

    def test_invalid_file(self):
        with self.assertRaisesRegex(ValueError,'ELF32'):
            inspect(b'garbage',vtables={},expected_sha=None)

    def test_reject_when_executable_bytes_are_modified(self):
        data,off,tables=make_elf()
        fn=struct.unpack_from('<I',data,off(tables['MultiChorus']+21*4))[0]
        struct.pack_into('<I',data,off(fn+8),0xE5933048)
        with self.assertRaisesRegex(ValueError,'No verified'):
            inspect(data,vtables=tables,expected_sha=None)


if __name__=='__main__': unittest.main()
