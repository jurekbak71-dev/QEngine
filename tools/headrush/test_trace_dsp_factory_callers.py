"""Synthetic unit tests for Core DSP factory incoming-edge verification."""
import struct
import unittest
from trace_dsp_factory_callers import analyze, decode_arm_b, decode_bl, direct_call_sites, section_ranges

BASE=0x00812500
FACTORY=0x00812570
SITES=(0x00812900,0x00812940,0x00812980)
TARGET=0x00812A40

def fixture():
    text_size=0x700;off=0x100
    labels=b'\0.text\0.shstrtab\0';name_off=0x900;shoff=0xA00
    blob=bytearray(0xB00)
    blob[:6]=b'\x7fELF\x01\x01';struct.pack_into('<H',blob,18,40)
    struct.pack_into('<I',blob,32,shoff)
    struct.pack_into('<HHH',blob,46,40,3,2)
    blob[name_off:name_off+len(labels)]=labels
    struct.pack_into('<10I',blob,shoff+40,1,1,0,BASE,off,text_size,0,0,4,0)
    struct.pack_into('<10I',blob,shoff+80,7,3,0,0,name_off,len(labels),0,0,1,0)
    def put(va,op):struct.pack_into('<I',blob,off+va-BASE,op)
    def bl(site,dest):return 0xeb000000|(((dest-site-8)//4)&0xffffff)
    def branch(site,dest):return 0xea000000|(((dest-site-8)//4)&0xffffff)
    put(0x8125A8,0xe350008a)
    put(0x8125AC,0x908ff100)
    put(0x8126E0,branch(0x8126E0,TARGET))
    expected={}; results={}
    for i,site in enumerate(SITES):
        selector=site-4
        expected[site]={'selector_va':selector,'selector_opcode':0xe3a0004b,
                        'provenance':'mov r0,#75'}
        put(selector,0xe3a0004b);put(site,bl(site,FACTORY))
        store=site+8;vcall=site+16
        put(store,0xe584023c+i*4)
        put(vcall,0xe5936050)
        results[site]={'store_va':store,'store_opcode':0xe584023c+i*4,
                       'vcall_load_va':vcall,'vcall_opcode':0xe5936050,
                       'slot_offset':0x23c+4*i}
    return blob,expected,results,put

def report(b,expected,results):
    return analyze(b,expected_sha=None,factory_va=FACTORY,
                   expected_sites=expected,results=results,
                   case_index=75,case_target=TARGET)

class FactoryCallerTests(unittest.TestCase):
    def test_verified_three_callers(self):
        b,e,r,_=fixture();out=report(b,e,r)
        self.assertEqual(out['direct_unconditional_bl_callers'],3)
        self.assertEqual(out['case_branch_target_va'],f'0x{TARGET:08X}')
        self.assertTrue(all(x['virtual_slot_index']==20 for x in out['caller_sites']))

    def test_unexpected_caller_rejected(self):
        b,e,r,put=fixture()
        put(0x812A00,0xeb000000|(((FACTORY-0x812A08)//4)&0xffffff))
        with self.assertRaisesRegex(ValueError,'caller sites'):
            report(b,e,r)

    def test_wrong_caller_target(self):
        b,e,r,put=fixture()
        put(SITES[1],0xeb000000)
        with self.assertRaisesRegex(ValueError,'caller sites'):
            report(b,e,r)

    def test_selector_guard(self):
        b,e,r,put=fixture()
        put(SITES[0]-4,0)
        with self.assertRaisesRegex(ValueError,'selector'):
            report(b,e,r)

    def test_result_store_guard(self):
        b,e,r,put=fixture()
        put(SITES[1]+8,0)
        with self.assertRaisesRegex(ValueError,'Result store'):
            report(b,e,r)

    def test_virtual_slot_guard(self):
        b,e,r,put=fixture()
        put(SITES[2]+16,0xe5936054)
        with self.assertRaisesRegex(ValueError,'vtable'):
            report(b,e,r)

    def test_jump_case_guard(self):
        b,e,r,put=fixture()
        put(0x8126e0,0xeafffffe)
        with self.assertRaisesRegex(ValueError,'case target'):
            report(b,e,r)

    def test_jump_dispatch_guard(self):
        b,e,r,put=fixture()
        put(0x8125ac,0)
        with self.assertRaisesRegex(ValueError,'dispatch'):
            report(b,e,r)

    def test_bad_elf(self):
        with self.assertRaisesRegex(ValueError,'ELF'):
            section_ranges(b'not-elf')

    def test_sha_guard(self):
        b,e,r,_=fixture()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            analyze(b,'0'*64,FACTORY,e,r,75,TARGET)

    def test_bl_decode_backward(self):
        self.assertEqual(decode_bl(0xebfffffe,0x1000),0x1000)
        self.assertIsNone(decode_bl(0xea000000,0x1000))
        self.assertEqual(decode_arm_b(0xeafffffe,0x1000),0x1000)

    def test_empty_text_has_no_calls(self):
        b,e,r,_=fixture();ranges=section_ranges(b)
        self.assertEqual(direct_call_sites(b,BASE,0x100,0x200,FACTORY),[])

if __name__=='__main__': unittest.main()
