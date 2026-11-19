"""Synthetic ELF regression tests for connector method instruction comparison."""
import hashlib
import struct
import unittest

from compare_spatial_connector_methods import analyze, decode_arm_bl, reg_blx


def make_fixture():
    blob=bytearray(0x1c00)
    blob[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',blob,18,40)
    struct.pack_into('<I',blob,32,0x1a00)
    struct.pack_into('<HHH',blob,46,40,5,4)
    names=b'\0.text\0.data.rel.ro.local\0.ARM.exidx\0.shstrtab\0'
    blob[0x1900:0x1900+len(names)]=names
    for i,name,typ,va,off,size in [
        (1,b'.text',1,0x1000,0x100,0x1200),
        (2,b'.data.rel.ro.local',1,0x3000,0x1700,0x100),
        (3,b'.ARM.exidx',0x70000001,0x4000,0x1800,0x20),
        (4,b'.shstrtab',3,0,0x1900,len(names))]:
        struct.pack_into('<10I',blob,0x1a00+i*40,names.index(name),typ,0,va,off,size,0,0,4,0)
    starts=[0x1000,0x13a8,0x1750]
    ends=starts[1:]+[0x1af8]
    methods={}
    for i,(start,end) in enumerate(zip(starts,ends)):
        methods[f'connector{i}']={'method_va':start,'end_va':end,'vtable_va':0x3000+i*4}
        struct.pack_into('<I',blob,0x1700+i*4,start)
        for off in range(0,0x338,4):
            word=0xe1a00000
            if off in (0xdc,0x1a0):
                delta=((0x1e00-(start+off+8))//4)&0xffffff
                word=0xeb000000|delta
            elif off in (0x4c,0xb8,0x17c):word=0xe12fff33
            elif off==0x74:word=0xe12fff31
            struct.pack_into('<I',blob,0x100+start-0x1000+off,word)
        for k in range(28):
            value=2 if k==0 else 0 if k==1 else (0x12000 if k<7 else i*10000+k)
            struct.pack_into('<I',blob,0x100+start-0x1000+0x338+4*k,value)
    for i,start in enumerate(starts+[ends[-1]]):
        place=0x4000+8*i
        struct.pack_into('<II',blob,0x1800+8*i,(start-place)&0x7fffffff,1)
    return blob,methods


def scan(raw,methods):
    return analyze(raw,methods,expected_sha=None,expected_bl=2)

class ConnectorMethodEquivalenceTests(unittest.TestCase):
    def test_three_clone_templates(self):
        raw,methods=make_fixture();r=scan(raw,methods)
        self.assertEqual(r['identical_instruction_words'],204)
        self.assertEqual(r['relocated_bl_instruction_words'],2)
        self.assertEqual([x['target_va'] for x in r['shared_direct_call_targets']],['0x00001E00']*2)
        self.assertEqual(r['literal_pool_words_per_method'],28)
        self.assertEqual(r['literal_pool_words_identical'],7)
        self.assertEqual(r['literal_pool_words_different'],21)
        self.assertEqual(len(r['blx_register_sites']),4)

    def test_mismatched_non_branch_instruction_rejected(self):
        raw,methods=make_fixture();start=methods['connector1']['method_va']
        struct.pack_into('<I',raw,0x100+start-0x1000+0x90,0xe1a01000)
        with self.assertRaisesRegex(ValueError,'Non-relocation'):
            scan(raw,methods)

    def test_mismatched_call_destination_rejected(self):
        raw,methods=make_fixture();start=methods['connector1']['method_va']
        off=0xdc
        struct.pack_into('<I',raw,0x100+start-0x1000+off,
                         0xeb000000|(((0x1e04-start-off-8)//4)&0xffffff))
        with self.assertRaisesRegex(ValueError,'Non-relocation'):
            scan(raw,methods)

    def test_identical_bl_opcode_with_different_targets_rejected(self):
        raw,methods=make_fixture()
        reference=methods['connector0']['method_va']
        reference_op=struct.unpack_from('<I',raw,0x100+reference-0x1000+0xdc)[0]
        for entry in list(methods.values())[1:]:
            start=entry['method_va']
            struct.pack_into('<I',raw,0x100+start-0x1000+0xdc,reference_op)
        with self.assertRaisesRegex(ValueError,'Identical BL encodings'):
            scan(raw,methods)

    def test_modified_vtable_rejected(self):
        raw,methods=make_fixture();struct.pack_into('<I',raw,0x1704,0x12345678)
        with self.assertRaisesRegex(ValueError,'Vtable'):
            scan(raw,methods)

    def test_bad_sha_rejected(self):
        raw,methods=make_fixture()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            analyze(raw,methods,expected_sha='0'*64,expected_bl=2)

    def test_literal_pool_difference_is_expected(self):
        raw,methods=make_fixture()
        start=methods['connector2']['method_va']
        struct.pack_into('<I',raw,0x100+start-0x1000+0x354,0xffabcdef)
        r=scan(raw,methods)
        self.assertEqual(r['literal_pool_words_different'],21)

    def test_corrupt_blx_pattern_rejected(self):
        raw,methods=make_fixture();start=methods['connector2']['method_va']
        struct.pack_into('<I',raw,0x100+start-0x1000+0x74,0xe12fff33)
        with self.assertRaisesRegex(ValueError,'BLX signature'):
            scan(raw,methods)

    def test_literal_pool_marker_rejected(self):
        raw,methods=make_fixture();start=methods['connector0']['method_va']
        struct.pack_into('<I',raw,0x100+start-0x1000+0x338,3)
        with self.assertRaisesRegex(ValueError,'boundary'):
            scan(raw,methods)

    def test_undocumented_exidx_end_rejected(self):
        raw,methods=make_fixture();methods['connector0']['end_va']+=4
        with self.assertRaisesRegex(ValueError,'Unwind'):
            scan(raw,methods)

    def test_invalid_elf_rejected(self):
        raw,methods=make_fixture()
        with self.assertRaisesRegex(ValueError,'ELF'):
            scan(b'bad',methods)

    def test_branch_decode_and_blx(self):
        self.assertEqual(decode_arm_bl(0xebfffffe,0x1000),0x1000)
        self.assertIsNone(decode_arm_bl(0xe1a00000,0x1000))
        self.assertEqual(reg_blx(0xe12fff31),1)
        self.assertIsNone(reg_blx(0xe12fff13))

    def test_call_count_guard(self):
        raw,methods=make_fixture()
        with self.assertRaisesRegex(ValueError,'relocated BL'):
            analyze(raw,methods,expected_sha=None,expected_bl=3)


if __name__=='__main__':unittest.main()
