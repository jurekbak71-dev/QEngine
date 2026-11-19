"""Synthetic regression tests for connector buffer layout and dirty marker."""
import struct
import unittest
from trace_spatial_parameter_buffer_writes import (
    static_evidence, METHOD_WORDS, SETTER_WORDS, CLEAR_WORDS, HELPER_WORDS,
    CONSTRUCTOR_INDEX_SITES, METHODS, SETTER_HELPER_CALL, SETTER_HELPER_TARGET,
    REFERENCE_COUNT_HELPER, FLAG_CONSUMER_WORDS, FLAG_CONSUMER_CALLS,
)

REGIONS = [
    ('text_a', 0x007A6800, 0x1000),
    ('text_b', 0x007D2000, 0x200),
    ('audio_processing', 0x007EF000, 0x2600),
    ('text_c', 0x00926000, 0x30000),
    ('text_d', 0x00CB2E00, 0x200),
    ('data_vtables', 0x02EB2900, 0x200),
]


def fixture():
    names=b'\0'+b''.join(name.encode()+b'\0' for name,_,_ in REGIONS)+b'shstrtab\0'
    offsets=[];file_off=0x100
    for name, va, size in REGIONS:
        offsets.append(file_off)
        file_off += size
    n_off=file_off; file_off+=len(names)
    sh_off=(file_off+3)&~3
    data=bytearray(sh_off+40*(len(REGIONS)+2))
    data[:6]=b'\x7fELF\x01\x01'
    struct.pack_into('<H',data,18,40)
    struct.pack_into('<I',data,32,sh_off)
    struct.pack_into('<HHH',data,46,40,len(REGIONS)+2,len(REGIONS)+1)
    data[n_off:n_off+len(names)]=names
    for i,((name,va,size),off) in enumerate(zip(REGIONS,offsets),1):
        struct.pack_into('<10I',data,sh_off+40*i,names.index(name.encode()),1,0,va,off,size,0,0,4,0)
    struct.pack_into('<10I',data,sh_off+40*(len(REGIONS)+1),names.index(b'shstrtab'),3,0,0,n_off,len(names),0,0,1,0)

    def at(va):
        for (_,start,size),off in zip(REGIONS,offsets):
            if start<=va<start+size:return off+va-start
        raise ValueError(hex(va))
    def put(va,word):struct.pack_into('<I',data,at(va),word)
    def bl(va,target):return 0xeb000000 | (((target-va-8)//4)&0xffffff)

    for table in (SETTER_WORDS,CLEAR_WORDS,HELPER_WORDS,FLAG_CONSUMER_WORDS):
        for va,word in table.items():put(va,word)
    put(SETTER_HELPER_CALL,bl(SETTER_HELPER_CALL,SETTER_HELPER_TARGET))
    for va,target in FLAG_CONSUMER_CALLS.items():put(va,bl(va,target))
    for name,method in METHODS.items():
        start=method['method_va']
        put(method['vtable_va'],start)
        for off,word in METHOD_WORDS.items():put(start+off,word)
        info=CONSTRUCTOR_INDEX_SITES[name]
        for field in ('source_load','object_stm','index_set','index_store'):
            va,word=info[field];put(va,word)
        va=info['refcount_call'];put(va,bl(va,REFERENCE_COUNT_HELPER))
    return data,at


class ParameterBufferWriteTests(unittest.TestCase):
    def test_three_known_indices_and_chain(self):
        raw,_=fixture()
        report=static_evidence(raw,expected_sha=None)
        self.assertEqual(report['verified_connectors'],3)
        self.assertEqual(report['method_opcode_checks'],75)
        self.assertEqual(report['constructor_opcode_checks'],15)
        self.assertEqual(report['upstream_opcode_checks'],15)
        self.assertEqual(report['flag_consumer_opcode_checks'],15)
        self.assertEqual({x['connector']:x['constructor_confirmed_index'] for x in report['connectors']},
                         {'ShimmerIntervalKind':0,'ChorusMultiVoiceKind':4,'ChorusMultiWaveformKind':7})

    def test_alt_bytes_written_and_dirty_marker(self):
        raw,_=fixture();out=static_evidence(raw,expected_sha=None)
        for item in out['connectors']:
            self.assertEqual(len(item['byte_writes']),4)
            self.assertEqual(item['flag_offset'],'0xB6C')
            self.assertEqual(item['entry_stride_bytes'],8)

    def test_method_memory_read_mutation(self):
        raw,at=fixture();raw[at(METHODS['ChorusMultiVoiceKind']['method_va']+0x7c)]=0
        with self.assertRaisesRegex(ValueError,'unexpected A32 opcode'):
            static_evidence(raw,expected_sha=None)

    def test_change_flag_mutation(self):
        raw,at=fixture();raw[at(METHODS['ShimmerIntervalKind']['method_va']+0x118)]=0
        with self.assertRaisesRegex(ValueError,'unexpected A32 opcode'):
            static_evidence(raw,expected_sha=None)

    def test_constructor_index_mutation(self):
        raw,at=fixture();raw[at(CONSTRUCTOR_INDEX_SITES['ChorusMultiWaveformKind']['index_set'][0])]=0
        with self.assertRaisesRegex(ValueError,'altered constructor index_set'):
            static_evidence(raw,expected_sha=None)

    def test_constructor_pointer_write_mutation(self):
        raw,at=fixture();raw[at(CONSTRUCTOR_INDEX_SITES['ShimmerIntervalKind']['object_stm'][0])]=0
        with self.assertRaisesRegex(ValueError,'altered constructor object_stm'):
            static_evidence(raw,expected_sha=None)

    def test_reference_count_helper_mutation(self):
        raw,at=fixture();raw[at(CONSTRUCTOR_INDEX_SITES['ChorusMultiVoiceKind']['refcount_call'])]=0
        with self.assertRaisesRegex(ValueError,'reference-count helper'):
            static_evidence(raw,expected_sha=None)

    def test_setter_target_mutation(self):
        raw,at=fixture();raw[at(SETTER_HELPER_CALL)]=0
        with self.assertRaisesRegex(ValueError,'Setter helper target changed'):
            static_evidence(raw,expected_sha=None)

    def test_clear_slot_mutation(self):
        raw,at=fixture();raw[at(0x7d2098)]=0
        with self.assertRaisesRegex(ValueError,'clear'):
            static_evidence(raw,expected_sha=None)

    def test_helper_virtual_call_mutation(self):
        raw,at=fixture();raw[at(0xcb2e94)]=0
        with self.assertRaisesRegex(ValueError,'getter_helper'):
            static_evidence(raw,expected_sha=None)

    def test_vtable_mutation(self):
        raw,at=fixture();raw[at(METHODS['ShimmerIntervalKind']['vtable_va'])]=0
        with self.assertRaisesRegex(ValueError,'First vtable method'):
            static_evidence(raw,expected_sha=None)

    def test_checksum_guard(self):
        raw,_=fixture()
        with self.assertRaisesRegex(ValueError,'SHA-256'):
            static_evidence(raw,expected_sha='0'*64)

    def test_audio_buffer_adjacent_flag_read(self):
        raw,_=fixture();report=static_evidence(raw,expected_sha=None)
        self.assertEqual(report['flag_consumer']['flag_read_va'],'0x007F0B48')
        self.assertEqual(report['flag_consumer']['neon_store_va'],'0x007F0D84')

    def test_audio_neon_opcode_mutation_rejected(self):
        raw,at=fixture();raw[at(0x7f0d84)]=0
        with self.assertRaisesRegex(ValueError,'flag consumer'):
            static_evidence(raw,expected_sha=None)

    def test_audio_processing_call_mutation_rejected(self):
        raw,at=fixture();raw[at(0x7f0df0)]=0
        with self.assertRaisesRegex(ValueError,'flag consumer'):
            static_evidence(raw,expected_sha=None)

    def test_invalid_elf(self):
        with self.assertRaisesRegex(ValueError,'ARM32'):
            static_evidence(b'garbage',expected_sha=None)


if __name__=='__main__': unittest.main()
