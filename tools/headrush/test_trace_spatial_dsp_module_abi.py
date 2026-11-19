"""Synthetic ARM32 ELF regression tests for spatial DSPModule lifecycle slots."""
import struct
import unittest

from test_verify_spatial_factory_paths import synthetic_elf
from trace_spatial_dsp_module_abi import (
    inspect, immediate_r0, bl_target, ror32, ALLOCATOR, SLOT21_OPCODES,
)


def make_module_fixture():
    blob, at, names, _, _ = synthetic_elf()
    # Fake addresses lie inside fixture .text, which covers 0x00812570..0x00816770.
    vtable = names[84][0]
    slot20, slot21 = 0x00813000, 0x00813100
    allocation_load, allocation_bl = 0x00813040, 0x00813048
    struct.pack_into('<I', blob, at(vtable + 20 * 4), slot20)
    struct.pack_into('<I', blob, at(vtable + 21 * 4), slot21)
    struct.pack_into('<I', blob, at(allocation_load), 0xE3010118)  # MOVW r0, #4376
    instr = 0xEB000000 | (((ALLOCATOR-allocation_bl-8)//4) & 0xffffff)
    struct.pack_into('<I', blob, at(allocation_bl), instr)
    for i, opcode in enumerate(SLOT21_OPCODES):
        struct.pack_into('<I', blob, at(slot21+i*4), opcode)
    model = {'DemoDelay': {'vtable': vtable, 'slot20': slot20, 'slot21': slot21,
                           'allocation_load': allocation_load,
                           'allocation_bl': allocation_bl,
                           'expected_allocation': 4376}}
    return blob, at, model


class SpatialDSPModuleABITests(unittest.TestCase):
    def test_valid_slot20_and_slot21(self):
        data, _, ref = make_module_fixture()
        result = inspect(data, entries=ref, expected_sha=None)
        self.assertEqual(len(result['modules']), 1)
        self.assertEqual(result['modules'][0]['slot20_allocation_request_bytes'], 4376)
        self.assertEqual(result['modules'][0]['slot21_shared_words'], 13)

    def test_reject_mutated_vtable_slot20(self):
        data, at, ref = make_module_fixture()
        struct.pack_into('<I', data, at(ref['DemoDelay']['vtable']+20*4), 0)
        with self.assertRaisesRegex(ValueError, 'vtable slots'):
            inspect(data,entries=ref,expected_sha=None)

    def test_reject_mutated_vtable_slot21(self):
        data, at, ref = make_module_fixture()
        struct.pack_into('<I', data, at(ref['DemoDelay']['vtable']+21*4), 0)
        with self.assertRaisesRegex(ValueError, 'vtable slots'):
            inspect(data,entries=ref,expected_sha=None)

    def test_reject_changed_allocation(self):
        data, at, ref = make_module_fixture()
        struct.pack_into('<I', data, at(ref['DemoDelay']['allocation_load']), 0xE3010119)
        with self.assertRaisesRegex(ValueError, 'allocation size'):
            inspect(data,entries=ref,expected_sha=None)

    def test_reject_non_immediate_allocation(self):
        data, at, ref = make_module_fixture()
        struct.pack_into('<I', data, at(ref['DemoDelay']['allocation_load']), 0xE1A00001)
        with self.assertRaisesRegex(ValueError, 'immediate assignment'):
            inspect(data,entries=ref,expected_sha=None)

    def test_reject_changed_allocator_target(self):
        data, at, ref = make_module_fixture()
        pos = ref['DemoDelay']['allocation_bl']
        old = struct.unpack_from('<I',data,at(pos))[0]
        struct.pack_into('<I',data,at(pos),old + 1)
        with self.assertRaisesRegex(ValueError, 'allocation call'):
            inspect(data,entries=ref,expected_sha=None)

    def test_reject_non_branch_allocator(self):
        data, at, ref = make_module_fixture()
        struct.pack_into('<I',data,at(ref['DemoDelay']['allocation_bl']),0xE1A00000)
        with self.assertRaisesRegex(ValueError, 'unconditional A32 BL'):
            inspect(data,entries=ref,expected_sha=None)

    def test_reject_changed_slot21_body(self):
        data, at, ref = make_module_fixture()
        data[at(ref['DemoDelay']['slot21'] + 5*4)] ^= 1
        with self.assertRaisesRegex(ValueError, 'Slot 21 A32 body'):
            inspect(data,entries=ref,expected_sha=None)

    def test_reject_wrong_source_sha(self):
        data, _, ref = make_module_fixture()
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            inspect(data,entries=ref,expected_sha='0'*64)

    def test_decode_movw_for_allocation(self):
        self.assertEqual(immediate_r0(0xE3010118),4376)
        self.assertEqual(immediate_r0(0xE3020050),8272)

    def test_decode_rotated_mov_immediate(self):
        # Encoded MOV r0,#0xEC0 (3776) uses ARM's rotated 8-bit literal.
        self.assertEqual(immediate_r0(0xE3A00D3B),3776)

    def test_rotated_bit_math(self):
        self.assertEqual(ror32(0x3B,26), 3776)
        self.assertEqual(ror32(0x3B,0),0x3B)

    def test_reject_invalid_elf(self):
        with self.assertRaisesRegex(ValueError, 'ELF32'):
            inspect(b'bad data', entries={}, expected_sha=None)

    def test_branch_decode_backward(self):
        self.assertEqual(bl_target(0xEBFFFFFE,0x1000),0x1000)


if __name__ == '__main__':
    unittest.main()
