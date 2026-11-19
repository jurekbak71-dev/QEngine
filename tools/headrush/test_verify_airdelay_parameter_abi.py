import unittest
from unittest.mock import patch
from verify_airdelay_parameter_abi import validate, BYTE_CALLEE, FLOAT_CALLEE


def run_case(name, call_target, length, read_opcode):
    row = {"path": name, "call_va": 0xA11F38, "destination_va": call_target,
           "stack_slots": {"4": {"value_bits": length}, "8": {"value_bits": 123}}}
    if call_target == BYTE_CALLEE:
        ops = {0x014CDA34: 0xE1A08003, 0x014CDB60: read_opcode}
    else:
        ops = {0x014CD148: 0xE1A08003, 0x014CD264: read_opcode}
    ops[0xA11F30] = 0xE1A03006
    with patch("verify_airdelay_parameter_abi.sections", return_value=[]), patch(
         "verify_airdelay_parameter_abi.word",
         side_effect=lambda blob, sec, va: ops.get(va, 0)):
        return validate(b"", {"rows": [row]})


class ParameterABITests(unittest.TestCase):
    def test_boolean_byte_load(self):
        name = "/Engine/Patch/AIR Delay/HPFdbk"
        result = run_case(name, BYTE_CALLEE, len(name), 0xE5D83000)
        self.assertEqual(result["name_lengths_matched"], 1)
        self.assertEqual(result["valid_callee_read_patterns"], 1)
        self.assertEqual(result["results"][0]["value_load_kind"], "byte")

    def test_float32_load(self):
        name = "/Engine/Patch/AIR Delay/LFORate"
        result = run_case(name, FLOAT_CALLEE, len(name), 0xEDD87A00)
        self.assertEqual(result["valid_callee_read_patterns"], 1)
        self.assertEqual(result["results"][0]["value_load_kind"], "float32")

    def test_wrong_length_detected(self):
        result = run_case("/Engine/Patch/AIR Delay/LFORate", FLOAT_CALLEE, 99, 0xEDD87A00)
        self.assertEqual(result["name_lengths_matched"], 0)

    def test_wrong_opcode_detected(self):
        name = "/Engine/Patch/AIR Delay/LFORate"
        result = run_case(name, FLOAT_CALLEE, len(name), 0xE5D83000)
        self.assertEqual(result["valid_callee_read_patterns"], 0)

    def test_empty_input(self):
        with patch("verify_airdelay_parameter_abi.sections", return_value=[]):
            with self.assertRaisesRegex(ValueError, "No AIR Delay calls"):
                validate(b"", {"rows": []})


if __name__ == "__main__":
    unittest.main()
