import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from verify_spatial_serialization_keys import (
    get_name, inspect_code, inspect_factory_db, CONSTRUCTOR_VA,
)


class SerializationKeyTests(unittest.TestCase):
    def setUp(self):
        self.data = bytearray(0x700)
        self.mapping = [
            {"type": 1, "offset": 0x100, "addr": 0x1000, "size": 0x300},
            {"type": 1, "offset": 0x500, "addr": 0x5000, "size": 0x100},
        ]
        self.data[0x520:0x525] = b"type\x00"
        struct.pack_into("<I", self.data, 0x120, 0xe59f1018)
        struct.pack_into("<I", self.data, 0x124, 0xe08f1001)
        struct.pack_into("<I", self.data, 0x140, 0x5020 - 0x102c)
        rel = (CONSTRUCTOR_VA - 0x1028 - 8) // 4
        struct.pack_into("<I", self.data, 0x128, 0xeb000000 | (rel & 0xffffff))
        self.sites = {"byte": (("type", 0x1020, 0x1024, 0x1028),)}

    def test_extract_literal_key_and_call(self):
        result = inspect_code(self.data, self.mapping, self.sites)
        self.assertEqual(result["matched_keys"], 1)
        self.assertEqual(result["matched_constructors"], 1)

    def test_changed_string_detected(self):
        self.data[0x520:0x524] = b"typo"
        self.assertEqual(inspect_code(self.data, self.mapping, self.sites)["matched_keys"], 0)

    def test_changed_constructor_detected(self):
        struct.pack_into("<I", self.data, 0x128, 0xeb000000)
        self.assertEqual(inspect_code(self.data, self.mapping, self.sites)["matched_constructors"], 0)

    def test_wrong_instruction_rejected(self):
        struct.pack_into("<I", self.data, 0x124, 0)
        with self.assertRaisesRegex(ValueError, "LDR/ADD"):
            get_name(self.data, self.mapping, 0x1020, 0x1024)

    def test_factory_db_state_value(self):
        document = {"data": {"Patch": {"children": {"AIR Delay": {"children": {
            "On": {"type": 1, "state": True},
            "Mix": {"type": 0, "value": 12},
        }}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.db"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE rigs(content TEXT)")
                db.execute("INSERT INTO rigs VALUES(?)", (json.dumps(document),))
            result = inspect_factory_db(path)
            self.assertEqual(result["air_delay_parameter_instances"],
                             {"state": 1, "value": 1, "mixed": 0})
            self.assertEqual(result["example_items"]["state"]["key"], "On")
            self.assertEqual(result["example_items"]["value"]["key"], "Mix")


if __name__ == "__main__":
    unittest.main()
