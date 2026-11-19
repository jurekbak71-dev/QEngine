import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from rig_spatial_lab import read_rigs, inspect, patch_rig


def fixture():
    return {'data': {'Patch': {'children': {
        'Chain': {'children': {
            'ModuleType1': {'string': 'AIR Delay'},
            'ModuleType2': {'string': 'Eleven Reverb'}}},
        'AIR Delay': {'children': {
            'On': {'state': True},
            'Mix': {'type': 0, 'value': 18},
            'Delay': {'type': 4, 'string': '1/4'}}},
        'Eleven Reverb': {'children': {
            'Mode': {'type': 4, 'string': 'Arena'}}}
    }}}}


class RigsTest(unittest.TestCase):
    def setUp(self):
        self.rigs = [('id', 'Factory Rig', fixture())]

    def test_inventory(self):
        report = inspect(self.rigs)
        self.assertEqual(report['rig_count'], 1)
        delay = next(x for x in report['families']['delay']
                     if x['model'] == 'AIR Delay')
        self.assertEqual(delay['enabled_instances'], 1)
        self.assertIn('Mix', delay['parameter_names'])

    def test_json_copy_isolation(self):
        result, change = patch_rig(
            self.rigs, 'Factory Rig', 'AIR Delay', 'Mix', '32')
        self.assertEqual(
            result['data']['Patch']['children']['AIR Delay']['children']['Mix']['value'], 32)
        self.assertEqual(
            self.rigs[0][2]['data']['Patch']['children']['AIR Delay']['children']['Mix']['value'], 18)
        self.assertEqual(change['before'], 18)

    def test_string_edit(self):
        result, _ = patch_rig(
            self.rigs, 'Factory Rig', 'AIR Delay', 'Delay', '1/8')
        self.assertEqual(
            result['data']['Patch']['children']['AIR Delay']['children']['Delay']['string'], '1/8')

    def test_reject_model_not_in_chain(self):
        with self.assertRaisesRegex(ValueError, 'not selected'):
            patch_rig(self.rigs, 'Factory Rig', 'Chorus', 'Mix', '18')

    def test_reject_missing_parameter(self):
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            patch_rig(self.rigs, 'Factory Rig', 'AIR Delay', 'SecretDSPMode', '42')

    def test_reject_invalid_integer(self):
        with self.assertRaisesRegex(ValueError, 'integer'):
            patch_rig(self.rigs, 'Factory Rig', 'AIR Delay', 'Mix', '1.5')

    def test_read_sqlite_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'sample.db'
            conn = sqlite3.connect(database)
            conn.execute('create table rigs (id text, name text, content text)')
            conn.execute('insert into rigs values (?, ?, ?)',
                         ('id', 'Factory Rig', json.dumps(fixture())))
            conn.commit()
            conn.close()
            self.assertEqual(len(read_rigs(database)), 1)
            self.assertFalse((Path(directory) / 'sample.db-wal').exists())


if __name__ == '__main__':
    unittest.main()
