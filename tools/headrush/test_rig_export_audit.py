import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class RigExportAuditTests(unittest.TestCase):
    def test_cli_preserves_original_root_and_separates_audit(self):
        rig = {'info': {'version': '5.0.0'},
               'data': {'Patch': {'children': {
                   'Chain': {'children': {'ModuleType1': {'string': 'AIR Delay'}}},
                   'AIR Delay': {'children': {'Mix': {'type': 0, 'value': 10}}}
               }}}}
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'factory.db'
            dest = Path(d) / 'lab.json'
            conn = sqlite3.connect(source)
            conn.execute('create table rigs(id text, name text, content text)')
            conn.execute('insert into rigs values(?,?,?)',
                         ('id1','Test Rig',json.dumps(rig)))
            conn.commit()
            conn.close()
            app = Path(__file__).with_name('rig_spatial_lab.py')
            subprocess.run([sys.executable, str(app), '--db', str(source),
                            '--out', str(dest), '--rig-name', 'Test Rig',
                            '--model', 'AIR Delay', '--parameter', 'Mix',
                            '--value', '35'], check=True, capture_output=True)
            edited = json.loads(dest.read_text(encoding='utf-8'))
            audit = json.loads(Path(str(dest)+'.audit.json').read_text(encoding='utf-8'))
            self.assertEqual(set(edited), set(rig))
            self.assertEqual(edited['data']['Patch']['children']['AIR Delay']['children']['Mix']['value'],35)
            self.assertEqual(audit['before'],10)
            self.assertEqual(audit['after'],35)
            self.assertNotIn('lab_edit_metadata', edited)
            with sqlite3.connect(source) as check:
                original = json.loads(check.execute('select content from rigs').fetchone()[0])
            self.assertEqual(original,rig)


if __name__ == '__main__':
    unittest.main()
