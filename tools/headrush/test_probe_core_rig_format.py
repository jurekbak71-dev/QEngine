import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from probe_core_rig_format import decode_candidate, diff_paths, inspect, validate_core_inner


def rig():
    return {'FootSwitch':{},'Pedal1':{},'Pedal2':{},'Pedal3':{},'Pedal4':{},
            'RigEncoder':{},'info':{'version':'5.0.0'},'data':{'Patch':{'children':{
                'Chain':{'children':{f'ModuleType{i}':{'string':'Empty'} for i in range(1,15)}},
                'AIR Delay':{'children':{'Mix':{'type':0,'value':5}}}
            }}}}


class RigFormatTests(unittest.TestCase):
    def test_decode_envelope(self):
        d=rig()
        kind,root,inner=decode_candidate(json.dumps({'content':json.dumps(d),'author':'test'}))
        self.assertEqual(kind,'envelope-string')
        self.assertEqual(inner,d)
        self.assertEqual(root['author'],'test')

    def test_factory_structure(self):
        self.assertEqual(validate_core_inner(rig())['module_type_slots'],list(range(1,15)))
        d=rig();del d['Pedal4']
        self.assertEqual(validate_core_inner(d)['missing_core_sections'],['Pedal4'])

    def test_diff_only_modified_parameter(self):
        original=rig()
        modified=json.loads(json.dumps(original))
        modified['data']['Patch']['children']['AIR Delay']['children']['Mix']['value']=20
        self.assertEqual(list(diff_paths(original,modified)),
                         ['/data/Patch/children/AIR Delay/children/Mix/value'])

    def test_reference_comparison_does_not_write_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'factory.db'
            with sqlite3.connect(db) as connection:
                connection.execute('create table rigs(id text,name text,content text)')
                connection.execute('insert into rigs values(?,?,?)',
                                   ('abc','Test Rig',json.dumps(rig())))
            file=Path(tmp)/'candidate.json'
            file.write_text(json.dumps(rig()),encoding='utf-8')
            result=inspect(db,file,'Test Rig')
            self.assertEqual(result['core_14_slot_count'],1)
            self.assertEqual(result['comparison']['difference_count'],0)
            self.assertEqual(result['candidate']['container_kind'],'inner-document')


if __name__=='__main__':
    unittest.main()
