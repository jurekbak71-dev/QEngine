import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from analyze_spatial_parameters import inspect

class SpatialParameterTests(unittest.TestCase):
    def test_observed_values_are_not_ranges(self):
        rig={'info':{'version':'5.0.0'},'data':{'Patch':{'children':{
          'Chain':{'children':{**{f'ModuleType{i}':{'string':'Empty'} for i in range(1,15)},'ModuleType1':{'string':'AIR Delay'}}},
          'AIR Delay':{'children':{'Mix':{'type':0,'value':30},'On':{'type':1,'state':True},'Mode':{'type':4,'string':'Ping Pong'}}}}}}}
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'rigs.db'
            con=sqlite3.connect(db)
            con.execute('create table rigs(name text, content text)')
            con.execute('insert into rigs values(?,?)',('demo',json.dumps(rig)))
            con.commit();con.close()
            result=inspect(db)
            self.assertEqual(result['rig_count'],1)
            mix=result['families']['delay']['AIR Delay']['Mix']
            self.assertEqual((mix['observed_min'],mix['observed_max']),(30,30))
            self.assertEqual(result['families']['delay']['AIR Delay']['On']['observed_values'],[True])
            self.assertEqual(result['structure']['chain_14_slots'],1)
    def test_missing_table(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'empty.db'
            con=sqlite3.connect(db);con.execute('create table x(a text)');con.close()
            with self.assertRaises(sqlite3.OperationalError): inspect(db)

if __name__=='__main__': unittest.main()
