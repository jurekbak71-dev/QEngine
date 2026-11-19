import unittest
from probe_spatial_control_paths import compare


class ControlPathTests(unittest.TestCase):
    def test_path_and_preset_evidence_are_separate(self):
        elf = (b'/Engine/Patch/AIR Delay/Mix\x00'
               b'/Engine/Patch/AIR Delay/LFORate\x00'
               b'/Engine/Patch/AIR Delay/Mix\x00')
        rig={'data':{'Patch':{'children':{'AIR Delay':{'children':{
            'Mix':{'value':20},'Feedback':{'value':30}}}}}}}
        r=compare(elf,[rig],('AIR Delay',))['models']['AIR Delay']
        self.assertEqual(r['both'],['Mix'])
        self.assertEqual(r['compiled_only'],['LFORate'])
        self.assertEqual(r['rig_only'],['Feedback'])
        self.assertEqual(r['rig_instances'],1)

    def test_empty_model_has_no_evidence(self):
        rig={'data':{'Patch':{'children':{}}}}
        r=compare(b'', [rig], ('Shimmer',))['models']['Shimmer']
        self.assertEqual(r['stored_keys'],[])
        self.assertEqual(r['compiled_path_keys'],[])
        self.assertEqual(r['rig_instances'],0)

    def test_numbered_instances(self):
        rig={'data':{'Patch':{'children':{
            'Tape Echo 2':{'children':{'Wow':{'value':10}}}}}}}
        r=compare(b'', [rig], ('Tape Echo',))['models']['Tape Echo']
        self.assertEqual(r['rig_instances'],1)
        self.assertEqual(r['stored_keys'],['Wow'])


if __name__=='__main__':
    unittest.main()
