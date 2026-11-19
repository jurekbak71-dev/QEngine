#!/usr/bin/env python3
"""Read-only spatial parameter statistics from factory HeadRush SQLite rigs.

All ranges are observed examples, NOT device-accepted min/max constraints.
"""
import argparse
import collections
import json
import sqlite3
from pathlib import Path

MODELS = {
    'reverb': ('AIR Reverb','Eleven Reverb','Spring Reverb','Shimmer','Ambi Verb','C-Verb'),
    'delay': ('AIR Delay','BBD Delay','Dyn Delay','Tape Echo','Pitch Delay','Time Warp','Grain Delay'),
    'modulation': ('Multi Chorus','Chorus','AIR Flanger','Rotary','Flanger','Dim Chorus'),
}

def inspect(db_path):
    uri = Path(db_path).resolve().as_uri() + '?mode=ro&immutable=1'
    with sqlite3.connect(uri, uri=True) as connection:
        rows = connection.execute('SELECT name,content FROM rigs').fetchall()
    values = collections.defaultdict(lambda: collections.defaultdict(list))
    unique_versions = set()
    format_checks = collections.Counter()
    for rig_name, content in rows:
        rig = json.loads(content)
        unique_versions.add(rig.get('info', {}).get('version'))
        patch = rig['data']['Patch']['children']
        chain = patch['Chain']['children']
        selected = {v['string'] for k,v in chain.items() if k.startswith('ModuleType')
                    and k[10:].isdigit() and isinstance(v,dict) and 'string' in v}
        format_checks['has_extended_core_root'] += all(k in rig for k in ('FootSwitch','Pedal3','Pedal4','RigEncoder','data','info'))
        format_checks['chain_14_slots'] += all(f'ModuleType{i}' in chain for i in range(1,15))
        for family, models in MODELS.items():
            for name, node in patch.items():
                base = next((m for m in models if name == m or
                             (name.startswith(m+' ') and name[len(m)+1:].isdigit())), None)
                if base is None or base not in selected:
                    continue
                for key, item in node.get('children',{}).items():
                    typ = item.get('type')
                    if typ == 0 and isinstance(item.get('value'),(int,float)) and not isinstance(item.get('value'),bool):
                        value = item['value']
                    elif typ in (1,3) and isinstance(item.get('state'),bool):
                        value = item['state']
                    elif typ in (4,8) and isinstance(item.get('string'),str):
                        value = item['string']
                    else:
                        continue
                    values[(family,base)][key].append(value)
    report = {'rig_count':len(rows), 'versions':sorted(str(x) for x in unique_versions),
              'structure':dict(format_checks), 'families':{},
              'warning':'observed preset values ARE NOT valid hardware or algorithm bounds'}
    for (family,model), params in sorted(values.items()):
        result = {}
        for key, records in sorted(params.items()):
            if records and all(type(v) in (float,int) for v in records):
                result[key] = {'kind':'number','samples':len(records),'observed_min':min(records),
                               'observed_max':max(records),'distinct':len(set(records))}
            else:
                result[key] = {'kind':'state' if all(type(v) is bool for v in records) else 'choice',
                               'samples':len(records),'observed_values':sorted(set(records),key=str)}
        report['families'].setdefault(family,{})[model]=result
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(inspect(a.db),indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

if __name__=='__main__':
    main()
