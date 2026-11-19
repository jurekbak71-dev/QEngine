#!/usr/bin/env python3
"""Compare Core 5.2.0 compiled control-path strings with stored rig parameters.

No conclusions about writable controls or valid ranges follow from strings.
Reads both inputs only; never calls firmware/device APIs.
"""
import argparse
import json
import re
import sqlite3
from pathlib import Path

MODELS = ('AIR Delay', 'AIR Reverb', 'Eleven Reverb', 'Shimmer',
          'Multi Chorus', 'AIR Flanger', 'Tape Echo', 'BBD Delay', 'Rotary')


def compare(elf, rig_docs, models=MODELS):
    result = {}
    for model in models:
        prefix = ('/Engine/Patch/' + model + '/').encode()
        pattern = re.compile(re.escape(prefix) + rb'[A-Za-z0-9_-]+')
        binary = sorted({match.group()[len(prefix):].decode('ascii')
                         for match in pattern.finditer(elf)})
        stored = set()
        represented = 0
        for rig in rig_docs:
            nodes = rig['data']['Patch']['children']
            for key, node in nodes.items():
                if key == model or (key.startswith(model+' ') and key[len(model)+1:].isdigit()):
                    represented += 1
                    stored.update(node.get('children', {}))
        both = sorted(stored.intersection(binary))
        result[model] = {
            'rig_instances': represented,
            'compiled_path_keys': binary,
            'stored_keys': sorted(stored),
            'both': both,
            'compiled_only': sorted(set(binary)-stored),
            'rig_only': sorted(stored-set(binary)),
        }
    return {'models': result, 'warning': (
        'String paths can refer to internal controls. Compiled-only does NOT '
        'mean hidden writable parameters. Rig-only does NOT mean unsupported.')}


def run(elf_path, db_path):
    with sqlite3.connect(Path(db_path).resolve().as_uri()+'?mode=ro&immutable=1',uri=True) as db:
        rigs = [json.loads(row[0]) for row in db.execute('select content from rigs')]
    return compare(Path(elf_path).read_bytes(), rigs)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evil',type=Path,required=True)
    p.add_argument('--db',type=Path,required=True)
    p.add_argument('--output',type=Path)
    a=p.parse_args()
    data=json.dumps(run(a.evil,a.db),indent=2,ensure_ascii=False)+'\n'
    if a.output:
        a.output.write_text(data,encoding='utf-8')
    else:
        print(data,end='')


if __name__=='__main__':
    main()
