#!/usr/bin/env python3
"""Read-only inventory and experimental rig JSON patcher for factory HeadRush rigs.

Never writes the SQLite database or talks to hardware. Exported JSON has
NOT been validated as a device-importable rig. Observed values are not
manufacturer-approved parameter ranges.
"""
import argparse
import json
import sqlite3
from pathlib import Path

FAMILY_MODELS = {
    'reverb': ('AIR Reverb', 'Eleven Reverb', 'Spring Reverb', 'Spring Pro',
               'Shimmer', 'Party Verb', 'Ambi Verb', 'C-Verb'),
    'delay': ('AIR Delay', 'BBD Delay', 'Dyn Delay', 'Time Warp', 'Pitch Delay',
              'Reverse Delay', 'Tape Echo', 'Multi Delay', 'Grain Delay',
              'Reso Delay', 'M104 Analog Delay', 'Budda Samsara Delay'),
    'modulation': ('Chorus', 'C2 Chorus', 'C2 Bass Chorus', 'Multi Chorus',
                   'Dim Chorus', 'Flanger', 'AIR Flanger', 'Analog Flanger',
                   'Digital Flanger', 'Orange Phaser', 'Tron Phaser',
                   'Stone Phaser', 'Vibe Phaser', 'Square-Phase', 'Rotary',
                   'Tremolo', 'Tube Tremolo', 'Budda Karma Chorus'),
}


def read_rigs(db_path):
    uri = Path(db_path).resolve().as_uri() + '?mode=ro&immutable=1'
    connection = sqlite3.connect(uri, uri=True)
    try:
        tables = {row[0] for row in connection.execute(
            'select name from sqlite_master where type = ?', ('table',))}
        if 'rigs' not in tables:
            raise ValueError('database has no rigs table')
        rows = connection.execute(
            'select id, name, content from rigs order by name, id').fetchall()
    finally:
        connection.close()
    rigs = []
    for id_, name, content in rows:
        rig = json.loads(content)
        if not isinstance(rig, dict) or not isinstance(rig.get('data'), dict):
            raise ValueError(f'invalid rig content: {id_}')
        rigs.append((id_, name, rig))
    return rigs


def models_in_chain(rig):
    patch = rig['data']['Patch']['children']
    chain = patch['Chain']['children']
    return {value['string'] for key, value in chain.items()
            if key.startswith('ModuleType') and key[len('ModuleType'):].isdigit()
            and isinstance(value, dict) and isinstance(value.get('string'), str)}


def extract_values(model_node):
    result = {}
    for key, value in model_node.get('children', {}).items():
        if not isinstance(value, dict):
            continue
        if 'value' in value:
            result[key] = value['value']
        elif 'state' in value:
            result[key] = value['state']
        elif 'string' in value:
            result[key] = value['string']
    return result


def inspect(rigs):
    inventory = {}
    for family, labels in FAMILY_MODELS.items():
        records = []
        for label in labels:
            usages = []
            for id_, rig_name, rig in rigs:
                patch = rig['data']['Patch']['children']
                selected = models_in_chain(rig)
                matches = [(name, node) for name, node in patch.items()
                           if name == label or (name.startswith(label + ' ')
                           and name[len(label)+1:].isdigit())]
                for key, node in matches:
                    values = extract_values(node)
                    usages.append({'rig': rig_name, 'instance': key,
                                   'selected_in_chain': label in selected,
                                   'enabled': values.get('On'),
                                   'parameters': values})
            keys = sorted({k for row in usages for k in row['parameters']})
            records.append({'model': label, 'rig_instances': len(usages),
                            'enabled_instances': sum(u['enabled'] is True for u in usages),
                            'selected_in_chain': sum(u['selected_in_chain'] for u in usages),
                            'parameter_names': keys, 'instances': usages})
        inventory[family] = records
    return {'rig_count': len(rigs), 'families': inventory,
            'caution': ('Preset values are observations, not approved ranges. '
                        'JSON edits have not been validated for device import.')}


def patch_rig(rigs, rig_name, model, parameter, raw_value):
    matching = [(rid, name, rig) for rid, name, rig in rigs if name == rig_name]
    if len(matching) != 1:
        raise ValueError(f'expected one exact rig name, found {len(matching)}')
    if model not in {m for group in FAMILY_MODELS.values() for m in group}:
        raise ValueError('model not in spatial FX inventory')
    rig = json.loads(json.dumps(matching[0][2], ensure_ascii=False))
    if model not in models_in_chain(rig):
        raise ValueError('requested model is not selected in the rig chain')
    nodes = rig['data']['Patch']['children']
    if model not in nodes:
        raise ValueError('requested model node missing')
    entries = nodes[model]['children']
    if parameter not in entries:
        raise ValueError('parameter does not exist in this model instance')
    entry = entries[parameter]
    if ('value' in entry and isinstance(entry['value'], (int, float))
            and not isinstance(entry['value'], bool)):
        value = float(raw_value)
        if not (-1e10 < value < 1e10):
            raise ValueError('value must be finite and within parser safety bound')
        if isinstance(entry['value'], int):
            if not value.is_integer():
                raise ValueError('integer parameter requires an integer')
            value = int(value)
        key = 'value'
    elif 'state' in entry and isinstance(entry['state'], bool):
        if raw_value.lower() not in ('true', 'false'):
            raise ValueError('state must be true or false')
        value, key = raw_value.lower() == 'true', 'state'
    elif 'string' in entry and isinstance(entry['string'], str):
        if not raw_value or len(raw_value) > 256:
            raise ValueError('invalid string parameter length')
        value, key = raw_value, 'string'
    else:
        raise ValueError('unsupported existing parameter representation')
    before = entry[key]
    entry[key] = value
    return rig, {'rig': rig_name, 'model': model, 'parameter': parameter,
                 'before': before, 'after': value,
                 'format': 'experimental-json-not-verified-for-import'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--rig-name')
    parser.add_argument('--model')
    parser.add_argument('--parameter')
    parser.add_argument('--value')
    args = parser.parse_args()
    rigs = read_rigs(args.db)
    fields = (args.rig_name, args.model, args.parameter, args.value)
    if any(field is not None for field in fields):
        if any(field is None for field in fields):
            parser.error('editing requires --rig-name, --model, --parameter, --value')
        result, change = patch_rig(rigs, *fields)
    else:
        result, change = inspect(rigs), None
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                        encoding='utf-8')
    if change is not None:
        audit_path = args.out.with_name(args.out.name + '.audit.json')
        audit_path.write_text(json.dumps(change, ensure_ascii=False, indent=2) + '\n',
                              encoding='utf-8')
        print('Wrote experimental audit', audit_path)
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
