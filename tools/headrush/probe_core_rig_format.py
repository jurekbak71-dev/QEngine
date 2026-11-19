#!/usr/bin/env python3
"""Offline, read-only structural validator of a HeadRush Core rig candidate.

It compares a native export candidate (if available) with bundled Core
factory rig documents. No device I/O, no firmware modification, no export.
"""
import argparse
import collections
import hashlib
import json
import sqlite3
from pathlib import Path


def decode_candidate(raw):
    root = json.loads(raw)
    if not isinstance(root, dict):
        raise ValueError('root must be a JSON object')
    if isinstance(root.get('content'), str):
        inner = json.loads(root['content'])
        kind = 'envelope-string'
    elif isinstance(root.get('content'), dict):
        inner = root['content']
        kind = 'envelope-object'
    else:
        inner = root
        kind = 'inner-document'
    if not isinstance(inner, dict):
        raise ValueError('inner rig must be a JSON object')
    return kind, root, inner


def validate_core_inner(inner):
    if not isinstance(inner, dict):
        raise ValueError('rig must be a JSON object')
    sections = ('FootSwitch', 'Pedal1', 'Pedal2', 'Pedal3',
                'Pedal4', 'RigEncoder', 'data', 'info')
    missing = sorted(set(sections) - set(inner))
    errors = []
    try:
        patch = inner['data']['Patch']['children']
        chain = patch['Chain']['children']
        slots = sorted(int(key[10:]) for key in chain
                       if key.startswith('ModuleType') and key[10:].isdigit())
        if slots != list(range(1, 15)):
            errors.append('expected 14 consecutive ModuleType slots, got '+str(slots))
    except (KeyError, TypeError):
        slots = []
        errors.append('missing Patch/Chain/children')
    return {'core_factory_section_match': not missing,
            'missing_core_sections': missing, 'module_type_slots': slots,
            'schema_errors': errors,
            'version': inner.get('info', {}).get('version') if isinstance(inner.get('info'), dict) else None,
            'top_level_sections': sorted(inner)}


def read_reference_rigs(path):
    uri = Path(path).resolve().as_uri() + '?mode=ro&immutable=1'
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute('SELECT id,name,content FROM rigs ORDER BY id').fetchall()
    return [(identifier, name, json.loads(content)) for identifier, name, content in rows]


def diff_paths(before, after, prefix=''):
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys()):
            keypath = prefix + '/' + key.replace('~', '~0').replace('/', '~1')
            if key not in before or key not in after:
                yield keypath
            else:
                yield from diff_paths(before[key], after[key], keypath)
    elif isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            yield prefix + '/length'
        for index, (left, right) in enumerate(zip(before, after)):
            yield from diff_paths(left, right, prefix + '/' + str(index))
    elif type(before) is not type(after) or before != after:
        yield prefix or '/'


def inspect(reference_db, candidate_path=None, compare_to=None):
    factory = read_reference_rigs(reference_db)
    schemas = [validate_core_inner(doc) for _, _, doc in factory]
    report = {
        'reference_count': len(factory),
        'core_14_slot_count': sum(x['module_type_slots'] == list(range(1, 15)) for x in schemas),
        'factory_versions': dict(collections.Counter(str(s['version']) for s in schemas)),
        'factory_top_sections': [list(group) for group in sorted(set(tuple(s['top_level_sections']) for s in schemas))],
        'warnings': [
            'A schema match is not proof of a Core-compatible .rig export.',
            'Import is not tested. This tool does not generate a device file.',
        ],
    }
    if candidate_path:
        kind, root, inner = decode_candidate(Path(candidate_path).read_text(encoding='utf-8'))
        report['candidate'] = {
            'source': str(candidate_path), 'container_kind': kind,
            'outer_keys': sorted(root) if kind != 'inner-document' else None,
            'inner': validate_core_inner(inner),
            'sha256': hashlib.sha256(Path(candidate_path).read_bytes()).hexdigest(),
        }
        if compare_to:
            originals = [(name, document) for _, name, document in factory if name == compare_to]
            if len(originals) != 1:
                raise ValueError('reference rig name is absent or ambiguous')
            changed = list(diff_paths(originals[0][1], inner))
            report['comparison'] = {
                'reference_rig_name': compare_to,
                'difference_count': len(changed),
                'different_json_paths': changed,
                'note': 'Structural comparison only; changes are not device-validated.',
            }
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db', type=Path, required=True)
    p.add_argument('--candidate', type=Path)
    p.add_argument('--compare-to', help='Exact factory rig name')
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    if a.compare_to and not a.candidate:
        p.error('--compare-to requires --candidate')
    report = inspect(a.db, a.candidate, a.compare_to)
    result = json.dumps(report, indent=2, ensure_ascii=False) + '\n'
    if a.output:
        a.output.write_text(result, encoding='utf-8')
    else:
        print(result, end='')


if __name__ == '__main__':
    main()
