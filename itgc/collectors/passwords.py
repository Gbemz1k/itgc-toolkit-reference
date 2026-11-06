# Credential reuse testing WITHOUT storing credentials.
#
# Auditor note: the control objective is "credentials are unique per system".
# That objective can be satisfied with hashes alone, so this tool never writes
# a plaintext password to disk. The decision is deliberate, and it is the kind
# of thing an interviewer will ask you to defend.
import csv
import hashlib
import collections
from ..util import save_json


def _h(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def run(csv_path):
    # Accepts a Chrome/Edge password export: columns name,url,username,password
    rows = []
    with open(csv_path, encoding='utf-8', errors='ignore') as f:
        for r in csv.DictReader(f):
            pw = (r.get('password') or '').strip()
            if not pw:
                continue
            rows.append({
                'site': (r.get('name') or r.get('url') or '').strip(),
                'username': (r.get('username') or '').strip(),
                'hash': _h(pw),
                'length': len(pw),
            })

    groups = collections.defaultdict(list)
    for r in rows:
        groups[r['hash']].append(r)

    reused = []
    for h, members in groups.items():
        sites = sorted({m['site'] for m in members if m['site']})
        if len(sites) > 1:
            reused.append({
                'hash_prefix': h[:12],
                'system_count': len(sites),
                'systems': sites,
            })

    result = {
        'population': len(rows),
        'distinct_credentials': len(groups),
        'reused_groups': sorted(reused, key=lambda x: -x['system_count']),
        'short_credentials': sum(1 for r in rows if r['length'] < 12),
    }
    save_json('evidence/password_analysis.json', result)
    return result
