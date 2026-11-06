# Shared helpers. Standard library only, on purpose: an audit tool a reviewer
# cannot install is an audit tool nobody runs.
import json, os, csv, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def path(*parts):
    return os.path.join(ROOT, *parts)


def load_json(rel, default=None):
    p = path(rel)
    if not os.path.exists(p):
        return default if default is not None else []
    with open(p, encoding='utf-8') as f:
        return json.load(f)


def save_json(rel, data):
    p = path(rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(data, f, indent=2)
    return p


def today():
    return datetime.date.today()


def days_since(value):
    # Whole days since an ISO date, or None when the field is unpopulated.
    if not value:
        return None
    try:
        d = datetime.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None
    return (today() - d).days


def write_csv(rel, rows, fieldnames):
    p = path(rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=fieldnames)
        wr.writeheader()
        for r in rows:
            wr.writerow(r)
    return p


def read_csv(rel):
    p = path(rel)
    if not os.path.exists(p):
        return []
    with open(p, encoding='utf-8') as f:
        return list(csv.DictReader(f))
