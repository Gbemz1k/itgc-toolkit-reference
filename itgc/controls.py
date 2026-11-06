# The control tests. One function per control id in controls/control-matrix.csv.
# Each returns (population_size, [exception dicts]).
#
# Design rule: every test runs over the FULL population, never a sample.
# That is the whole argument for testing controls in code.
from .util import load_json, days_since

DORMANT_DAYS = 180
RECOVERY_VERIFY_DAYS = 365
SESSION_STALE_DAYS = 180
RESTORE_DAYS = 365
SIGNATURE_MAX_AGE_DAYS = 7
SENSITIVE_SCOPES = ('gmail', 'drive', 'mail.google', 'contacts', 'calendar',
                    'admin', 'spreadsheets', 'documents', 'photos', 'unknown')


def _accounts():
    return load_json('inventory/accounts.json', [])


def _systems():
    return load_json('inventory/systems.json', [])


def _repos():
    return load_json('evidence/github_repos.json', [])


def _workstation():
    return load_json('evidence/workstation.json', {})


# --- Access to Programs and Data -------------------------------------------

def ac01():
    pop = _accounts()
    exc = []
    for a in pop:
        missing = [f for f in ('system', 'identifier', 'owner', 'last_used') if not a.get(f)]
        if missing:
            exc.append({'item': a.get('account_id'),
                        'detail': 'incomplete inventory record, missing: ' + ', '.join(missing)})
    return len(pop), exc


def ac02():
    pop = _accounts()
    exc = []
    for a in pop:
        d = days_since(a.get('last_used'))
        if d is not None and d > DORMANT_DAYS:
            exc.append({'item': a.get('account_id'),
                        'detail': str(a.get('system')) + ' dormant for ' + str(d) + ' days'})
    return len(pop), exc


def ac03():
    pop = [a for a in _accounts() if a.get('admin')]
    exc = []
    for a in pop:
        if not (a.get('admin_justification') or '').strip():
            exc.append({'item': a.get('account_id'),
                        'detail': 'admin rights on ' + str(a.get('system')) + ' with no documented justification'})
    return len(pop), exc


def ac04():
    dep = [d.lower() for d in load_json('inventory/deprecated_identifiers.json', [])]
    pop = _accounts()
    exc = []
    for a in pop:
        ident = (a.get('identifier') or '').lower()
        if ident and any(d in ident for d in dep):
            exc.append({'item': a.get('account_id'),
                        'detail': 'deprecated identifier still active: ' + ident})
    return len(pop), exc


def ac05():
    recovery = {r.get('system'): r for r in load_json('inventory/recovery.json', [])}
    pop = [a for a in _accounts() if a.get('criticality') in ('High', 'Medium')]
    exc = []
    for a in pop:
        r = recovery.get(a.get('system'))
        if not r:
            exc.append({'item': a.get('account_id'),
                        'detail': 'no recovery method recorded for ' + str(a.get('system'))})
            continue
        if not (r.get('recovery_email') or r.get('recovery_phone')):
            exc.append({'item': a.get('account_id'),
                        'detail': 'recovery record exists but no method populated'})
        elif r.get('owned_by_account_holder') is not True:
            exc.append({'item': a.get('account_id'),
                        'detail': 'recovery method not confirmed as owned by the account holder'})
        else:
            d = days_since(r.get('last_verified'))
            if d is None or d > RECOVERY_VERIFY_DAYS:
                exc.append({'item': a.get('account_id'),
                            'detail': 'recovery method not verified within ' + str(RECOVERY_VERIFY_DAYS) + ' days'})
    return len(pop), exc


def ac06():
    pop = load_json('inventory/sessions.json', [])
    exc = []
    for s in pop:
        if s.get('recognised') is not True:
            exc.append({'item': str(s.get('system')) + ' / ' + str(s.get('device')),
                        'detail': 'active session on an unrecognised device'})
            continue
        d = days_since(s.get('last_seen'))
        if d is not None and d > SESSION_STALE_DAYS:
            exc.append({'item': str(s.get('system')) + ' / ' + str(s.get('device')),
                        'detail': 'trusted device not seen for ' + str(d) + ' days'})
    return len(pop), exc


def au01():
    pop = [a for a in _accounts() if a.get('external_facing')]
    exc = []
    for a in pop:
        if a.get('mfa') is not True:
            exc.append({'item': a.get('account_id'),
                        'detail': 'MFA not enabled on ' + str(a.get('system'))})
    return len(pop), exc


def au02():
    data = load_json('evidence/password_analysis.json', {})
    pop = data.get('population', 0) if isinstance(data, dict) else 0
    exc = []
    for g in (data.get('reused_groups', []) if isinstance(data, dict) else []):
        exc.append({'item': 'hash:' + g['hash_prefix'],
                    'detail': 'credential reused across ' + str(g['system_count'])
                              + ' systems: ' + ', '.join(g['systems'][:6])})
    return pop, exc


def tp01():
    pop = load_json('inventory/oauth_grants.json', [])
    exc = []
    for g in pop:
        scopes = ' '.join(g.get('scopes') or []).lower()
        sensitive = any(s in scopes for s in SENSITIVE_SCOPES)
        if sensitive and (not (g.get('business_reason') or '').strip() or not g.get('last_reviewed')):
            exc.append({'item': g.get('grant_id'),
                        'detail': str(g.get('application')) + ' holds sensitive scopes without a documented reason or review date'})
    return len(pop), exc


# --- Program Changes --------------------------------------------------------

def _testable(field):
    # A repository whose configuration could not be read is excluded from the
    # population rather than counted as a failure. Missing evidence is not an
    # exception; it is a scope limitation, and the report says so.
    return [r for r in _repos() if r.get(field) is not None]


def cm01():
    pop = _testable('branch_protected')
    return len(pop), [{'item': r['repo'], 'detail': 'default branch not protected'}
                      for r in pop if not r.get('branch_protected')]


def cm02():
    pop = _testable('reviews_required')
    return len(pop), [{'item': r['repo'], 'detail': 'no review required before merge'}
                      for r in pop if not r.get('reviews_required')]


def cm03():
    pop = _testable('secret_scanning')
    return len(pop), [{'item': r['repo'], 'detail': 'secret scanning disabled'}
                      for r in pop if not r.get('secret_scanning')]


# --- Computer Operations ----------------------------------------------------

def op01():
    pop = [s for s in _systems() if s.get('criticality') == 'High']
    exc = []
    for s in pop:
        if not s.get('backup_method'):
            exc.append({'item': s.get('system'), 'detail': 'no documented backup method'})
    return len(pop), exc


def op02():
    pop = [s for s in _systems() if s.get('backup_method')]
    exc = []
    for s in pop:
        d = days_since(s.get('restore_last_tested'))
        if d is None:
            exc.append({'item': s.get('system'), 'detail': 'restore has never been tested'})
        elif d > RESTORE_DAYS:
            exc.append({'item': s.get('system'), 'detail': 'restore last tested ' + str(d) + ' days ago'})
        elif str(s.get('restore_result')).lower() not in ('pass', 'success', 'successful', 'true'):
            exc.append({'item': s.get('system'), 'detail': 'most recent restore test did not pass'})
    return len(pop), exc


def op03():
    ws = _workstation()
    vols = ws.get('volumes', []) if isinstance(ws, dict) else []
    exc = []
    for v in vols:
        status = str(v.get('protection_status', '')).lower()
        if status not in ('on', 'protected', 'fullyencrypted'):
            exc.append({'item': str(v.get('mount_point')),
                        'detail': 'volume not protected (status: ' + str(v.get('protection_status')) + ')'})
    return len(vols), exc


def op04():
    ws = _workstation()
    ep = ws.get('endpoint_protection') if isinstance(ws, dict) else None
    if not ep:
        return 0, []
    exc = []
    if ep.get('realtime_protection') is not True:
        exc.append({'item': ep.get('product', 'endpoint protection'),
                    'detail': 'real-time protection is not enabled'})
    age = ep.get('signature_age_days')
    if age is None:
        exc.append({'item': ep.get('product', 'endpoint protection'),
                    'detail': 'signature age could not be determined'})
    elif age > SIGNATURE_MAX_AGE_DAYS:
        exc.append({'item': ep.get('product', 'endpoint protection'),
                    'detail': 'signatures are ' + str(age) + ' days old'})
    return 1, exc


REGISTRY = [
    ('ITGC-AC-01', ac01),
    ('ITGC-AC-02', ac02),
    ('ITGC-AC-03', ac03),
    ('ITGC-AC-04', ac04),
    ('ITGC-AC-05', ac05),
    ('ITGC-AC-06', ac06),
    ('ITGC-AU-01', au01),
    ('ITGC-AU-02', au02),
    ('ITGC-TP-01', tp01),
    ('ITGC-CM-01', cm01),
    ('ITGC-CM-02', cm02),
    ('ITGC-CM-03', cm03),
    ('ITGC-OP-01', op01),
    ('ITGC-OP-02', op02),
    ('ITGC-OP-03', op03),
    ('ITGC-OP-04', op04),
]
