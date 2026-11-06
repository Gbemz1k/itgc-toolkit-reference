# Runs every control test, assigns severity, and writes the findings register.
#
# Severity is derived, not typed by hand: control criticality drives the floor,
# and the proportion of the population failing can raise it. An auditor should
# be able to explain why a finding is High without saying "it felt High".
import datetime
from .util import read_csv, write_csv, today
from .controls import REGISTRY

FIELDS = ['finding_id', 'control_id', 'itgc_domain', 'cis_v8', 'severity',
          'population', 'exceptions', 'exception_rate', 'item', 'detail',
          'recommendation', 'owner', 'due_date', 'status', 'date_identified']

RECOMMENDATIONS = {
    'ITGC-AC-01': 'Complete the account inventory so every record carries system, identifier, owner and last-used date.',
    'ITGC-AC-02': 'Close or disable the dormant account, or record a documented reason for retaining it.',
    'ITGC-AC-03': 'Document the business justification for administrative access, or downgrade the account.',
    'ITGC-AC-04': 'Update the account to the current identifier and confirm the deprecated address no longer resolves.',
    'ITGC-AC-05': 'Record a recovery method you control for the account and verify it resolves to you; re-verify annually.',
    'ITGC-AC-06': 'Revoke the session, or confirm and record the device as recognised.',
    'ITGC-AU-01': 'Enable multi-factor authentication on the account.',
    'ITGC-AU-02': 'Replace the shared credential with a unique one per system and record the rotation date.',
    'ITGC-TP-01': 'Review the grant; revoke it if the access is no longer required, otherwise record the business reason and review date.',
    'ITGC-CM-01': 'Enable branch protection on the default branch.',
    'ITGC-CM-02': 'Require at least one approving review before merge, or record the compensating control for a single-maintainer repository.',
    'ITGC-CM-03': 'Enable secret scanning on the repository.',
    'ITGC-OP-01': 'Define and document a backup method for the system.',
    'ITGC-OP-02': 'Perform a restore test, record the date and the outcome, and repeat at least annually.',
    'ITGC-OP-03': 'Enable full-volume encryption on the affected volume and confirm protection status is On.',
    'ITGC-OP-04': 'Enable real-time protection and update signatures.',
}

DUE_DAYS = {'High': 30, 'Medium': 60, 'Low': 90}


def _matrix():
    return {r['control_id']: r for r in read_csv('controls/control-matrix.csv')}


def _severity(criticality, rate):
    order = ['Low', 'Medium', 'High']
    base = criticality if criticality in order else 'Low'
    idx = order.index(base)
    if rate >= 0.5 and idx < 2:
        idx += 1
    return order[idx]


def run():
    matrix = _matrix()
    rows = []
    summary = []
    n = 0
    for control_id, fn in REGISTRY:
        meta = matrix.get(control_id, {})
        population, exceptions = fn()
        rate = (len(exceptions) / population) if population else 0.0
        severity = _severity(meta.get('criticality', 'Low'), rate)
        result = 'Pass' if not exceptions else 'Fail'
        if population == 0:
            result = 'Not tested - no population'
        summary.append({
            'control_id': control_id,
            'domain': meta.get('itgc_domain', ''),
            'cis': meta.get('cis_v8', ''),
            'population': population,
            'exceptions': len(exceptions),
            'result': result,
            'severity': severity if exceptions else '',
        })
        for e in exceptions:
            n += 1
            due = today() + datetime.timedelta(days=DUE_DAYS[severity])
            rows.append({
                'finding_id': 'F-{:03d}'.format(n),
                'control_id': control_id,
                'itgc_domain': meta.get('itgc_domain', ''),
                'cis_v8': meta.get('cis_v8', ''),
                'severity': severity,
                'population': population,
                'exceptions': len(exceptions),
                'exception_rate': '{:.0%}'.format(rate),
                'item': e.get('item', ''),
                'detail': e.get('detail', ''),
                'recommendation': RECOMMENDATIONS.get(control_id, ''),
                'owner': 'Gbeminiyi Otusajo',
                'due_date': due.isoformat(),
                'status': 'Open',
                'date_identified': today().isoformat(),
            })
    write_csv('findings/findings.csv', rows, FIELDS)
    return summary, rows
