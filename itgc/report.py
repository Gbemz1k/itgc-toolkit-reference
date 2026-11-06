# Renders the audit report from the test summary and the findings register.
from .util import path, today


def render(summary, findings, scope_note=''):
    tested = [s for s in summary if s['result'] != 'Not tested - no population']
    passed = [s for s in tested if s['result'] == 'Pass']
    failed = [s for s in tested if s['result'] == 'Fail']
    pop = sum(s['population'] for s in summary)

    L = []
    L.append('# IT General Controls Review')
    L.append('')
    L.append('**Entity:** personal technology environment  ')
    L.append('**Framework:** CIS Controls v8, Implementation Group 1  ')
    L.append('**Period:** as at ' + today().isoformat() + '  ')
    L.append('**Prepared by:** Gbeminiyi Otusajo')
    L.append('')
    L.append('## 1. Scope and approach')
    L.append('')
    L.append('Thirteen IT general controls were tested across four domains: access to '
             'programs and data, program changes, third-party access, and computer '
             'operations. Each control was mapped to CIS Controls v8 IG1.')
    L.append('')
    L.append('Every test was executed against the **full population** rather than a '
             'sample, using the automated test suite in this repository. Credential '
             'testing was performed on SHA-256 hashes only; no plaintext credential '
             'was written to disk at any point.')
    if scope_note:
        L.append('')
        L.append(scope_note)
    L.append('')
    L.append('## 2. Summary of results')
    L.append('')
    L.append('| Controls tested | Passed | Failed | Items in scope | Findings raised |')
    L.append('|---|---|---|---|---|')
    L.append('| {} | {} | {} | {} | {} |'.format(len(tested), len(passed), len(failed), pop, len(findings)))
    L.append('')
    L.append('| Control | Domain | CIS v8 | Population | Exceptions | Result | Severity |')
    L.append('|---|---|---|---|---|---|---|')
    for s in summary:
        L.append('| {} | {} | {} | {} | {} | {} | {} |'.format(
            s['control_id'], s['domain'], s['cis'], s['population'],
            s['exceptions'], s['result'], s['severity']))
    L.append('')
    L.append('## 3. Findings')
    L.append('')
    if not findings:
        L.append('No exceptions were identified.')
    else:
        for sev in ('High', 'Medium', 'Low'):
            group = [f for f in findings if f['severity'] == sev]
            if not group:
                continue
            L.append('### ' + sev + ' (' + str(len(group)) + ')')
            L.append('')
            for f in group:
                L.append('**' + f['finding_id'] + ' — ' + f['control_id'] + '** · '
                         + f['itgc_domain'] + ' · CIS ' + f['cis_v8'])
                L.append('')
                L.append('- **Condition:** ' + f['detail'])
                L.append('- **Item:** ' + str(f['item']))
                L.append('- **Population tested:** ' + str(f['population'])
                         + ' (' + f['exception_rate'] + ' exception rate)')
                L.append('- **Recommendation:** ' + f['recommendation'])
                L.append('- **Owner:** ' + f['owner'] + ' · **Due:** ' + f['due_date']
                         + ' · **Status:** ' + f['status'])
                L.append('')
    L.append('## 4. Remediation tracking')
    L.append('')
    L.append('Findings are tracked in `findings/findings.csv`. Re-running '
             '`python -m itgc test` after remediation re-tests the full population and '
             'regenerates this report, which is what makes the review repeatable '
             'rather than a point-in-time exercise.')
    L.append('')

    out = '\n'.join(L) + '\n'
    p = path('reports/itgc-report.md')
    open(p, 'w', encoding='utf-8', newline='\n').write(out)
    return p
