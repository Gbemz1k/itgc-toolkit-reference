# Renders the audit report as a self-contained HTML page.
#
# No external CSS, fonts or scripts: the file must open correctly from disk,
# from a shared drive, or from a static host, with no network.
import html
from .util import path, today

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
color:#111827;background:#f4f5f7;padding:40px 20px}
.wrap{max-width:980px;margin:0 auto}
header{background:#0f2744;color:#fff;border-radius:16px 16px 0 0;padding:34px 38px}
header h1{font-size:26px;font-weight:650;letter-spacing:-.02em}
header .sub{color:#9fb3cc;margin-top:10px;font-size:14px}
header .sub b{color:#dbe6f3;font-weight:600}
main{background:#fff;border:1px solid rgba(0,0,0,.07);border-top:0;border-radius:0 0 16px 16px;
padding:34px 38px 44px}
h2{font-size:17px;font-weight:650;margin:38px 0 14px;letter-spacing:-.01em}
h2:first-child{margin-top:0}
h3{font-size:14px;font-weight:650;margin:26px 0 12px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280}
p{margin:0 0 12px;color:#374151}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin:18px 0 6px}
.tile{background:#f9fafb;border:1px solid rgba(0,0,0,.06);border-radius:14px;padding:16px 18px}
.tile .n{font-size:28px;font-weight:650;letter-spacing:-.02em}
.tile .l{font-size:12px;color:#6b7280;margin-top:3px;text-transform:uppercase;letter-spacing:.04em}
.tile.bad .n{color:#ef4444}.tile.good .n{color:#10b981}
table{width:100%;border-collapse:collapse;margin:14px 0;font-size:14px}
th{text-align:left;font-weight:600;color:#6b7280;font-size:12px;text-transform:uppercase;
letter-spacing:.04em;padding:9px 10px;border-bottom:1px solid #e5e7eb}
td{padding:10px;border-bottom:1px solid #f3f4f6;vertical-align:top}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums;color:#374151}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:#f3f4f6;padding:1px 6px;border-radius:5px}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:2px 9px;border-radius:999px;white-space:nowrap}
.pass{background:#ecfdf5;color:#047857}
.fail{background:#fef2f2;color:#b91c1c}
.nt{background:#f3f4f6;color:#6b7280}
.sev-High{background:#fef2f2;color:#b91c1c}
.sev-Medium{background:#fffbeb;color:#b45309}
.sev-Low{background:#f3f4f6;color:#4b5563}
.f{border:1px solid rgba(0,0,0,.07);border-radius:14px;padding:16px 18px;margin:0 0 10px;background:#fff}
.f .top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:9px;flex-wrap:wrap}
.f .id{font:13px ui-monospace,Menlo,monospace;color:#6b7280}
.f .cond{font-weight:600;margin-bottom:8px}
.f dl{display:grid;grid-template-columns:150px 1fr;gap:5px 14px;font-size:13.5px;color:#374151}
.f dt{color:#6b7280}
.note{background:#f9fafb;border-left:3px solid #0f2744;padding:13px 16px;border-radius:0 10px 10px 0;
margin:14px 0;font-size:14px;color:#374151}
footer{text-align:center;color:#9ca3af;font-size:12.5px;margin-top:22px}
"""


def _pill(result):
    if result == 'Pass':
        return '<span class="pill pass">Pass</span>'
    if result == 'Fail':
        return '<span class="pill fail">Fail</span>'
    return '<span class="pill nt">Not tested</span>'


def render(summary, findings, entity='Personal technology environment', scope_note='', out='reports/itgc-report.html'):
    e = html.escape
    tested = [s for s in summary if s['result'] != 'Not tested - no population']
    passed = [s for s in tested if s['result'] == 'Pass']
    failed = [s for s in tested if s['result'] == 'Fail']
    pop = sum(s['population'] for s in summary)
    high = [f for f in findings if f['severity'] == 'High']

    L = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         '<title>IT General Controls Review</title><style>', CSS, '</style></head><body><div class="wrap">']

    L.append('<header><h1>IT General Controls Review</h1><div class="sub">'
             '<b>Entity</b> ' + e(entity) + ' &nbsp;·&nbsp; '
             '<b>Framework</b> CIS Controls v8, Implementation Group 1 &nbsp;·&nbsp; '
             '<b>As at</b> ' + today().isoformat() + '</div></header><main>')

    L.append('<h2>Summary of results</h2><div class="tiles">')
    for n, l, cls in ((len(summary), 'Controls in scope', ''),
                      (len(tested), 'Controls tested', ''),
                      (len(passed), 'Passed', 'good'),
                      (len(failed), 'Failed', 'bad'),
                      (pop, 'Items tested', ''),
                      (len(findings), 'Findings', 'bad' if findings else 'good')):
        L.append('<div class="tile ' + cls + '"><div class="n">' + str(n) + '</div><div class="l">' + l + '</div></div>')
    L.append('</div>')

    L.append('<div class="note"><b>Every test ran against the full population, not a sample.</b> '
             'Credential testing used SHA-256 hashes only; no plaintext credential was written to disk. '
             'Controls whose evidence could not be read are reported as <i>not tested</i> rather than failed.</div>')
    if scope_note:
        L.append('<div class="note">' + e(scope_note) + '</div>')

    L.append('<h2>Controls</h2><table><thead><tr><th>Control</th><th>Domain</th><th>CIS v8</th>'
             '<th style="text-align:right">Population</th><th style="text-align:right">Exceptions</th>'
             '<th>Result</th><th>Severity</th></tr></thead><tbody>')
    for s in summary:
        sev = ('<span class="pill sev-' + s['severity'] + '">' + s['severity'] + '</span>') if s['severity'] else ''
        L.append('<tr><td><code>' + e(s['control_id']) + '</code></td><td>' + e(s['domain']) +
                 '</td><td>' + e(str(s['cis'])) + '</td><td class="num">' + str(s['population']) +
                 '</td><td class="num">' + str(s['exceptions']) + '</td><td>' + _pill(s['result']) +
                 '</td><td>' + sev + '</td></tr>')
    L.append('</tbody></table>')

    L.append('<h2>Findings</h2>')
    if not findings:
        L.append('<p>No exceptions were identified.</p>')
    else:
        L.append('<p>' + str(len(findings)) + ' exceptions raised, of which ' + str(len(high)) +
                 ' are rated High. Severity is derived: control criticality sets the floor, and an '
                 'exception rate at or above 50% raises it one level.</p>')
        for sev in ('High', 'Medium', 'Low'):
            group = [f for f in findings if f['severity'] == sev]
            if not group:
                continue
            L.append('<h3>' + sev + ' &nbsp;(' + str(len(group)) + ')</h3>')
            for f in group:
                L.append('<div class="f"><div class="top"><span class="id">' + e(f['finding_id']) +
                         ' &nbsp;·&nbsp; ' + e(f['control_id']) + ' &nbsp;·&nbsp; CIS ' + e(str(f['cis_v8'])) +
                         '</span><span class="pill sev-' + sev + '">' + sev + '</span></div>')
                L.append('<div class="cond">' + e(f['detail']) + '</div><dl>')
                for k, v in (('Item', f['item']), ('Domain', f['itgc_domain']),
                             ('Population', str(f['population']) + ' tested, ' + f['exception_rate'] + ' exception rate'),
                             ('Recommendation', f['recommendation']),
                             ('Owner', f['owner']), ('Due', f['due_date']), ('Status', f['status'])):
                    L.append('<dt>' + k + '</dt><dd>' + e(str(v)) + '</dd>')
                L.append('</dl></div>')

    L.append('<h2>Remediation tracking</h2><p>Findings are tracked in <code>findings/findings.csv</code>. '
             'Re-running <code>python -m itgc report</code> after remediation re-tests the full population and '
             'regenerates this page, which is what makes the review repeatable rather than point-in-time.</p>')
    L.append('</main><footer>Generated by itgc-toolkit · '
             '<a href="https://github.com/Gbemz1k/itgc-toolkit-reference" style="color:#6b7280">'
             'github.com/Gbemz1k/itgc-toolkit-reference</a></footer></div></body></html>')

    out_path = path(out)
    open(out_path, 'w', encoding='utf-8', newline='\n').write('\n'.join(L))
    return out_path
