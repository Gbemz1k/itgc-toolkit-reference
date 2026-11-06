import argparse
import sys
from . import engine, report, report_html
from .collectors import passwords, github, workstation
from .util import load_json


def cmd_collect(args):
    if args.source == 'passwords':
        if not args.csv:
            sys.exit('--csv is required (export your browser passwords first)')
        r = passwords.run(args.csv)
        print('Credential population: {}'.format(r['population']))
        print('Distinct credentials:  {}'.format(r['distinct_credentials']))
        print('Reused across systems: {} group(s)'.format(len(r['reused_groups'])))
        for g in r['reused_groups'][:10]:
            print('  - {} systems: {}'.format(g['system_count'], ', '.join(g['systems'][:6])))
        print('No plaintext credential was written to disk.')
    elif args.source == 'github':
        if not args.owner:
            sys.exit('--owner is required')
        rows = github.run(args.owner, args.token, args.org)
        print('Collected {} repositories.'.format(len(rows)))
        if not args.token:
            print('  ! No token supplied. Repository configuration could not be read, so')
            print('    ITGC-CM-01/02/03 will report as not tested rather than failed.')
    elif args.source == 'workstation':
        r = workstation.run()
        print('Host: {}'.format(r.get('hostname')))
        print('Volumes: {}'.format(len(r.get('volumes', []))))
        if r.get('volumes_note'):
            print('  ! ' + r['volumes_note'])
        ep = r.get('endpoint_protection')
        print('Endpoint protection: {}'.format('collected' if ep else 'unavailable'))
        if r.get('endpoint_note'):
            print('  ! ' + r['endpoint_note'])


def cmd_test(args):
    summary, findings = engine.run()
    width = max(len(s['control_id']) for s in summary)
    print('')
    print('{}  {:>10}  {:>10}  {}'.format('CONTROL'.ljust(width), 'POPULATION', 'EXCEPTIONS', 'RESULT'))
    for s in summary:
        print('{}  {:>10}  {:>10}  {}'.format(
            s['control_id'].ljust(width), s['population'], s['exceptions'], s['result']))
    print('')
    print('{} finding(s) written to findings/findings.csv'.format(len(findings)))


def cmd_report(args):
    summary, findings = engine.run()
    md = report.render(summary, findings)
    print('Markdown report: {}'.format(md))
    if not args.no_html:
        htmlp = report_html.render(summary, findings, entity=args.entity)
        print('HTML report    : {}'.format(htmlp))
        print('Open it by double-clicking the file, or drag it into a browser.')


def cmd_status(args):
    accounts = load_json('inventory/accounts.json', [])
    systems = load_json('inventory/systems.json', [])
    grants = load_json('inventory/oauth_grants.json', [])
    repos = load_json('evidence/github_repos.json', [])
    pw = load_json('evidence/password_analysis.json', {})
    print('accounts in inventory : {}'.format(len(accounts)))
    print('systems in inventory  : {}'.format(len(systems)))
    print('oauth grants          : {}'.format(len(grants)))
    print('repositories collected: {}'.format(len(repos)))
    print('credentials analysed  : {}'.format(pw.get('population', 0) if isinstance(pw, dict) else 0))


def main(argv=None):
    p = argparse.ArgumentParser(prog='itgc', description='IT general controls review toolkit')
    sub = p.add_subparsers(dest='cmd', required=True)

    c = sub.add_parser('collect', help='gather evidence')
    c.add_argument('source', choices=['passwords', 'github', 'workstation'])
    c.add_argument('--csv')
    c.add_argument('--owner')
    c.add_argument('--token')
    c.add_argument('--org', action='store_true')
    c.set_defaults(func=cmd_collect)

    t = sub.add_parser('test', help='run all control tests')
    t.set_defaults(func=cmd_test)

    r = sub.add_parser('report', help='run tests and render the audit report')
    r.add_argument('--no-html', action='store_true', help='skip the HTML report')
    r.add_argument('--entity', default='Personal technology environment',
                   help='entity name shown in the report header')
    r.set_defaults(func=cmd_report)

    s = sub.add_parser('status', help='show what evidence has been gathered')
    s.set_defaults(func=cmd_status)

    args = p.parse_args(argv)
    args.func(args)
