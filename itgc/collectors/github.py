# Pulls repository configuration from the GitHub REST API as audit evidence.
import json
import urllib.request
import urllib.error
from ..util import save_json

API = 'https://api.github.com'


def _get(url, token):
    headers = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'itgc-toolkit',
    }
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {'_error': e.code}
    except Exception as e:
        return {'_error': str(e)}


def run(owner, token, is_org=False):
    base = '/orgs/' if is_org else '/users/'
    repos = _get(API + base + owner + '/repos?per_page=100&type=all', token)
    if isinstance(repos, dict):
        raise SystemExit('GitHub API error: ' + str(repos.get('_error')))

    # Without a token the configuration endpoints are not readable. Record that
    # as "not tested" rather than reporting every repository as an exception —
    # an audit that manufactures findings from missing evidence is worse than no
    # audit at all.
    out = []
    for repo in repos:
        full = repo['full_name']
        branch = repo.get('default_branch') or 'main'
        row = {
            'repo': full,
            'private': repo.get('private'),
            'default_branch': branch,
            'pushed_at': repo.get('pushed_at'),
            'authenticated': bool(token),
        }
        if token:
            prot = _get(API + '/repos/' + full + '/branches/' + branch + '/protection', token)
            protected = isinstance(prot, dict) and '_error' not in prot
            row['branch_protected'] = protected
            row['reviews_required'] = bool(prot.get('required_pull_request_reviews')) if protected else False
            detail = _get(API + '/repos/' + full, token)
            sec = (detail.get('security_and_analysis') or {}) if isinstance(detail, dict) else {}
            row['secret_scanning'] = ((sec.get('secret_scanning') or {}).get('status') == 'enabled')
        else:
            row['branch_protected'] = None
            row['reviews_required'] = None
            row['secret_scanning'] = None
        out.append(row)
    save_json('evidence/github_repos.json', out)
    return out
