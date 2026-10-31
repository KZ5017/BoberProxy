"""Run only after the corresponding Burp UI state is confirmed.

Single sends, stop on first failure, no automatic retries or report overwrite.
Suite transitions deliberately require explicit UI actions by the user.
"""
import argparse
import json
import time
from pathlib import Path

from probe_k04_session import run_case


MARKER = 'c5rfm4rk3r'


def scenarios(suite):
    if suite == 'normal':
        steps = [('seed', 'SEED', 'SEED'), ('deleted-prefix', 'deletedButValid', 'PREFIX'),
                 ('deleted-literal', 'deleted', 'DELETED'), ('empty-value', '', 'EMPTYCOOKIE'),
                 ('max-zero', None, 'ZERO'), ('readd', 'READD', 'READD'),
                 ('max-negative', None, 'NEG'), ('expires-past', None, 'PAST'),
                 ('precedence-positive', 'POS', 'POS'), ('precedence-delete', None, 'PREDELETE'),
                 ('invalid-age-past', None, 'BADAGE'), ('invalid-expires', 'INVALID_DATE', 'BADDATE'),
                 ('headers', 'HEADERS', 'HEADERS'), ('no-match', 'HEADERS', 'HEADERS'),
                 ('empty-token', 'HEADERS', ''), ('positive-short', 'SHORT', 'SHORT'),
                 ('no-match', None, 'SHORT'), ('high-bytes', '\xff\x80', '\xff\x80')]
        initial_sid, initial_token = 'template', MARKER
        for index, (case, sid, token) in enumerate(steps):
            # Evaluate the delay before run_case: lazy expiry must also affect RT.
            if index == 16:
                initial_sid = None
            yield dict(case=case, expected_sid=sid, expected_token=token,
                       initial_sid=initial_sid, initial_token=initial_token,
                       delay=1.2 if index == 16 else 0)
            initial_sid, initial_token = sid, token
    elif suite == 'redirect':
        yield dict(case='chain10', expected_sid=None, expected_token='H10', initial_sid='\xff\x80', initial_token='\xff\x80', hops=10)
        yield dict(case='chain11', expected_sid=None, expected_token='H10', initial_sid=None, initial_token='H10', hops=10, drop=True)
        yield dict(case='no-match', expected_sid=None, expected_token='H10', initial_sid=None, initial_token='H10')
    elif suite == 'clear':
        yield dict(case='clear-control', expected_sid='template', expected_token=MARKER, initial_sid='template', initial_token=MARKER)
    elif suite == 'cookie-only':
        yield dict(case='seed', expected_sid='SEED', expected_token=MARKER, initial_sid='template', initial_token=MARKER)
    elif suite == 'csrf-only':
        yield dict(case='readd', expected_sid='template', expected_token='READD', initial_sid='template', initial_token=MARKER)
    elif suite == 'both-off':
        yield dict(case='deleted-literal', expected_sid='template', expected_token=MARKER, initial_sid='template', initial_token=MARKER)
    elif suite == 'restored':
        yield dict(case='no-match', expected_sid='SEED', expected_token='READD', initial_sid='SEED', initial_token='READD')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--suite', required=True, choices=['normal', 'redirect', 'clear', 'cookie-only', 'csrf-only', 'both-off', 'restored'])
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--label', help='Distinct label for an explicitly authorized fresh attempt')
    args = parser.parse_args()
    steps = list(scenarios(args.suite))
    paths = [args.directory / ('%s-%02d-%s.json' % (args.label or args.suite, index + 1, step['case']))
             for index, step in enumerate(steps)]
    if any(path.exists() for path in paths):
        raise RuntimeError('Existing reports: no overwrite or automatic retry allowed.')
    args.directory.mkdir(parents=True, exist_ok=True)
    for step, path in zip(steps, paths):
        delay = step.pop('delay', 0)
        if delay:
            time.sleep(delay)
        report = run_case(**step)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
        print('%s %s' % (path.name, 'PASS' if report['passed'] else 'FAIL'), flush=True)
        if not report['passed']:
            print(json.dumps(report['checks'], indent=2))
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
