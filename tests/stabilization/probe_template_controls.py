"""Unmatched/passive HTTP byte controls; no q/w activation, no retries."""
import argparse
import base64
import hashlib
import json
import uuid
from pathlib import Path

from probe_proxy import exchange, snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--mode', choices=['passive', 'active-unmatched'], required=True)
    args = parser.parse_args()
    cases = [('empty', '/empty', 'GET', b'', None),
             ('binary-response', '/bytes?size=256', 'GET', b'', None),
             ('json', '/echo', 'POST', b'{"q":"%252F+marker","w":"TWO"}', 'application/json'),
             ('multipart', '/echo', 'POST', b'--k02\r\nContent-Disposition: form-data; name="q"\r\n\r\nVALUE\r\n--k02--\r\n',
              'multipart/form-data; boundary=k02'),
             ('binary-request', '/echo', 'POST', bytes(range(256)), 'application/octet-stream')]
    results = []
    for name, path, method, body, content_type in cases:
        run = 'k02-control-' + uuid.uuid4().hex[:12]
        headers = [('X-Bober-Test-Run', run)]
        if content_type:
            headers.append(('Content-Type', content_type))
        response = exchange(path, method=method, body=body, headers=headers)
        observed = snapshot(run, 18765)
        events = observed['recent_events']
        checks = dict(one_request=len(events) == 1, no_action=observed['action_count'] == 0,
                      original_target=bool(events and events[0]['target'] == path),
                      original_method=bool(events and events[0]['method'] == method),
                      request_body=bool(events and base64.b64decode(events[0]['body_base64']) == body),
                      response_status=response['status'] == (204 if name == 'empty' else 200))
        if name in ('empty', 'binary-response'):
            checks['response_body'] = base64.b64decode(response['body_base64']) == (b'' if name == 'empty' else bytes(range(256)))
        results.append(dict(scenario=name, checks=checks, passed=all(checks.values()),
                            observed=observed, response=response))
        if not results[-1]['passed']:
            break
    root = Path(__file__).resolve().parents[2]
    report = dict(kind='external-burp-byte-controls', mode=args.mode,
                  source_on_disk_sha256=hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest(),
                  passed=len(results) == len(cases) and all(r['passed'] for r in results), cases=results,
                  note='Mode and loaded source require user confirmation; distinct requests, no retries.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], mode=args.mode,
                          cases={r['scenario']: r['passed'] for r in results}), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
