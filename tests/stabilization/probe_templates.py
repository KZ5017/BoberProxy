"""K02 live scenarios: one client request each, never automatically retried.

Requires the exact UI state documented in K02 evidence and confirmation from
the user. Run scenarios individually so an unexpected result can be inspected.
"""
import argparse
import base64
import hashlib
import http.client
import json
import time
from pathlib import Path

from probe_proxy import exchange, snapshot
from probe_transport import is_burp_drop_response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', required=True,
                        choices=['markers', 'custom-error', 'badtype', 'unicode-error',
                                 'after-rt-error', 'binary', 'utf8', 'normal'])
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    payload = {'markers': '53c0undm4rk3r+c5rfm4rk3r', 'custom-error': 'K02_FAIL',
               'badtype': 'K02_BADTYPE', 'unicode-error': 'K02_UNICODE',
               'after-rt-error': 'K02_AFTER_RT', 'binary': 'K02_BINARY',
               'utf8': 'K02_UTF8', 'normal': '%252F+%2B'}[args.scenario]
    binary = bytes(range(256)) if args.scenario == 'binary' else (
        '\u00e1\u20ac'.encode('utf-8') if args.scenario == 'utf8' else payload.encode('ascii'))
    root = Path(__file__).resolve().parents[2]
    trace = root / 'tests/stabilization/runtime/k02-custom-trace.jsonl'
    before = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    run = 'k00-workflow'  # fixed in the two HTTP fixtures
    exchange('/__control/reset?run=' + run, method='POST', proxy_port=None)
    path = '/entry?q=' + payload + '&w=TWO'
    response, error = None, None
    try:
        response = exchange(path, headers=[('X-Bober-Test-Run', run)])
    except (OSError, ValueError, http.client.HTTPException) as exc:
        error = dict(type=type(exc).__name__, message=str(exc))
    observed = snapshot(run, 18765)
    # Late observation is control traffic only, never an application retry.
    samples = []
    if args.scenario == 'after-rt-error':
        started = time.monotonic()
        while time.monotonic() - started < 1:
            time.sleep(0.1)
            observed = snapshot(run, 18765)
            samples.append(dict(seconds=round(time.monotonic() - started, 3),
                                count=observed['event_count'], actions=observed['action_count']))
    events = observed['recent_events']
    after = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    records = [json.loads(line) for line in after[len(before):]]
    if args.scenario in ('custom-error', 'badtype', 'unicode-error'):
        checks = dict(no_action=observed['action_count'] == 0,
                      original_once=len(events) == 1 and events[0]['target'] == path and events[0]['method'] == 'GET',
                      original_response=response is not None and response.get('json', {}).get('request', {}).get('target') == path,
                      one_custom_call=len(records) == 1)
    elif args.scenario == 'after-rt-error':
        checks = dict(one_action=observed['action_count'] == 1,
                      only_rt=len(events) == 1 and events[0]['target'] == '/workflow/action',
                      two_custom_calls=len(records) == 2,
                      initial_token_empty=len(records) == 2 and records[0]['csrf_token'] is None,
                      terminal_drop=is_burp_drop_response(response))
    else:
        token = observed['session'][1] if observed.get('session') else None
        checks = dict(one_action=observed['action_count'] == 1,
                      rt_then_cp=len(events) == 2 and [e['target'] for e in events] == ['/workflow/action', '/workflow/check'],
                      methods=len(events) == 2 and all(e['method'] == 'POST' for e in events),
                      rt_body=bool(events and base64.b64decode(events[0]['body_base64']) == b'one=' + binary + b'&two=TWO'),
                      cp_body=len(events) == 2 and token is not None and base64.b64decode(events[1]['body_base64']) ==
                              ('csrf=' + token).encode('ascii') + b'&one=' + binary + b'&two=TWO',
                      two_custom_calls=len(records) == 2,
                      correct_step_token=len(records) == 2 and records[1]['csrf_token'] == token,
                      correct_response=response is not None and response.get('json', {}).get('cookie_ok') is True
                                       and response.get('json', {}).get('token_ok') is True)
    checks['trace_inputs_unchanged'] = bool(records) and all(r['payload1'] == payload and r['payload2'] == 'TWO' for r in records)
    checks['no_transport_error'] = error is None
    report = dict(kind='external-burp-template-scenario', scenario=args.scenario,
                  source_on_disk_sha256=hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest(),
                  passed=all(checks.values()), checks=checks, observed=observed,
                  response=response, transport_error=error, custom_records=records,
                  observation_samples=samples, note='UI state and loaded source require user confirmation. No retries.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(scenario=args.scenario, passed=report['passed'], checks=checks), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
