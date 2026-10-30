"""One K03 proxy workflow per run; exact bytes/counts, never a client retry."""
import argparse
import base64
import hashlib
import http.client
import json
import ssl
import time
from pathlib import Path

from probe_proxy import exchange, snapshot
from probe_transport import is_burp_drop_response


def tls_control(path, method='GET'):
    # Only our fixed loopback fixture uses a generated, self-signed certificate.
    connection = http.client.HTTPSConnection('127.0.0.1', 18768, timeout=3,
                                             context=ssl._create_unverified_context())
    try:
        connection.request(method, path, headers={'Connection': 'close'})
        response = connection.getresponse()
        assert response.status == 200
        return json.loads(response.read())
    finally:
        connection.close()


def observations(run):
    return {'18766': snapshot(run, 18766), '18767': snapshot(run, 18767),
            '18768': tls_control('/__control/events?run=' + run)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True, choices=['off', 'relative', 'chain10', 'chain11', 'loop', 'invalid', 'cross-port', 'cross-scheme'])
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--state-from-report', type=Path, help='Verify state collected by a preceding manual response')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    trace = base / 'runtime/k03-custom-trace.jsonl'
    before = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    run = 'k03-workflow'
    for port in (18766, 18767):
        exchange('/__control/reset?run=' + run, method='POST', target_port=port, proxy_port=None)
    tls_control('/__control/reset?run=' + run, 'POST')
    reply, error = None, None
    try:
        reply = exchange('/entry?q=' + args.case + '&w=%252F+%2B', target_port=18766,
                         headers=[('X-Bober-Test-Run', run)], timeout=8)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        error = dict(type=type(exc).__name__, message=str(exc))
    observed = observations(run)
    samples = []
    failed_case = args.case in ('chain11', 'loop', 'invalid')
    if failed_case:
        started = time.monotonic()
        while time.monotonic() - started < 1:
            time.sleep(0.1)
            observed = observations(run)
            samples.append(dict(seconds=round(time.monotonic() - started, 3),
                                counts={port: state['event_count'] for port, state in observed.items()}))
    events = sorted([dict(event, port=int(port)) for port, state in observed.items()
                     for event in state['recent_events']], key=lambda event: event['time_ns'])
    after = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    records = [json.loads(line) for line in after[len(before):]]
    hops = 0 if args.case in ('off', 'invalid') else (10 if args.case in ('chain10', 'chain11') else 1)
    gets = [event for event in events if event['method'] == 'GET']
    checks = dict(no_transport_error=error is None,
                  action_once=sum(state['action_count'] for state in observed.values()) == 1,
                  request_count=len(events) == 1 + hops + (0 if failed_case else 1),
                  redirect_get_count=len(gets) == hops,
                  rt_original_service=bool(events and events[0]['port'] == 18766 and events[0]['method'] == 'POST'
                                           and events[0]['target'] == '/k03/a/start?case=' + args.case),
                  rt_raw_body=bool(events and base64.b64decode(events[0]['body_base64']) ==
                                   ('one=' + args.case + '&two=%252F+%2B').encode('ascii')),
                  no_original_forwarded=not any(event['target'].startswith('/entry') for event in events),
                  custom_calls=len(records) == (1 if failed_case else 2),
                  custom_inputs_preserved=bool(records) and all(record['payload1'] == args.case and record['payload2'] == '%252F+%2B' for record in records))
    checks['minimal_get_policy'] = all(base64.b64decode(event['body_base64']) == b''
        and dict((k.lower(), v) for k, v in event['headers']).get('user-agent') == 'K03-Fixture'
        and 'authorization' not in dict((k.lower(), v) for k, v in event['headers']) for event in gets)
    if args.state_from_report:
        prior = json.loads(args.state_from_report.read_text(encoding='utf-8'))
        checks['manual_response_token_collected'] = bool(prior['passed'] and records and
            records[0]['csrf_token'] == prior['expected_token'])
        rt_headers = {key.lower(): value for key, value in events[0]['headers']} if events else {}
        checks['manual_response_cookie_collected'] = bool(prior['passed'] and
            ('sid=' + prior['expected_cookie']) in rt_headers.get('cookie', '').split('; '))
    if failed_case:
        checks['terminal_drop'] = is_burp_drop_response(reply)
        checks['no_checkpage'] = not any(event['target'] == '/k03/check' for event in events)
    else:
        token = 'csrf.%s.h%d' % (run, hops)
        checks.update(cp_original_service=bool(events and events[-1]['port'] == 18766 and events[-1]['target'] == '/k03/check'),
                      cp_exact_body=bool(events and base64.b64decode(events[-1]['body_base64']) ==
                                         ('csrf=' + token + '&one=' + args.case + '&two=%252F+%2B').encode('ascii')),
                      cookie_and_token=bool(reply and reply.get('json', {}).get('cookie_ok') is True and reply.get('json', {}).get('token_ok') is True),
                      second_custom_token=len(records) == 2 and records[1]['csrf_token'] == token)
    if args.case == 'cross-port':
        checks['second_origin'] = len(gets) == 1 and gets[0]['port'] == 18767
    elif args.case == 'cross-scheme':
        checks['tls_origin'] = len(gets) == 1 and gets[0]['port'] == 18768 and bool(gets[0].get('tls_version'))
    else:
        checks['no_origin_change'] = all(event['port'] == 18766 for event in events)
    report = dict(kind='external-burp-k03-redirect-workflow', scenario=args.case,
                  source_on_disk_sha256=hashlib.sha256((base.parents[1] / 'BoberProxy.py').read_bytes()).hexdigest(),
                  passed=all(checks.values()), checks=checks, observed=observed, custom_records=records,
                  response=reply, transport_error=error, observation_samples=samples,
                  preceding_state_report=str(args.state_from_report) if args.state_from_report else None,
                  note='UI selection and loaded main extension confirmed separately. One client request, no automatic retries.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(scenario=args.case, passed=report['passed'], checks=checks), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
