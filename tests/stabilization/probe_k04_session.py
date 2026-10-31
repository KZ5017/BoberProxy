"""One real K04 workflow; record counts/bytes, no retry or success-by-status."""
import argparse
import base64
import hashlib
import http.client
import json
import time
from pathlib import Path
from urllib.parse import parse_qs

from probe_proxy import exchange, snapshot
from probe_transport import is_burp_drop_response
from target_server_k04 import PORT


RUN = 'k04-workflow'


def cookie_map(event):
    values = [value for name, value in event['headers'] if name.lower() == 'cookie']
    result = {}
    for value in values:
        for pair in value.split(';'):
            if '=' in pair:
                name, val = pair.strip().split('=', 1)
                result[name] = val
    return result


def body_fields(event):
    return parse_qs(base64.b64decode(event['body_base64']).decode('latin-1'), keep_blank_values=True)


def run_case(case, expected_sid, expected_token, *, initial_sid, initial_token,
             hops=0, drop=False, proxy_port=8080, target_port=PORT):
    exchange('/__control/reset?run=' + RUN, method='POST', target_port=target_port, proxy_port=None)
    reply, error = None, None
    try:
        reply = exchange('/entry?q=' + case + '&w=%252F+%2B', target_port=target_port,
                         proxy_port=proxy_port, headers=[('X-Bober-Test-Run', RUN)], timeout=8)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        error = dict(type=type(exc).__name__, message=str(exc))
    observed = snapshot(RUN, target_port)
    if drop:
        # A finite late observation catches accidental post-error forwarding.
        time.sleep(0.3)
        late = snapshot(RUN, target_port)
    else:
        late = observed
    events = observed['recent_events']
    rt = events[0] if events else None
    cp = events[-1] if events and not drop else None
    checks = dict(no_transport_error=error is None,
                  action_once=observed['action_count'] == 1,
                  event_count=observed['event_count'] == 1 + hops + (0 if drop else 1),
                  no_late_extra_send=late['event_count'] == observed['event_count'],
                  redirect_get_count=sum(event['method'] == 'GET' for event in events) == hops,
                  rt_target=rt is not None and rt['method'] == 'POST' and rt['target'] == '/k04/action?case=' + case,
                  rt_sid=rt is not None and cookie_map(rt).get('sid') == initial_sid,
                  rt_token=rt is not None and body_fields(rt).get('csrf') == [initial_token],
                  raw_payload=rt is not None and body_fields(rt).get('one') == [case]
                     and b'two=%252F+%2B&' in base64.b64decode(rt['body_base64']))
    if drop:
        checks['explicit_burp_drop'] = reply is not None and is_burp_drop_response(reply)
    else:
        checks.update(
            checkpage_target=cp is not None and cp['method'] == 'POST' and cp['target'] == '/k04/check?case=' + case,
            cp_cookie=cp is not None and cookie_map(cp).get('sid') == expected_sid,
            unmanaged_cookie=cp is not None and cookie_map(cp).get('untouched') == 'x',
            fake_header_not_cookie=cp is not None and not {'fake', 'fake2'} & set(cookie_map(cp)),
            cp_token=cp is not None and body_fields(cp).get('csrf') == [expected_token],
            client_received_checkpage=reply is not None and reply.get('json', {}).get('request', {}).get('target') == '/k04/check?case=' + case)
        if case == 'headers':
            checks['multiple_cookie_fields'] = cp is not None and cookie_map(cp).get('multi') == 'SECOND'
    root = Path(__file__).resolve().parents[2]
    return dict(kind='K04-external-proxy-traffic-no-retry', scenario=case, run=RUN,
                expected=dict(initial_sid=initial_sid, initial_token=initial_token,
                              final_sid=expected_sid, final_token=expected_token, hops=hops, drop=drop),
                checks=checks, passed=all(checks.values()), response=reply, transport_error=error,
                observed=observed, late_observed=late,
                source_on_disk_sha256=hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest(),
                note='Loaded source and UI switches require separate user confirmation.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True)
    parser.add_argument('--initial-sid', required=True, help='Literal value, or ABSENT for no sid')
    parser.add_argument('--initial-token', required=True)
    parser.add_argument('--final-sid', required=True)
    parser.add_argument('--final-token', required=True)
    parser.add_argument('--hops', type=int, default=0)
    parser.add_argument('--drop', action='store_true')
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    report = run_case(args.case, None if args.final_sid == 'ABSENT' else args.final_sid, args.final_token,
                      initial_sid=None if args.initial_sid == 'ABSENT' else args.initial_sid,
                      initial_token=args.initial_token, hops=args.hops, drop=args.drop)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checks=report['checks']), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
