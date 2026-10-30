"""One tagged real Proxy action test; can wait for two manual Forward presses."""
import argparse
import base64
import hashlib
import html
import http.client
import json
import uuid
from pathlib import Path

from probe_proxy import exchange, snapshot
from probe_transport import is_burp_drop_response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True, choices=['request-drop', 'response-drop', 'follow-rules', 'dont-intercept', 'manual-both', 'active-ready'])
    parser.add_argument('--mode', required=True, choices=['extension-off', 'unmatched', 'active'])
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=8)
    parser.add_argument('--stateful-response', action='store_true', help='Manual test returns a fresh fixture cookie/CSRF')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    trace = base / 'runtime/k03-actions.jsonl'
    before = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    native = json.loads((base / 'runtime/k03-burp-native.json').read_text())
    constants = native['action_constants']
    run = 'k03-workflow' if args.case == 'active-ready' else 'k03-action-' + uuid.uuid4().hex[:12]
    exchange('/__control/reset?run=' + run, method='POST', target_port=18766, proxy_port=None)
    path = '/entry?q=ONE&w=%252F+%2B' if args.case == 'active-ready' else '/echo?case=' + args.case
    if args.stateful_response:
        if args.case != 'manual-both':
            parser.error('--stateful-response requires --case manual-both')
        path = '/k03/a/next?case=relative&hop=1&run=' + run
    response, error = None, None
    try:
        response = exchange(path, target_port=18766, headers=[('X-Bober-Test-Run', run), ('X-Bober-K03-Probe', args.case)], timeout=args.timeout)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        error = dict(type=type(exc).__name__, message=str(exc))
    observed = snapshot(run, 18766)
    after = trace.read_text(encoding='utf-8').splitlines() if trace.exists() else []
    records = [json.loads(line) for line in after[len(before):]]
    request_before = [r for r in records if r['request'] and r['role'] == 'before']
    request_after = [r for r in records if r['request'] and r['role'] == 'after']
    response_before = [r for r in records if not r['request'] and r['role'] == 'before']
    response_after = [r for r in records if not r['request'] and r['role'] == 'after']
    response_drop_page = bool(response and 'Response was dropped by Burp extension.' in
                              html.unescape(base64.b64decode(response['body_base64']).decode('utf-8', 'replace')))
    dropped = is_burp_drop_response(response) or args.case == 'response-drop' and response_drop_page or bool(
        error and error['type'] in ('RemoteDisconnected', 'ConnectionResetError'))
    checks = dict(no_unexpected_transport_error=error is None or args.case in ('request-drop', 'response-drop') and dropped,
                  request_listener_pair=len(request_before) == len(request_after) == 1,
                  no_state_changing_action=observed['action_count'] == 0)
    if args.case == 'active-ready':
        checks.update(guard_before_main=bool(request_before and request_before[0]['first_line'].startswith('GET /entry?')),
                      observer_after_main=bool(request_after and request_after[0]['first_line'].startswith('POST /echo ')),
                      active_automatic_forward=bool(request_after and request_after[0]['after'] == constants['dont_intercept']),
                      one_rewritten_request=observed['event_count'] == 1 and observed['recent_events'][0]['method'] == 'POST')
    else:
        checks['prior_request_action_preserved'] = bool(request_before and request_after and request_before[0]['after'] == request_after[0]['after'])
    if args.case == 'request-drop':
        checks.update(no_request_forwarded=observed['event_count'] == 0, terminal_drop=dropped)
    elif args.case == 'response-drop':
        checks.update(response_listener_pair=len(response_before) == len(response_after) == 1,
                      prior_response_drop_preserved=bool(response_after and response_after[0]['after'] == constants['drop']),
                      request_once=observed['event_count'] == 1, terminal_drop=dropped)
    else:
        checks['successful_reply'] = bool(response and response.get('json', {}).get('request')) if not args.stateful_response else bool(
            response and response['status'] == 200 and ('csrf.' + run + '.h1').encode('ascii') in base64.b64decode(response['body_base64']))
        checks['request_once'] = observed['event_count'] == 1
        if args.case == 'manual-both':
            checks['response_intercept_preserved'] = bool(response_before and response_after and response_before[0]['after'] == response_after[0]['after'] == constants['do_intercept'])
    report = dict(kind='external-burp-k03-same-callback-action-instrumentation', scenario=args.case, mode=args.mode,
                  source_on_disk_sha256=hashlib.sha256((base.parents[1] / 'BoberProxy.py').read_bytes()).hexdigest(),
                  passed=all(checks.values()), checks=checks, observed=observed,
                  response=response, transport_error=error, action_trace=records,
                  stateful_response=args.stateful_response,
                  expected_cookie='sid.%s.h1' % run if args.stateful_response else None,
                  expected_token='csrf.%s.h1' % run if args.stateful_response else None,
                  note='Instrumented entry point calls the unchanged main method between before/after traces on the same real message. Mode/Forward require user confirmation; no retries.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(scenario=args.case, mode=args.mode, passed=report['passed'], checks=checks), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
