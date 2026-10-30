"""K01 failure scenarios. Each invocation sends exactly one client request."""
import argparse
import base64
import hashlib
import html
import http.client
import json
import time
from pathlib import Path

from probe_proxy import exchange, snapshot


def is_burp_drop_response(response):
    if response is None:
        return False
    body = base64.b64decode(response.get('body_base64', '')).decode('utf-8', 'replace')
    return 'Request was dropped by Burp extension.' in html.unescape(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', required=True,
                        choices=['preflight-empty', 'post-build-failure', 'post-send-failure'])
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    run = 'k00-workflow'
    exchange('/__control/reset?run=' + run, method='POST', proxy_port=None)
    transport_error = None
    response = None
    try:
        response = exchange('/entry?q=%252F+%2B&w=TWO', headers=[('X-Bober-Test-Run', run)])
    except (OSError, ValueError, http.client.HTTPException) as error:
        transport_error = dict(type=type(error).__name__, message=str(error))
    # This is a direct control read, not a retry of the application request.
    observed = snapshot(run, 18765)
    observation_samples = []
    if args.scenario != 'preflight-empty':
        # Observe late requests too; these control reads never retry the operation.
        started = time.monotonic()
        while time.monotonic() - started < 1.0:
            time.sleep(0.1)
            observed = snapshot(run, 18765)
            observation_samples.append(dict(seconds=round(time.monotonic() - started, 3),
                                            event_count=observed['event_count'],
                                            action_count=observed['action_count']))
    events = observed['recent_events']
    if args.scenario == 'preflight-empty':
        checks = dict(no_action_sent=observed['action_count'] == 0,
                      original_forwarded_once=len(events) == 1 and events[0]['method'] == 'GET'
                      and events[0]['target'] == '/entry?q=%252F+%2B&w=TWO',
                      original_response=response is not None and response['status'] == 200
                      and response.get('json', {}).get('request', {}).get('method') == 'GET')
    else:
        expected_target = '/workflow/action' if args.scenario == 'post-build-failure' else '/accept-then-close'
        checks = dict(action_once=observed['action_count'] == 1,
                      only_expected_operation=len(events) == 1 and events[0]['method'] == 'POST'
                      and events[0]['target'] == expected_target,
                      no_checkpage_or_original_forwarded=not any(
                          event['target'].startswith(('/workflow/check', '/entry')) for event in events),
                      terminal_drop_observed=is_burp_drop_response(response) or bool(
                          transport_error and transport_error['type'] in ('RemoteDisconnected', 'ConnectionResetError')))
    root = Path(__file__).resolve().parents[2]
    report = dict(kind='external-burp-transport-failure-scenario', scenario=args.scenario,
                  passed=all(checks.values()), checks=checks, observed=observed,
                  response=response, transport_error=transport_error,
                  burp_drop_page=is_burp_drop_response(response),
                  observation_samples=observation_samples,
                  client_timed_out=bool(transport_error and transport_error['type'] in ('TimeoutError', 'timeout')),
                  source_on_disk_sha256=hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest(),
                  note='UI setup and loaded revision must be confirmed separately. No client retries.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(scenario=args.scenario, passed=report['passed'], checks=checks,
                          client_status=response['status'] if response else None,
                          transport_error=transport_error), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
