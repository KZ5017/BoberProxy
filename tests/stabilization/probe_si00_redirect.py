"""One real main-source RT/redirect/CheckPage workflow with template cookies."""
import argparse
import base64
import hashlib
import json
import time
import uuid
from pathlib import Path

from probe_proxy import exchange, snapshot
from probe_si00_wire import command, read_json
from probe_si00_workflow import records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise RuntimeError('Preserve previous attempts; choose a new report')
    root = Path(__file__).resolve().parents[2]
    runtime = Path(__file__).resolve().parent / 'runtime'
    state = read_json(runtime / 'si00-wire-state.json')
    if not state or state.get('state') != 'ready':
        raise RuntimeError('Live observer not ready')
    # Reuse the already loaded, scoped normal trace; no interleave gate.
    run = 'si00-normal-' + uuid.uuid4().hex[:10]
    cleanup = dict(cleanup_complete=False)
    error, response = None, None
    command(runtime, state, 'cleanup')
    macro_before = snapshot('si00-macro-template', 18781)
    try:
        response = exchange('/si00/entry?run=' + run + '&q=' + run + '&w=%252F+%2B',
                            target_port=18781, timeout=7)
    except Exception as exc:
        error = dict(type=type(exc).__name__, detail=str(exc))
    observed = snapshot(run, 18781)
    custom = [row for row in records(runtime / 'si00-workflow-custom.jsonl') if row.get('run') == run]
    # Inspection/cleanup contain no network send and follow the completed client.
    if error is None:
        cleanup = command(runtime, state, 'cleanup')
    wire = [row for row in records(runtime / 'si00-wire-trace.jsonl')
            if row.get('instance') == state['instance'] and row.get('run') == run]
    time.sleep(0.5)
    delayed = snapshot(run, 18781)
    macro_after = snapshot('si00-macro-template', 18781)
    events = observed['recent_events']
    cookies = [[value for key, value in event['headers'] if key.lower() == 'cookie'] for event in events]
    name = state['cookie_name']
    expected_start = ('one=' + run + '&two=%252F+%2B').encode('ascii')
    token = custom[-1].get('csrf_token') if custom else None
    expected_check = ('csrf=' + (token or '') + '&one=' + run + '&two=%252F+%2B').encode('ascii')
    native_before = [row['own_cookie_values'] for row in wire if row['phase'] == 'rule-before cookie']
    native_after = [row['own_cookie_values'] for row in wire if row['phase'] == 'rule-after cookie']
    checks = dict(
        no_transport_error=error is None,
        final_http_200=bool(response and response['status'] == 200),
        exactly_three_target_requests=observed['event_count'] == 3,
        no_application_action=observed['action_count'] == 0,
        exact_methods_and_targets=bool(len(events) == 3
            and [event['method'] for event in events] == ['POST', 'GET', 'POST']
            and [event['target'] for event in events] == ['/si00/start?run=' + run,
                 '/si00/deep/echo?run=' + run, '/si00/check?run=' + run]),
        raw_template_bodies_preserved=bool(len(events) == 3
            and base64.b64decode(events[0]['body_base64']) == expected_start
            and not base64.b64decode(events[1]['body_base64'])
            and base64.b64decode(events[2]['body_base64']) == expected_check),
        template_then_native_cookie=cookies == [[name + '=TEMPLATE'], [name + '=REDIRECT'], [name + '=REDIRECT']],
        native_rule_order=native_before == [['TEMPLATE'], [], ['TEMPLATE']]
                          and native_after == [['TEMPLATE'], ['REDIRECT'], ['REDIRECT']],
        two_custom_calls=len(custom) == 2 and not any(row['gated'] for row in custom),
        no_macro_triggered=macro_before['event_count'] == macro_after['event_count'],
        no_unowned_cookies=all(event['other_cookie_count'] == 0 for event in events),
        no_delayed_extra_requests=delayed['event_count'] == observed['event_count'],
        owned_cleanup=cleanup['cleanup_complete'])
    report = dict(kind='SI00-main-native-cookie-redirect-and-template', passed=all(checks.values()),
                  checks=checks, run=run, response=response, observed=observed, delayed=delayed,
                  native_before=native_before, native_after=native_after, custom=custom,
                  wire_records=wire, error=error, cleanup=cleanup, macro_before=macro_before,
                  macro_after=macro_after, observer_instance=state['instance'],
                  source_sha256=hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest(),
                  note='No token-producing action in this redirect fixture. Echo cookie_ok/token_ok '
                       'and custom trace phase heuristic are not the verdict; compare raw requests, '
                       'rule order and exact target counts. No replay or Compatibility behavior change.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checks=checks), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
