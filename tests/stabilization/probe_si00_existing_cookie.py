"""Characterize native rules with an existing owned Cookie header, no retries."""
import argparse
import json
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
        raise RuntimeError('Use a new report; preserve previous attempts')
    runtime = Path(__file__).resolve().parent / 'runtime'
    state = read_json(runtime / 'si00-wire-state.json')
    if not state or state.get('state') != 'ready':
        raise RuntimeError('Live observer not ready')
    cases, errors = [], []
    cleanup = dict(cleanup_complete=False)
    for case in ('empty-jar', 'live-jar', 'expired-jar'):
        run = 'si00-existing-' + case + '-' + uuid.uuid4().hex[:10]
        item = dict(case=case, run=run)
        cases.append(item)
        try:
            command(runtime, state, 'cleanup')
            if case != 'empty-jar':
                command(runtime, state, 'seed', value='API_SEED')
            if case == 'expired-jar':
                item['expiry_reply'] = exchange('/si00/cookie?run=' + run + '&kind=expired_root', target_port=18781)
            item['jar_before_echo'] = command(runtime, state, 'inspect')['jar']
            item['reply'] = exchange('/si00/echo?run=' + run + '&value=%252F+%2B', target_port=18781,
                                     headers=[('Cookie', state['cookie_name'] + '=TEMPLATE')])
            item['observed'] = snapshot(run, 18781)
            item['cleanup'] = command(runtime, state, 'cleanup')
        except Exception as exc:
            errors.append(dict(case=case, type=type(exc).__name__, detail=str(exc)))
            item['observed'] = snapshot(run, 18781)
            break  # Inspect a possibly accepted operation, never replay.
    if not errors:
        cleanup = command(runtime, state, 'cleanup')
    wire = [row for row in records(runtime / 'si00-wire-trace.jsonl')
            if row.get('instance') == state['instance'] and row.get('run') in {item['run'] for item in cases}]
    capabilities = {}
    for item in cases:
        echo = [event for event in item['observed']['recent_events'] if event['target'].startswith('/si00/echo?')]
        capabilities[item['case']] = [value for event in echo for key, value in event['headers'] if key.lower() == 'cookie']
    checks = dict(controller_completed=not errors, three_cases=len(cases) == 3,
                  exact_target_counts=all(item['observed']['event_count'] == (2 if item['case'] == 'expired-jar' else 1)
                                          for item in cases),
                  no_application_action=all(item['observed']['action_count'] == 0 for item in cases),
                  raw_other_parameter_preserved=all(event['target'].endswith('value=%252F+%2B')
                      for item in cases for event in item['observed']['recent_events']
                      if event['target'].startswith('/si00/echo?')),
                  no_macro_triggered=all(row.get('macro_count') in (None, 0) for row in wire),
                  no_unowned_cookies=all(event['other_cookie_count'] == 0 for item in cases
                                         for event in item['observed']['recent_events']),
                  owned_cleanup=cleanup['cleanup_complete'])
    report = dict(kind='SI00-native-rule-existing-Cookie-header', passed=all(checks.values()),
                  checks=checks, cases=cases, capabilities=capabilities, wire_records=wire,
                  errors=errors, cleanup=cleanup, observer_instance=state['instance'],
                  note='Existing Cookie header measured on ordinary Proxy GETs. Main template/redirect path '
                       'requires its own separate fixture; not a Compatibility tombstone guarantee.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checks=checks, capabilities=capabilities), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
