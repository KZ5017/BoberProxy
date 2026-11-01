"""Drive only the live SI00 observer channel; never replay an application request."""
import argparse
import hashlib
import json
import time
import uuid
from pathlib import Path
from probe_proxy import exchange, snapshot


def read_json(path):
    try: return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError): return None


def command(runtime, state, operation, **values):
    payload = dict(instance=state['instance'], id=uuid.uuid4().hex, operation=operation, **values)
    path = runtime / 'si00-wire-command.json'
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(payload), encoding='utf-8')
    temporary.replace(path)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = read_json(runtime / 'si00-wire-result.json')
        if result and result.get('instance') == state['instance'] and result.get('id') == payload['id']:
            if not result['passed']: raise RuntimeError('SI00 command failed: ' + json.dumps(result))
            if result['trace_dropped']: raise RuntimeError('SI00 observation capacity exceeded')
            return result['result']
        time.sleep(0.05)
    raise TimeoutError('SI00 operation outcome unknown; inspect target/trace, do not replay')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', choices=['baseline', 'rules', 'inspect', 'cleanup'], required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    runtime = Path(__file__).resolve().parent / 'runtime'
    state = read_json(runtime / 'si00-wire-state.json')
    if not state or state.get('state') != 'ready': raise RuntimeError('Live SI00 observer not ready')
    if args.report.exists(): raise RuntimeError('Use a new report path; preserve previous attempts')
    if args.scenario in ('inspect', 'cleanup'):
        result = command(runtime, state, args.scenario)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result, indent=2))
        return 0
    health = exchange('/si00/health?run=si00-health', target_port=18780, proxy_port=None)
    if health.get('json', {}).get('cookie_name') != state['cookie_name']:
        raise RuntimeError('Wrong loopback fixture namespace')
    run = 'si00-' + args.scenario + '-' + uuid.uuid4().hex[:10]
    result, error = {}, None
    try:
        result['seed'] = command(runtime, state, 'seed', value='API_SEED')
        result['api'] = command(runtime, state, 'send', path='/si00/echo?run=' + run + '&via=api&value=%252F+%2B')
        result['proxy'] = exchange('/si00/echo?run=' + run + '&via=proxy&value=%252F+%2B', target_port=18780)
    except Exception as exc:
        error = dict(type=type(exc).__name__, detail=str(exc))
    if error is None:
        try: result['inspect'] = command(runtime, state, 'inspect')
        except Exception as exc: error = dict(type=type(exc).__name__, detail=str(exc))
    try:
        observed = snapshot(run, 18780)
    except Exception as exc:
        observed = dict(event_count=None,action_count=None,recent_events=[])
        error = error or dict(type=type(exc).__name__,detail=str(exc))
    trace_path = runtime / 'si00-wire-trace.jsonl'
    records = []
    if trace_path.exists():
        for line in trace_path.read_text().splitlines():
            try: records.append(json.loads(line))
            except ValueError: error = error or dict(type='IncompleteTrace',detail='Preserve capture; do not replay')
    records = [r for r in records if r.get('instance') == state['instance'] and r.get('run') == run]
    cookies = [value for e in observed['recent_events'] for key,value in e['headers'] if key.lower() == 'cookie']
    expected_cookie = state['cookie_name'] + '=API_SEED'
    rule_records = [r for r in records if r['phase'].startswith('rule-')]
    checks = dict(no_transport_error=error is None, exactly_two_target_requests=observed['event_count']==2,
                  no_actions=observed['action_count']==0,
                  query_preserved=all(e['target'].endswith('value=%252F+%2B') for e in observed['recent_events']),
                  no_unowned_cookies=all(e['other_cookie_count']==0 for e in observed['recent_events']))
    if args.scenario == 'baseline':
        checks.update(no_native_cookie_injection=not cookies, no_session_action_calls=not rule_records)
    else:
        checks.update(native_cookie_on_both_requests=cookies==[expected_cookie,expected_cookie],
                      both_rule_actions_for_each_request=len(rule_records)==4
                      and sum(r['phase']=='rule-before cookie' for r in rule_records)==2
                      and sum(r['phase']=='rule-after cookie' for r in rule_records)==2)
    if error is None:
        try: result['cleanup'] = command(runtime, state, 'cleanup')
        except Exception as exc: error = dict(type=type(exc).__name__,detail=str(exc))
    if 'cleanup' not in result:
        result['cleanup'] = dict(cleanup_complete=False,note='Outcome uncertain; inspect pending command before issuing more commands.')
    checks['no_transport_error'] = error is None
    checks['owned_cleanup_complete'] = result['cleanup']['cleanup_complete']
    report = dict(kind='SI00-wire-' + args.scenario, run=run, checks=checks,
                  passed=all(checks.values()), observed=observed, records=records, results=result,
                  transport_error=error, no_application_request_replayed=True,
                  observer_instance=state['instance'],cookie_name=state['cookie_name'],
                  source_sha256=hashlib.sha256((Path(__file__).resolve().parents[2]/'BoberProxy.py').read_bytes()).hexdigest())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checks=checks), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
