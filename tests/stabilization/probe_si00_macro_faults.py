"""Characterize a missing/slow macro token without retrying a parent request."""
import argparse
import hashlib
import json
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from probe_proxy import exchange, snapshot
from probe_si00_wire import command, read_json
from probe_si00_workflow import records


def new_events(before, after):
    sequence = max((event['sequence'] for event in before['recent_events']), default=0)
    return [event for event in after['recent_events'] if event['sequence'] > sequence]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', choices=['missing', 'slow'], required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise RuntimeError('Preserve previous attempts; choose a new report')
    root = Path(__file__).resolve().parents[2]
    runtime = Path(__file__).resolve().parent / 'runtime'
    state = read_json(runtime / 'si00-wire-state.json')
    if not state or state.get('state') != 'ready':
        raise RuntimeError('Live observer not ready')
    before = snapshot('si00-macro-template', 18781)
    trials, errors = [], []
    cleanup = dict(cleanup_complete=False)

    def request(via, timeout=7):
        run = 'si00-macro-' + args.scenario + '-' + via + '-' + uuid.uuid4().hex[:10]
        path = '/si00/echo?run=' + run + '&si00_token=OLD&value=%252F+%2B'
        trial = dict(run=run, via=via, client_timeout_seconds=timeout)
        started = time.monotonic()
        try:
            trial['result'] = (command(runtime, state, 'send', port=18781, path=path)
                               if via == 'api' else exchange(path, target_port=18781, timeout=timeout))
        except Exception as exc:
            trial['error'] = dict(type=type(exc).__name__, detail=str(exc))
        trial['elapsed_seconds'] = time.monotonic() - started
        trials.append(trial)
        return trial

    try:
        command(runtime, state, 'cleanup')
        api = request('api')
        if 'error' in api:
            raise RuntimeError('API operation outcome uncertain; inspect before more sends')
        # Verify the manually selected fixture before starting a second client.
        first_macro = new_events(before, snapshot('si00-macro-template', 18781))
        expected_path = '/si00/not-found' if args.scenario == 'missing' else '/delay'
        if len(first_macro) != 1 or urlsplit(first_macro[0]['target']).path != expected_path:
            raise RuntimeError('Macro profile differs from requested case; no second send')
        if args.scenario == 'slow' and parse_qs(urlsplit(first_macro[0]['target']).query).get('ms') != ['600']:
            raise RuntimeError('Slow macro must have a finite 600 ms delay; no second send')
        request('proxy', timeout=0.1 if args.scenario == 'slow' else 7)
        # Observe delayed delivery after client timeout; no second parent send.
        if args.scenario == 'slow':
            time.sleep(1.2)
        command(runtime, state, 'inspect')
        for trial in trials:
            trial['observed'] = snapshot(trial['run'], 18781)
        after = snapshot('si00-macro-template', 18781)
        wire = [record for record in records(runtime / 'si00-wire-trace.jsonl')
                if record.get('instance') == state['instance']
                and record.get('run') in {trial['run'] for trial in trials}]
        # A second bounded observation catches replay/late callbacks without HTTP retry.
        time.sleep(0.4)
        for trial in trials:
            trial['delayed_observed'] = snapshot(trial['run'], 18781)
        delayed_macro = snapshot('si00-macro-template', 18781)
        cleanup = command(runtime, state, 'cleanup')
    except Exception as exc:
        errors.append(dict(type=type(exc).__name__, detail=str(exc)))
        after = snapshot('si00-macro-template', 18781)
        delayed_macro = after
        wire = []
        # Do not submit more live commands after an unknown API outcome.
        for trial in trials:
            trial.setdefault('observed', snapshot(trial['run'], 18781))
            trial.setdefault('delayed_observed', trial['observed'])

    macro_events = new_events(before, after)
    callbacks = [record for record in wire if record.get('macro_count') == 1]
    parent_events = [event for trial in trials for event in trial['observed']['recent_events']]
    capabilities = dict(
        parent_reached_target={trial['via']: trial['observed']['event_count'] == 1 for trial in trials},
        sent_token_values=[parse_qs(urlsplit(event['target']).query).get('si00_token', [''])[0]
                           for event in parent_events],
        callback_without_extracted_token=bool(callbacks and all(not row['macro_tokens'] for row in callbacks)),
        client_timeout_observed=any(trial.get('error', {}).get('type') == 'TimeoutError' for trial in trials),
        api_elapsed_seconds=trials[0]['elapsed_seconds'] if trials else None)
    checks = dict(
        controller_completed=not errors,
        two_parent_attempts=len(trials) == 2,
        exactly_two_macro_requests=after['event_count'] - before['event_count'] == 2,
        macro_fixture_matches=bool(len(macro_events) == 2 and all(
            urlsplit(event['target']).path == ('/si00/not-found' if args.scenario == 'missing' else '/delay')
            for event in macro_events)),
        no_application_action=after['action_count'] == 0 and all(
            trial['observed']['action_count'] == 0 for trial in trials),
        no_parent_replay=all(trial['observed']['event_count'] <= 1 for trial in trials),
        no_delayed_extra_requests=after['event_count'] == delayed_macro['event_count'] and all(
            trial['observed']['event_count'] == trial['delayed_observed']['event_count'] for trial in trials),
        correlated_macro_items=len(callbacks) == 2 and all(
            sum(row['run'] == trial['run'] for row in callbacks) == 1 for trial in trials),
        raw_other_parameter_preserved=all('value=%252F+%2B' in event['target'].split('?', 1)[1].split('&')
                                          for event in parent_events),
        no_unowned_cookies=all(event['other_cookie_count'] == 0 for event in parent_events + macro_events),
        owned_cleanup=cleanup['cleanup_complete'])
    if args.scenario == 'slow':
        checks.update(finite_delay_observed=bool(trials and 0.55 <= trials[0]['elapsed_seconds'] < 7),
                      client_deadline_exercised=capabilities['client_timeout_observed'])
    else:
        checks['no_client_transport_errors'] = all('error' not in trial for trial in trials)
    report = dict(kind='SI00-macro-fault-characterization', scenario=args.scenario,
                  passed=all(checks.values()), checks=checks, capabilities=capabilities,
                  trials=trials, macro_before=before, macro_after=after,
                  delayed_macro=delayed_macro, wire_records=wire, errors=errors, cleanup=cleanup,
                  observer_instance=state['instance'],
                  source_sha256=hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest(),
                  note='Measurement success is not fail-closed behavior. No RT/CheckPage/application action, '
                       'HTTP retry, hard Burp timeout or cancellation guarantee is claimed.')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checks=checks, capabilities=capabilities), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
