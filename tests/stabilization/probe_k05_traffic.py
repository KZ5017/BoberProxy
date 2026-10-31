"""K05 one-send wire checks; finite delays, no implicit retries."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import time

from probe_proxy import exchange, snapshot
from probe_transport import is_burp_drop_response


BASE = Path(__file__).resolve().parent
TRACE = BASE / 'runtime/k05-cases-trace.jsonl'
RUN = 'k00-workflow'


def traces():
    return [json.loads(line) for line in TRACE.read_text(encoding='utf-8').splitlines()] if TRACE.exists() else []


def reset():
    exchange('/__control/reset?run=' + RUN, method='POST', proxy_port=None)


def send(payload):
    return exchange('/entry?q=' + payload + '&w=TWO', headers=[('X-Bober-Test-Run', RUN)], timeout=8)


def run_case(case):
    reset()
    before = len(traces())
    payload = '%252F+%2B' if case == 'normal' else case
    reply = send(payload)
    early = snapshot(RUN, 18765)
    # Observe finite late results and any prohibited extra network sends.
    time.sleep(0.45)
    late = snapshot(RUN, 18765)
    added = traces()[before:]
    enters = [row for row in added if row['phase'] == 'enter']
    exits = [row for row in added if row['phase'] == 'exit']
    events = late['recent_events']
    checks = dict(no_late_extra_send=early['event_count'] == late['event_count'],
                  single_worker=len({row['thread_id'] for row in added}) <= 1,
                  owned_worker_group=all(row['thread_group'] == 'BoberProxy.custom.v1' for row in added))
    if case == 'normal':
        checks.update(action_once=late['action_count'] == 1, two_requests=late['event_count'] == 2,
                      normal_checkpage=reply.get('json', {}).get('cookie_ok') is True and reply.get('json', {}).get('token_ok') is True,
                      two_custom_calls=len(enters) == 2 and len(exits) == 2,
                      first_token_missing=bool(enters) and enters[0]['csrf_token'] is None,
                      raw_payloads=len(enters) == 2 and all(row['payload1'] == '%252F+%2B' and row['payload2'] == 'TWO' for row in enters),
                      rt_raw_body=bool(events) and base64.b64decode(events[0]['body_base64']) == b'one=%252F+%2B&two=TWO')
    elif case == 'after-rt':
        checks.update(action_once=late['action_count'] == 1, no_checkpage_or_original=late['event_count'] == 1
                      and events[0]['target'] == '/workflow/action', terminal_drop=is_burp_drop_response(reply),
                      separate_step_tokens=len(enters) == 2 and enters[0]['csrf_token'] is None
                      and enters[1]['csrf_token'] == 'csrf.k00-workflow.1',
                      late_user_result_observed_but_unused=len(exits) == 2)
    else:
        checks.update(no_action=late['action_count'] == 0, original_once=late['event_count'] == 1
                      and events[0]['target'] == '/entry?q=' + payload + '&w=TWO',
                      original_response=reply.get('json', {}).get('request', {}).get('target') == '/entry?q=' + payload + '&w=TWO')
        if case == 'top-timeout':
            checks.update(top_level_started=any(row['phase'] == 'top' for row in added), function_never_called=not enters)
        elif case == 'config-error':
            checks['no_custom_execution'] = not added
        elif case == 'function-timeout':
            checks.update(function_called_once=len(enters) == 1, late_result_not_sent=len(exits) == 1)
        else:
            checks['one_failed_transform'] = len(enters) == 1 and not exits
    return dict(kind='K05-real-Burp-wire-and-custom-trace', scenario=case, checks=checks,
                passed=all(checks.values()), response=reply, observed=late, early_observed=early, trace=added)


def concurrency():
    reset()
    before = len(traces())
    with ThreadPoolExecutor(max_workers=2) as clients:
        first = clients.submit(send, 'busy-active')
        end = time.monotonic() + 3
        while time.monotonic() < end:
            if any(row['phase'] == 'enter' and row['payload1'] == 'busy-active' for row in traces()[before:]):
                break
            time.sleep(0.01)
        else:
            raise RuntimeError('First finite custom call did not enter; no other request was sent')
        second = clients.submit(send, 'busy-queued')
        time.sleep(0.10)  # First function sleeps 0.8 seconds; queued call has time to reach Burp.
        rejected = send('busy-rejected')
        replies = [first.result(timeout=8), second.result(timeout=8)]
    state = snapshot(RUN, 18765)
    rows = traces()[before:]
    enters = [row for row in rows if row['phase'] == 'enter']
    depth, overlap = 0, False
    for row in rows:
        if row['phase'] == 'enter':
            depth += 1
            overlap = overlap or depth > 1
        elif row['phase'] == 'exit':
            depth -= 1
    posts = [event for event in state['recent_events'] if event['method'] == 'POST']
    checks = dict(two_actions=state['action_count'] == 2, three_target_requests=state['event_count'] == 3,
                  third_original_forwarded_once=rejected.get('json', {}).get('request', {}).get('target') == '/entry?q=busy-rejected&w=TWO',
                  two_template_posts=len(posts) == 2 and all(event['target'] == '/workflow/action' for event in posts),
                  accepted_clients_receive_target_html=all(b'csrfmiddlewaretoken' in base64.b64decode(reply['body_base64']) for reply in replies),
                  exactly_two_custom_calls=len(enters) == 2,
                  rejected_never_executed=all(row['payload1'] != 'busy-rejected' for row in enters),
                  one_worker_thread=len({row['thread_id'] for row in rows}) == 1,
                  custom_calls_never_overlap=not overlap and depth == 0)
    return dict(kind='K05-finite-real-Burp-concurrency', checks=checks, passed=all(checks.values()),
                responses=replies, rejected_response=rejected, observed=state, trace=rows,
                checkpage_enabled=False,
                session_pairing_not_acceptance='CheckPage is OFF to isolate executor capacity. Global RT/CheckPage session coordination remains K06.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True, choices=['normal', 'exception', 'bad-result', 'top-timeout', 'function-timeout', 'after-rt', 'config-error', 'concurrency'])
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.exists():
        raise RuntimeError('Do not overwrite an earlier attempt or retry automatically')
    report = concurrency() if args.case == 'concurrency' else run_case(args.case)
    report['source_on_disk_sha256'] = hashlib.sha256((BASE.parents[1] / 'BoberProxy.py').read_bytes()).hexdigest()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], checks=report['checks']), indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
