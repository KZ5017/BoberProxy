"""Directed real Proxy traffic. Requires the explicitly loaded K06 test wrapper."""
import argparse
import base64
import hashlib
import html
import json
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from probe_proxy import exchange

BASE = Path(__file__).resolve().parent
RUNTIME = BASE / 'runtime'


def command(action):
    session = json.loads((RUNTIME / 'k06-control-session.json').read_text())
    request = dict(instance=session['instance'], id=uuid.uuid4().hex, action=action)
    temp = RUNTIME / 'k06-command.tmp'
    temp.write_text(json.dumps(request), encoding='utf-8')
    temp.replace(RUNTIME / 'k06-command.json')
    end = time.monotonic() + 5
    while time.monotonic() < end:
        try:
            ack = json.loads((RUNTIME / 'k06-ack.json').read_text())
            if ack.get('instance') == request['instance'] and ack.get('id') == request['id']:
                if not ack.get('ok'):
                    raise AssertionError(ack.get('error'))
                return ack['state']
        except (OSError, ValueError):
            pass
        time.sleep(0.01)
    raise AssertionError('K06 wrapper command timeout: ' + action)


def direct(path):
    return exchange(path, target_port=18770, proxy_port=None)['json']


def control(op, case='', step=''):
    return direct('/k06/control?op=%s&case=%s&step=%s' % (op, case, step))


def wait_for(predicate, label, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError('Ordering point not observed: ' + label)


def stages(case, step=None):
    return [row for row in control('events')['stages'] if row['case'] == case
            and (step is None or row['step'] == step)]


def received(case, step=None):
    return [row for row in stages(case, step) if row['stage'] == 'received']


def proxy(case, passive=False):
    path = '/k06/passive?case=' + case if passive else '/entry?q=' + case + '&w=TWO'
    return exchange(path, target_port=18770, timeout=35, headers=[('X-Bober-Test-Run', 'k06-wire')])


def successful(response, case):
    data = response.get('json', {})
    return response['status'] == 200 and data.get('case') == case and data.get('cookie_ok') and data.get('token_ok')


def dropped(response):
    text = base64.b64decode(response['body_base64']).decode('latin-1')
    return 'Request was dropped by Burp extension' in html.unescape(text)


def custom_records():
    path = RUNTIME / 'k06-custom-cases.jsonl'
    if not path.exists():
        return []
    text = path.read_text()
    if not text.endswith('\n'):
        text = text[:text.rfind('\n') + 1]
    return [json.loads(line) for line in text.splitlines()]


def run(scenario):
    checks, responses, observations = {}, {}, {}
    prefix = 'r' + uuid.uuid4().hex[:10]
    cases = []
    armed = []
    pool = ThreadPoolExecutor(3)
    futures = []
    def case(label):
        value = prefix + '_' + label
        cases.append(value)
        return value
    def arm(value, step):
        control('arm', value, step)
        armed.append((value, step))
    def release(value, step):
        control('release', value, step)
        armed.remove((value, step))
    def start(value):
        future = pool.submit(proxy, value)
        futures.append(future)
        return future
    try:
        observations['health'] = control('health')
        if observations['health']['fixture'] != 'K06-gated-v1':
            raise AssertionError('Wrong fixture version')
        observations['setup'] = command('setup')
        if observations['setup']['closed']:
            raise AssertionError('Wrapper source already unloaded')
        command('clear-cookies')
        command('clear-csrf')
        if scenario == 'normal':
            a = case('normal')
            responses[a] = proxy(a)
            checks['normal_two_step_pair'] = successful(responses[a], a)
            checks['two_requests'] = len(received(a)) == 2
            wait_for(lambda: command('state')['owner'] is None, 'final normal response release')
            checks['final_state'] = command('state')['csrf'] == 'K06_FINAL_' + a
        elif scenario == 'pairing':
            a, b, p = case('A_pause'), case('B'), case('PASSIVE')
            arm(a, 'action')
            arm(a, 'check')
            first = start(a)
            wait_for(lambda: bool(received(a, 'action')), 'RT A received')
            second = start(b)
            wait_for(lambda: command('state')['waiting'] == 1, 'B queued behind A')
            checks['B_not_sent_while_A_RT_waits'] = not received(b)
            release(a, 'action')
            wait_for(lambda: any(r.get('payload1') == a and r.get('pause') for r in custom_records()), 'A CheckPage custom pause')
            responses[p] = proxy(p, passive=True)
            observations['passive_midflow'] = command('state')
            checks['passive_updates_global_during_owner'] = observations['passive_midflow']['csrf'] == 'K06_' + p
            (RUNTIME / (a + '.release')).write_text('released', encoding='ascii')
            wait_for(lambda: bool(received(a, 'check')), 'CP A received')
            checks['CP_A_has_own_RT_cookie_token'] = (received(a, 'check')[0]['csrf'] == 'K06_' + a
                and received(a, 'check')[0]['cookie'] == 'sid=K06_' + a)
            checks['B_waits_through_final_CP_response'] = not received(b) and not second.done()
            release(a, 'check')
            responses[a], responses[b] = first.result(10), second.result(10)
            checks['A_pair_passes'] = successful(responses[a], a)
            checks['B_pair_passes'] = successful(responses[b], b)
            checks['B_seeds_final_A_state'] = received(b, 'action')[0]['cookie'] == 'sid=K06_FINAL_' + a
            checks['exactly_two_requests_each'] = len(received(a)) == len(received(b)) == 2
        elif scenario in ('clear-rt', 'unload'):
            a = case('LATE_RT')
            arm(a, 'action')
            future = start(a)
            wait_for(lambda: bool(received(a, 'action')), 'held RT received')
            observations['before_action'] = command('state')
            observations['after_action'] = command('clear-cookies' if scenario == 'clear-rt' else 'unload')
            release(a, 'action')
            responses[a] = future.result(10)
            checks['one_action_no_CheckPage'] = len(received(a)) == 1
            checks['terminal_drop'] = dropped(responses[a])
            observations['late_state'] = command('state')
            checks['late_RT_not_published'] = observations['late_state']['sid'] is None and observations['late_state']['csrf'] is None
            if scenario == 'clear-rt':
                b = case('RECOVER')
                responses[b] = proxy(b)
                checks['new_epoch_normal_flow'] = successful(responses[b], b)
            else:
                wait_for(lambda: not command('state')['publisher_running'], 'unload publisher stop')
                checks['closed_runtime'] = command('state')['closed']
        elif scenario == 'clear-final':
            a, b = case('LATE_CP'), case('NEW_EPOCH')
            arm(a, 'check')
            first = start(a)
            wait_for(lambda: bool(received(a, 'check')), 'held final CP received')
            observations['old_owner'] = command('state')
            cleared = command('clear-csrf')
            checks['clear_releases_committed_owner'] = cleared['owner'] is None and cleared['csrf'] is None
            responses[b] = proxy(b)
            wait_for(lambda: command('state')['owner'] is None, 'new epoch owner completed')
            before_late = command('state')
            release(a, 'check')
            responses[a] = first.result(10)
            wait_for(lambda: len(stages(a)) >= 4, 'late response sent')
            time.sleep(0.1)
            observations['after_late'] = command('state')
            checks['new_epoch_succeeds_before_old_final'] = successful(responses[b], b)
            checks['committed_CP_can_finish'] = successful(responses[a], a)
            checks['late_final_cannot_restore_old_state'] = (before_late['sid'] == observations['after_late']['sid'] == 'K06_FINAL_' + b
                and before_late['csrf'] == observations['after_late']['csrf'] == 'K06_FINAL_' + b)
            checks['two_requests_per_flow'] = len(received(a)) == len(received(b)) == 2
        elif scenario == 'config':
            a, b = case('FROZEN'), case('PROXY_OFF')
            arm(a, 'action')
            future = start(a)
            wait_for(lambda: bool(received(a, 'action')), 'held RT before configuration edit')
            observations['changed'] = command('change')
            release(a, 'action')
            responses[a] = future.result(10)
            checks['started_flow_keeps_old_configuration'] = successful(responses[a], a)
            checks['original_checkpage_used'] = [r['step'] for r in received(a)] == ['action', 'check']
            responses[b] = proxy(b)
            checks['new_request_uses_proxy_OFF'] = responses[b].get('json', {}).get('request', {}).get('target') == '/entry?q=' + b + '&w=TWO'
            checks['no_template_for_new_request'] = not received(b)
            wait_for(lambda: command('state')['owner'] is None, 'frozen owner release')
            checks['old_response_flags_still_publish'] = command('state')['csrf'] == 'K06_FINAL_' + a
        else:
            raise ValueError('Unknown scenario')
    finally:
        for value, step in list(armed):
            control('release', value, step)
        for value in cases:
            if value.endswith('_pause'):
                (RUNTIME / (value + '.release')).write_text('cleanup', encoding='ascii')
        pool.shutdown(wait=True)
        observations['cases'] = cases
        observations['stages'] = [row for row in control('events')['stages'] if row['case'] in cases]
    checks['no_fixture_gate_timeout'] = all(row['stage'] != 'gate-timeout' for row in observations['stages'])
    return dict(checks=checks, responses=responses, observations=observations,
                passed=bool(checks) and all(checks.values()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', required=True, choices=['normal','pairing','clear-rt','clear-final','config','unload'])
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error('Existing evidence will not be overwritten; inspect it before choosing a new report path.')
    report = dict(kind='K06-external-Burp-wire-with-explicit-test-wrapper', scenario=args.scenario,
                  source_on_disk_sha256=hashlib.sha256((BASE.parents[1] / 'BoberProxy.py').read_bytes()).hexdigest())
    try:
        report.update(run(args.scenario))
    except Exception:
        report.update(passed=False, error=traceback.format_exc())
    report['wrapper_session'] = json.loads((RUNTIME / 'k06-control-session.json').read_text())
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('scenario','passed','checks','error') if k in report}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
