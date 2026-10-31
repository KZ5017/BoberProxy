"""Real callback/EDT logging assertions through the explicitly loaded wrapper."""
import argparse
import hashlib
import json
import time
import traceback
import uuid
from pathlib import Path
from probe_proxy import exchange,snapshot

BASE=Path(__file__).resolve().parent
RUNTIME=BASE/'runtime'


def command(action):
    session=json.loads((RUNTIME/'k07-control-session.json').read_text())
    request=dict(instance=session['instance'],id=uuid.uuid4().hex,action=action)
    temp=RUNTIME/'k07-command.tmp'
    temp.write_text(json.dumps(request),encoding='utf-8')
    replace_until=time.monotonic()+1
    while True:
        try:
            temp.replace(RUNTIME/'k07-command.json')
            break
        except PermissionError:
            if time.monotonic()>=replace_until:
                raise
            time.sleep(0.005)  # Windows read-handle sharing; no HTTP replay.
    end=time.monotonic()+5
    while time.monotonic()<end:
        try:
            reply=json.loads((RUNTIME/'k07-ack.json').read_text())
            if reply.get('instance')==request['instance'] and reply.get('id')==request['id']:
                if not reply.get('ok'):
                    raise AssertionError(reply.get('error'))
                return reply['state']
        except (OSError,ValueError):
            pass
        time.sleep(0.01)
    raise AssertionError('K07 command not acknowledged: '+action)


def wait_for(predicate,label):
    end=time.monotonic()+5
    while time.monotonic()<end:
        state=command('state')
        if predicate(state):
            return state
    raise AssertionError('K07 ordering point missing: '+label)


def idle(state):
    work=state['worker']
    return not any(work[k] for k in ('rows','controls','results','active')) and not state['rebuilding'] and not state['dirty']


def settled(expected_callbacks):
    # Two EDT snapshots cover a fast-path append queued just before callback
    # completion, as well as worker results applied through the Swing timer.
    predicate=lambda s:s['callbacks_done']>=expected_callbacks and idle(s)
    wait_for(predicate,'response callbacks/filter jobs completed')
    return wait_for(predicate,'second settled EDT snapshot')


def visible_paths(state):
    selected=set(state['displayed'])
    return [e['path'] for e in state['stored'] if e['index'] in selected]


def run(scenario,report):
    run_id='k07-'+uuid.uuid4().hex[:12]
    report.update(run=run_id,checks={},responses=[],states={})
    checks,states=report['checks'],report['states']
    start=command('state')
    if not start.get('ready') or start['proxy'] or start['use_cp'] or start['custom']:
        raise AssertionError('Fresh wrapper with template/custom options OFF required')
    baseline=start['callbacks_done']
    exchange('/__control/reset?run='+run_id,method='POST',proxy_port=None)
    def profile(action):
        command(action)
        return settled(baseline+len(report['responses']))
    def send(label,path):
        record=dict(label=label,path=path)
        report['responses'].append(record)
        record['response']=exchange(path,headers=[('X-Bober-Test-Run',run_id)],timeout=7)
        if record['response']['status'] not in (200,204):
            raise AssertionError('Unexpected target status')
    def current():
        return settled(baseline+len(report['responses']))
    def corpus():
        for label,path in [('alpha','/echo?tag=TOKEN_ALPHA'),('beta','/echo?tag=TOKEN_BETA'),
                           ('comma','/echo?value=a,b'),('empty','/empty'),('bytes','/bytes?size=8')]:
            send(label,path)
        return current()
    def sizes():
        for size in (3,8):
            send('size'+str(size),'/bytes?size='+str(size))
        send('zero','/empty')
        return current()
    try:
        profile('capture-none')
        profile('display-none')
        profile('clear')
        if scenario=='display':
            states['base']=corpus()
            checks['all_five_recorded']=len(states['base']['stored'])==len(states['base']['displayed'])==5
            states['tokens']=profile('display-tokens')
            checks['two_OR_patterns']=set(visible_paths(states['tokens']))=={'/echo?tag=TOKEN_ALPHA','/echo?tag=TOKEN_BETA'}
            before=states['tokens']['compile_patterns']
            send('new-alpha','/echo?tag=TOKEN_ALPHA')
            states['new_row']=current()
            checks['new_row_not_lost']=len(states['new_row']['stored'])==6 and len(states['new_row']['displayed'])==3
            checks['no_recompile_per_response']=states['new_row']['compile_patterns']==before
            states['comma']=profile('display-comma')
            checks['quantifier_and_literal_comma_preserved']=visible_paths(states['comma'])==['/echo?value=a,b']
            states['status']=profile('display-status')
            checks['metadata_filter']=visible_paths(states['status'])==['/empty']
            states['invalid']=profile('display-invalid')
            checks['invalid_display_keeps_last_valid']=states['invalid']['displayed']==states['status']['displayed'] and bool(states['invalid']['display_error'])
            states['reset']=profile('display-none')
            checks['display_never_erases_store']=len(states['reset']['stored'])==len(states['reset']['displayed'])==6
        elif scenario=='capture':
            states['alpha_profile']=profile('capture-alpha')
            send('alpha','/echo?tag=TOKEN_ALPHA')
            send('beta','/echo?tag=TOKEN_BETA')
            states['alpha']=current()
            checks['admission_regex_selects_one']=visible_paths(states['alpha'])==['/echo?tag=TOKEN_ALPHA'] and len(states['alpha']['stored'])==1
            checks['no_capture_recompile_per_response']=states['alpha']['compile_patterns']==states['alpha_profile']['compile_patterns']
            states['invalid_profile']=profile('capture-invalid')
            profile('clear')
            send('alpha-invalid-draft','/echo?tag=TOKEN_ALPHA')
            send('beta-invalid-draft','/echo?tag=TOKEN_BETA')
            states['invalid_regex']=current()
            checks['invalid_capture_preserves_filter']=states['invalid_regex']['capture_pattern']=='TOKEN_ALPHA' and len(states['invalid_regex']['stored'])==1 and bool(states['invalid_regex']['capture_error'])
            profile('capture-lower')
            profile('clear')
            send('case-sensitive','/echo?tag=TOKEN_ALPHA')
            states['case_sensitive']=current()
            checks['capture_remains_case_sensitive']=not states['case_sensitive']['stored']
            states['min_profile']=profile('capture-min')
            profile('clear')
            states['min']=sizes()
            checks['min_uses_smallest_threshold']=sorted(e['body_len'] for e in states['min']['stored'])==[3,8]
            checks['no_numeric_parse_per_row']=states['min']['parse_numbers']==states['min_profile']['parse_numbers']
            states['max_profile']=profile('capture-max')
            checks['unchanged_numeric_condition_reused']=states['max_profile']['parse_numbers']==states['min']['parse_numbers']
            profile('clear')
            states['max']=sizes()
            checks['max_uses_largest_threshold']=sorted(e['body_len'] for e in states['max']['stored'])==[0,3]
            profile('capture-noteq')
            profile('clear')
            states['noteq']=sizes()
            checks['not_equal_uses_set']=[e['body_len'] for e in states['noteq']['stored']]==[8]
            profile('capture-bad-number')
            profile('clear')
            states['invalid_number']=sizes()
            checks['invalid_number_preserves_condition']=states['invalid_number']['numbers']==[0,3] and bool(states['invalid_number']['capture_error']) and [e['body_len'] for e in states['invalid_number']['stored']]==[8]
        elif scenario=='clear':
            states['base']=corpus()
            profile('display-tokens')
            command('gate')
            states['gated']=wait_for(lambda s:s['gate_entered'] and s['worker']['active'],'finite rebuild gate entered')
            send('queued-before-clear','/echo?tag=TOKEN_ALPHA')
            states['queued']=wait_for(lambda s:s['callbacks_done']>=baseline+len(report['responses']) and s['worker']['rows']>=1,'new response queued behind held search')
            states['clear']=command('clear')
            checks['clear_is_immediate']=not states['clear']['stored'] and not states['clear']['displayed'] and states['clear']['worker']['active']
            checks['epoch_advanced']=states['clear']['epoch']>states['gated']['epoch']
            command('release')
            states['released']=current()
            checks['no_old_snapshot_or_pending_row_restored']=not states['released']['stored'] and not states['released']['displayed']
            send('new-after-clear','/echo?tag=TOKEN_BETA')
            states['fresh']=current()
            checks['new_generation_row_preserved']=visible_paths(states['fresh'])==['/echo?tag=TOKEN_BETA'] and len(states['fresh']['stored'])==1
        else:
            raise ValueError('Unknown scenario')
        final=current()
        states['final']=final
        checks['no_unexpected_overload']=final['rejected']==0
        observed=snapshot(run_id,18765)
        report['target']=observed
        checks['all_HTTP_requests_forwarded_once']=observed['event_count']==len(report['responses']) and observed['action_count']==0
        report['wrapper_session']=json.loads((RUNTIME/'k07-control-session.json').read_text())
        checks['same_main_source']=report['wrapper_session']['source_sha256']==report['source_on_disk_sha256']
    finally:
        if scenario=='clear':
            command('release')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--scenario',required=True,choices=['display','capture','clear'])
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    if args.report.exists():
        parser.error('Existing evidence will not be overwritten; inspect it before selecting a new path.')
    report=dict(kind='K07-real-Burp-filter-wire-with-explicit-test-entry',scenario=args.scenario,
                source_on_disk_sha256=hashlib.sha256((BASE.parents[1]/'BoberProxy.py').read_bytes()).hexdigest())
    try:
        run(args.scenario,report)
        report['passed']=bool(report['checks']) and all(report['checks'].values())
    except Exception:
        report.update(passed=False,error=traceback.format_exc())
        if report.get('run'):
            try:
                report['target']=snapshot(report['run'],18765)
            except Exception:
                report['target_error']=traceback.format_exc()
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('scenario','passed','checks','error') if k in report},indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
