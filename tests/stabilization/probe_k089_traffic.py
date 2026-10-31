"""Real callback/EDT logging assertions through the explicitly loaded wrapper."""
import argparse
import hashlib
import json
import time
import traceback
import uuid
from pathlib import Path
from probe_proxy import exchange as base_exchange, snapshot

def exchange(path,**kwargs):
    kwargs.setdefault('target_port',18772)
    return base_exchange(path,**kwargs)


BASE=Path(__file__).resolve().parent
RUNTIME=BASE/'runtime'


def command(action):
    session=json.loads((RUNTIME/'k089-control-session.json').read_text())
    if session.get('target_port')!=18772: raise AssertionError('Reload the K089 entry for the isolated18772 fixture')
    request=dict(instance=session['instance'],id=uuid.uuid4().hex,action=action)
    temp=RUNTIME/'k089-command.tmp'
    temp.write_text(json.dumps(request),encoding='utf-8')
    replace_until=time.monotonic()+1
    while True:
        try:
            temp.replace(RUNTIME/'k089-command.json')
            break
        except PermissionError:
            if time.monotonic()>=replace_until:
                raise
            time.sleep(0.005)  # Windows read-handle sharing; no HTTP replay.
    end=time.monotonic()+5
    while time.monotonic()<end:
        try:
            reply=json.loads((RUNTIME/'k089-ack.json').read_text())
            if reply.get('instance')==request['instance'] and reply.get('id')==request['id']:
                if not reply.get('ok'):
                    raise AssertionError(reply.get('error'))
                return reply['state']
        except (OSError,ValueError):
            pass
        time.sleep(0.01)
    raise AssertionError('K089 command not acknowledged: '+action)


def wait_for(predicate,label):
    end=time.monotonic()+5
    while time.monotonic()<end:
        state=command('state')
        if predicate(state):
            return state
    raise AssertionError('K089 ordering point missing: '+label)


def idle(state):
    work=state['worker']
    return (not any(work[k] for k in ('rows','controls','results','active')) and not any(state['writer'][k] for k in ('rows','controls','results','active')) and not state['rebuilding'] and not state['dirty'] and not state['io_pending'] and not state['storage']['reading'])


def settled(expected_callbacks):
    # Two EDT snapshots cover a fast-path append queued just before callback
    # completion, as well as worker results applied through the Swing timer.
    predicate=lambda s:s['callbacks_done']>=expected_callbacks and idle(s)
    wait_for(predicate,'response callbacks/filter jobs completed')
    return wait_for(predicate,'second settled EDT snapshot')


def run(scenario,report):
    from concurrent.futures import ThreadPoolExecutor
    import base64
    import statistics
    run_id='k089-'+uuid.uuid4().hex[:12]
    report.update(run=run_id,checks={},responses=[],states={})
    checks,states=report['checks'],report['states']
    start=command('state')
    if not start.get('ready') or start['proxy'] or start['use_cp'] or start['custom']:
        raise AssertionError('Fresh scoped entry and template/custom options OFF required')
    report['source_sha256']=start['source_sha256']
    baseline=start['callbacks_done']
    initial_rejected=start['not_accepted']
    exchange('/__control/reset?run='+run_id,method='POST',proxy_port=None)
    for action in ('normal-budget','capture-none','display-none','clear'): command(action)
    settled(baseline)
    def send(path):
        result=exchange(path,headers=[('X-Bober-Test-Run',run_id)],timeout=8)
        data=base64.b64decode(result['body_base64'])
        wire_response=('HTTP/1.1 200 OK\r\n'+'\r\n'.join('%s: %s' % pair for pair in result['headers'])+'\r\n\r\n').encode('latin-1')+data
        summary=dict(path=path,status=result['status'],seconds=result['seconds'],body_sha256=hashlib.sha256(data).hexdigest(),wire_response_sha=hashlib.sha256(wire_response).hexdigest())
        report['responses'].append(summary)
        if result['status'] not in (200,204): raise AssertionError('Unexpected HTTP status')
        if path.startswith('/bytes?size='):
            size=int(path.split('=')[1])
            expected=(bytes(range(256))*((size+255)//256))[:size]
            if data!=expected:
                summary['unexpected_body_base64']=result['body_base64']
                raise AssertionError('Wire body changed')
        return summary
    def current(): return settled(baseline+len(report['responses']))
    if scenario=='burst':
        with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(send,['/bytes?size=1024']*64))
        states['burst']=current()
        checks['all_64_burst_rows_preserved']=len(states['burst']['stored'])==64 and len(states['burst']['displayed'])==64
        report['timing_trials']=[]
        for trial in range(3):
            times=[]
            started=time.monotonic()
            for index in range(100):
                time.sleep(max(0,started+index/25.0-time.monotonic()))
                times.append(send('/bytes?size=1024')['seconds'])
            ordered=sorted(times)
            report['timing_trials'].append(dict(trial=trial+1,count=100,target_rate=25,median_seconds=statistics.median(times),p95_seconds=ordered[95],max_seconds=max(times)))
        states['final']=current()
        checks['all_364_rows_and_order']=len(states['final']['stored'])==364 and states['final']['displayed']==list(range(364,0,-1))
        checks['no_overload']=states['final']['not_accepted']==initial_rejected and not states['final']['log_error']
    elif scenario=='filters':
        send('/echo?tag=TOKEN_ALPHA')
        send('/echo?tag=TOKEN_BETA')
        send('/bytes?size=1024')
        states['base']=current()
        command('display-tokens')
        states['filtered']=current()
        checks['disk_regex_two_matches']=len(states['filtered']['displayed'])==2 and len(states['filtered']['stored'])==3
        command('gate')
        wait_for(lambda s:s['gate_entered'],'held rebuild')
        send('/echo?tag=TOKEN_ALPHA')
        command('clear')
        states['clear']=command('state')
        command('release')
        states['released']=current()
        checks['old_rebuild_and_pending_rows_cannot_restore_clear']=not states['released']['stored'] and not states['released']['displayed']
        send('/echo?tag=TOKEN_BETA')
        states['final']=current()
        checks['fresh_generation_retained']=len(states['final']['stored'])==1 and states['final']['displayed']==[1]
    elif scenario in ('clear','pause'):
        command('gate-write')
        send('/bytes?size=17')
        wait_for(lambda s:s['gate_entered'],'held disk write')
        if scenario=='clear':
            command('clear')
            states['clear']=command('state')
            checks['clear_is_immediate']=not states['clear']['stored']
        else:
            command('pause')
            send('/bytes?size=19')
            states['paused']=command('state')
            checks['pause_does_not_block_HTTP']=states['paused']['paused']
        command('release')
        states['released']=current()
        if scenario=='clear':
            checks['old_write_does_not_restore_row']=not states['released']['stored']
        else:
            checks['accepted_before_pause_finishes']=len(states['released']['stored'])==1
            command('resume')
        send('/bytes?size=23')
        states['final']=current()
        checks['new_acceptance_works']=len(states['final']['stored'])==(1 if scenario=='clear' else 2) and not states['final']['log_error']
    elif scenario=='overload':
        command('tiny-budget')
        send('/bytes?size=1024')
        states['rejected']=current()
        checks['visible_bounded_rejection']=not states['rejected']['stored'] and 'LOG_BUSY' in (states['rejected']['log_error'] or '') and states['rejected']['not_accepted']==initial_rejected+1
        checks['no_raw_snapshot_retained']=states['rejected']['raw_bytes']==0
        command('normal-budget')
        send('/bytes?size=13')
        states['final']=current()
        checks['manual_resume_recovers']=len(states['final']['stored'])==1 and not states['final']['log_error']
    elif scenario=='write-error':
        send('/bytes?size=11')
        current()
        command('fail-write')
        send('/bytes?size=17')
        states['failed']=current()
        checks['disk_error_visible_and_old_row_retained']=len(states['failed']['stored'])==1 and 'STORAGE_WRITE_FAILED' in (states['failed']['log_error'] or '') and states['failed']['paused']
        send('/bytes?size=19')
        states['paused']=current()
        checks['paused_HTTP_continues_without_new_row']=len(states['paused']['stored'])==1
        command('resume')
        send('/bytes?size=23')
        states['final']=current()
        checks['resume_preserves_old_and_new']=len(states['final']['stored'])==2 and not states['final']['log_error']
    elif scenario=='viewer':
        for size in (11,13,17,19,23): send('/bytes?size='+str(size))
        states['base']=current()
        original_target=snapshot(run_id,18772)
        expected=[dict(request_sha=hashlib.sha256(base64.b64decode(event['raw_base64'])).hexdigest(),response_sha=report['responses'][index]['wire_response_sha']) for index,event in enumerate(original_target['recent_events'])]
        report['original_wire_digests']=expected
        command('gate-view')
        command('select-first')
        wait_for(lambda s:s['gate_entered'],'held first viewer')
        command('select-next')
        command('release')
        states['new_selection']=current()
        checks['late_selection_cannot_replace_newer']=states['new_selection']['viewer']==expected[-2]
        command('sort-asc')
        command('select-two')
        current()
        command('export')
        states['exported']=current()
        checks['sitemap_exact_sorted_selected_messages']=states['exported']['exports'][-2:]==[expected[i] for i in (0,2)]
        command('clear-selected')
        states['removed']=current()
        checks['clear_selected_keeps_other_ids']=states['removed']['displayed']==[5,4,2]
        wait_for(lambda s:s['storage']['files']==3,'selected-file cleanup')
        command('fail-read')
        command('select-first')
        states['read_error']=current()
        checks['read_error_visible']=states['read_error']['status'].startswith('STORAGE_READ_FAILED') and states['read_error']['viewer']['response_sha'] is None
        command('select-next')
        states['final']=current()
        checks['other_message_remains_readable']=states['final']['viewer']==expected[3]
    else: raise ValueError('Unknown scenario')
    final=states['final']
    checks['no_disk_IO_on_EDT']=not final['storage']['edt_io']
    checks['raw_byte_budget_returns_to_zero']=final['raw_bytes']==0
    target=snapshot(run_id,18772)
    report['target']=target
    checks['every_HTTP_request_forwarded_once']=target['event_count']==len(report['responses'])
    checks['no_workflow_action']=target['action_count']==0
    checks['same_main_source']=final['source_sha256']==report['source_sha256']
    report['passed']=all(checks.values())


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--scenario',choices=['burst','filters','clear','pause','overload','write-error','viewer'],required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists(): parser.error('Refusing to overwrite an existing report or replay a scenario')
    report=dict(kind='K089-real-Burp-scoped-logging-storage-wire',scenario=args.scenario,passed=False)
    try: run(args.scenario,report)
    except BaseException:
        report['error']=traceback.format_exc()
        if report.get('run'):
            try: report['target_after_failure']=snapshot(report['run'],18772)
            except BaseException: pass
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:report.get(k) for k in ('scenario','passed','checks','error')},indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__': raise SystemExit(main())
