"""Fixed-duration live K11 reference/burst/soak controller; one at a time.

Requires a user-confirmed K11 instrumented entry. All data is synthetic, loopback
only. No HTTP retry, no GC in Burp, no arbitrary command/code channel.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import time
import traceback
import uuid
from k11_control import command, settled, state
from probe_proxy import exchange, snapshot


def distribution(values):
    values=sorted(values)
    def at(f): return values[min(len(values)-1,int((len(values)-1)*f))] if values else None
    return dict(count=len(values),median=at(.5),p95=at(.95),p99=at(.99),maximum=max(values) if values else None)


def send(path,run):
    return exchange(path,target_port=18790,headers=[('X-Bober-Test-Run',run)],timeout=35)


def clean():
    command('display-none'); settled()
    command('clear')
    end=time.monotonic()+60
    while time.monotonic()<end:
        value=settled()
        if not value['archive']['retired'] and not value['archive']['deleted']: return value
        time.sleep(.1)
    raise AssertionError('Prior own archive did not drain')


def reference(report):
    command('profile-passive'); clean()
    # Warm up parsing, archive and table before the three measurement windows.
    for index in range(25): send('/bytes?size=1024&warmup='+str(index),'k11-warmup')
    settled(); clean()
    report['iterations']=[]
    expected=bytes(range(256))*4
    for iteration in range(1,4):
        clean(); command('metrics-reset')
        tag='k11-reference-'+uuid.uuid4().hex[:12]
        timings,samples=[],[]
        started=time.monotonic()
        for index in range(200):
            time.sleep(max(0,started+index/25-time.monotonic()))
            result=send('/bytes?size=1024&sample='+str(index),tag)
            assert result['status']==200 and base64.b64decode(result['body_base64'])==expected
            timings.append(result['seconds']*1000)
            if index%25==24: samples.append(state())
        final=settled()
        metrics=command('metrics-stop')['metrics']
        observed=snapshot(tag,18790)
        checks=dict(all_200_once=observed['event_count']==200 and observed['action_count']==0,
                    all_200_logged=final['stored']==200 and final['displayed']==200,
                    all_200_measured=len(metrics['http_ms'])==200 and len(metrics['appearance_ms'])==200,
                    no_rejections=final['rejected']==0 and not final['log_error'],
                    no_edt_disk_io=not final['counts']['edt_io'],raw_budget_zero=final['raw_bytes']==0,
                    heartbeat_p95_at_most_100ms=distribution(metrics['heartbeat_ms'])['p95']<=100,
                    heartbeat_max_at_most_1000ms=distribution(metrics['heartbeat_ms'])['maximum']<=1000,
                    appearance_p99_at_most_1000ms=distribution(metrics['appearance_ms'])['p99']<=1000)
        report['iterations'].append(dict(iteration=iteration,run=tag,rate=25,count=200,body_bytes=1024,
            elapsed_seconds=time.monotonic()-started,client_ms=distribution(timings),
            metrics={key:distribution(values) for key,values in metrics.items()},raw_metrics=metrics,
            samples=samples,final=final,target=observed,checks=checks,passed=all(checks.values())))
        print('K11 live reference %d: %s' % (iteration,'PASS' if all(checks.values()) else 'FAIL'),flush=True)
        if not all(checks.values()): raise AssertionError('Reference gate failed')
    report['passed']=all(item['passed'] for item in report['iterations'])
    report['baseline_boundary']='K00 has external latency only; callback/EDT baseline absent. Unique sample query distinguishes per-row appearance; no exact old callback +10% verdict.'


def burst(report):
    command('profile-passive'); clean(); command('metrics-reset')
    run='k11-burst-'+uuid.uuid4().hex[:12]
    started=time.monotonic()
    with ThreadPoolExecutor(max_workers=64) as pool:
        responses=list(pool.map(lambda i:send('/bytes?size=1024&burst='+str(i),run),range(128)))
    final=settled()
    raw=command('metrics-stop')['metrics']
    observed=snapshot(run,18790)
    checks=dict(all_responses_correct=all(r['status']==200 and base64.b64decode(r['body_base64'])==bytes(range(256))*4 for r in responses),
                every_request_once=observed['event_count']==128,all_logged=final['stored']==128,
                no_rejections=not final['rejected'] and not final['log_error'],
                no_edt_disk_io=not final['counts']['edt_io'],raw_budget_zero=final['raw_bytes']==0)
    report.update(run=run,seconds=time.monotonic()-started,target=observed,final=final,
                  metrics={key:distribution(values) for key,values in raw.items()},checks=checks,passed=all(checks.values()))


def soak(report):
    # 30 minutes of mixed traffic with fixed, recorded profile/UI transitions.
    command('profile-passive'); clean(); command('metrics-reset')
    started=time.monotonic()
    next_due=started
    report.update(samples=[],transitions=[],client_count=0,expected_target_count=0,
                  expected_log_total=0,checks={},workflow_failures=[])
    run='k11-soak-'+uuid.uuid4().hex[:10]
    report['run']=run
    profile,paused,display,last_clear=None,False,None,-1
    expected_rows=0
    observed_log_total=0
    target_counts={}
    while time.monotonic()-started<1800:
        elapsed=time.monotonic()-started
        minute=int(elapsed//60)
        desired=('passive','normal','redirect-on')[minute%3]
        if desired!=profile:
            command('profile-'+desired); profile=desired; paused=False
            report['transitions'].append(dict(seconds=elapsed,action='profile-'+profile))
        desired_pause=45<=elapsed%60<48
        if desired_pause!=paused:
            command('pause' if desired_pause else 'resume'); paused=desired_pause
            report['transitions'].append(dict(seconds=elapsed,action='pause' if paused else 'resume'))
        desired_display=int(elapsed//20)%2
        if display!=desired_display:
            command('display-bytes' if desired_display else 'display-none'); display=desired_display
            report['transitions'].append(dict(seconds=elapsed,action='display-bytes' if display else 'display-none'))
        clear_slot=int(elapsed//300)
        if clear_slot!=last_clear:
            before=settled()
            assert before['stored']==expected_rows,'Accepted log count differs before Clear'
            observed_log_total+=before['stored']
            command('clear'); expected_rows=0; last_clear=clear_slot
            report['transitions'].append(dict(seconds=elapsed,action='clear'))
        index=report['client_count']
        is_workflow=profile!='passive' and index%4==0
        if is_workflow:
            tag='k11-soak-%s-%d' % (run[-10:],index)
            response=send('/entry?q='+tag+'&w=%252F+%2B',tag)
            count=3 if profile=='redirect-on' else 2
            if not response.get('json',{}).get('cookie_ok') or not response.get('json',{}).get('token_ok'):
                report['workflow_failures'].append(dict(run=tag,response=response))
                raise AssertionError('Mixed workflow state pairing failed')
            # Verify target-side counters for every operation, including RT/CP.
            observed=snapshot(tag,18790)
            assert observed['action_count']==1 and observed['event_count']==count
            target_counts[tag]=count
        else:
            tag=run
            size=65536 if index%20==0 else 1024
            response=send('/bytes?size=%d&sample=%d' % (size,index),tag)
            assert response['status']==200 and base64.b64decode(response['body_base64'])==bytes(range(256))*(size//256)
            count=1
            target_counts[tag]=target_counts.get(tag,0)+1
        report['client_count']+=1
        report['expected_target_count']+=count
        if not paused:
            expected_rows+=count
            report['expected_log_total']+=count
        if index%250==249:
            current=state()
            assert not current['log_error'] and not current['rejected'] and current['raw_bytes']<=32*1024**2
            report['samples'].append(dict(seconds=time.monotonic()-started,state=current))
            print('K11 soak %.0f/1800 s; clients=%d; rows=%d' % (time.monotonic()-started,report['client_count'],current['stored']),flush=True)
        next_due+=1/25
        time.sleep(max(0,next_due-time.monotonic()))
    command('display-none'); command('resume')
    final=settled(30)
    raw=command('metrics-stop')['metrics']
    passive=snapshot(run,18790)
    checks=dict(thirty_minutes=time.monotonic()-started>=1800,
                final_rows_exact=final['stored']==expected_rows and final['displayed']==expected_rows,
                accepted_total_exact=observed_log_total+final['stored']==report['expected_log_total'],
                passive_once=passive['event_count']==target_counts.get(run,0),
                no_rejections=not final['rejected'] and not final['log_error'],
                no_edt_disk_io=not final['counts']['edt_io'],raw_budget_zero=final['raw_bytes']==0,
                all_workflow_pairs_correct=not report['workflow_failures'])
    report.update(seconds=time.monotonic()-started,final=final,passive_target=passive,
                  metrics={key:distribution(values) for key,values in raw.items()},checks=checks,passed=all(checks.values()))
    command('profile-passive')


def faults(report):
    from probe_k11_wire import dropped
    command('profile-passive'); clean(); command('metrics-reset')
    started=time.monotonic()
    report.update(cycles=[],target_checks=[])
    targets={}
    initial_rejections=state()['rejected']
    report['initial_rejections']=initial_rejections
    def request(path,tag):
        response=send(path,tag)
        targets[tag]=targets.get(tag,0)+1
        return response
    cycle=0
    while time.monotonic()-started<300:
        cycle+=1
        command('profile-passive'); clean()
        tag='k11-faults-'+uuid.uuid4().hex[:12]
        before=state()['rejected']
        with ThreadPoolExecutor(max_workers=64) as pool:
            responses=list(pool.map(lambda i:send('/bytes?size=1024&burst='+str(i),tag),range(64)))
        targets[tag]=64
        assert all(r['status']==200 for r in responses)
        initial=settled()
        assert initial['stored']==64 and initial['rejected']==before
        command('fail-write')
        assert request('/bytes?size=1024&failure=write',tag)['status']==200
        write=settled()
        assert write['log_error'] and 'STORAGE_WRITE_FAILED' in write['log_error'] and write['rejected']==before+1
        command('normal-budget'); command('pause'); command('resume')
        command('tiny-budget')
        assert request('/bytes?size=1024&failure=capacity',tag)['status']==200
        capacity=settled()
        assert capacity['rejected']==before+2 and 'LOG_BUSY' in capacity['log_error']
        command('normal-budget'); command('pause'); command('resume')
        assert request('/bytes?size=1024&seed=reader',tag)['status']==200
        settled(); command('fail-read'); command('select-first')
        end=time.monotonic()+5
        while time.monotonic()<end:
            read=state()
            if read['status'].startswith('STORAGE_READ_FAILED'): break
            time.sleep(.05)
        assert read['status'].startswith('STORAGE_READ_FAILED')
        command('clear')
        command('profile-custom-error')
        error_tag='k11-error-'+uuid.uuid4().hex[:12]
        response=request('/entry?q='+error_tag+'&w=TWO',error_tag)
        error_target=snapshot(error_tag,18790)
        assert error_target['action_count']==0 and error_target['event_count']==1 and response['status']==200
        command('profile-close')
        close_tag='k11-close-'+uuid.uuid4().hex[:12]
        response=request('/entry?q='+close_tag+'&w=TWO',close_tag)
        close_target=snapshot(close_tag,18790)
        assert close_target['action_count']==1 and close_target['event_count']==1 and dropped(response)
        command('profile-passive')
        report['cycles'].append(dict(cycle=cycle,seconds=time.monotonic()-started,write=write,capacity=capacity,read=read,passed=True))
        # Sustained ordinary traffic between the fixed burst/failure sequences.
        due=time.monotonic()
        fill='k11-fill-'+uuid.uuid4().hex[:12]
        while time.monotonic()-started<min(300,cycle*30):
            i=targets.get(fill,0)
            response=request('/bytes?size=1024&sample='+str(i),fill)
            assert response['status']==200
            due+=1/25
            time.sleep(max(0,due-time.monotonic()))
        print('K11 faults %.0f/300 s; cycles=%d' % (time.monotonic()-started,cycle),flush=True)
    final=settled(30)
    metrics=command('metrics-stop')['metrics']
    for tag,count in targets.items():
        observed=snapshot(tag,18790)
        report['target_checks'].append(dict(run=tag,expected=count,actual=observed['event_count'],passed=observed['event_count']==count))
    checks=dict(five_minutes=time.monotonic()-started>=300,
                exactly_two_explicit_log_rejections_per_cycle=final['rejected']-initial_rejections==cycle*2,
                every_target_request_once=all(item['passed'] for item in report['target_checks']),
                no_edt_disk_io=not final['counts']['edt_io'],raw_budget_zero=final['raw_bytes']==0,
                recovered_logging=not final['log_error'] and not final['paused'])
    report.update(seconds=time.monotonic()-started,final=final,checks=checks,
                  metrics={key:distribution(values) for key,values in metrics.items()},passed=all(checks.values()))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--phase',choices=['reference','burst','soak','faults'],required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists(): parser.error('Refusing to overwrite/replay a live phase')
    report=dict(kind='K11-live-'+args.phase,passed=False,driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),source_sha256=hashlib.sha256(Path(__file__).resolve().parents[2].joinpath('BoberProxy.py').read_bytes()).hexdigest())
    try:
        if state()['source_sha256']!=report['source_sha256']: raise AssertionError('Loaded/disk source mismatch')
        globals()[args.phase](report)
    except BaseException:
        report['error']=traceback.format_exc()
        try: report['state_after_failure']=state()
        except BaseException: pass
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report.get(key) for key in ('passed','checks','error')},indent=2))
    raise SystemExit(0 if report['passed'] else 1)
