"""Directed live K11 checks. Requires the explicitly loaded K11 test entry.

Reports are new files, HTTP operations are never retried. All targets loopback.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import html
import json
from pathlib import Path
import time
import traceback
import uuid
from k11_control import command, settled, state
from probe_proxy import exchange, snapshot


def send(path,run,**kwargs):
    return exchange(path,target_port=18790,headers=[('X-Bober-Test-Run',run)],timeout=35,**kwargs)


def dropped(response):
    text=html.unescape(base64.b64decode(response['body_base64']).decode('latin-1'))
    return 'Request was dropped by Burp extension' in text


def run_functional(report):
    report['cases']=[]
    command('profile-passive'); command('clear'); command('metrics-reset')
    tag='k11-passive-'+uuid.uuid4().hex[:12]
    for path,status in (('/entry?q=%252F+%2B&w=TWO',200),('/bytes?size=256',200),('/empty',204)):
        result=send(path,tag)
        assert result['status']==status
        if path.startswith('/bytes'): assert base64.b64decode(result['body_base64'])==bytes(range(256))
    observed=snapshot(tag,18790)
    assert observed['event_count']==3 and observed['recent_events'][0]['target']=='/entry?q=%252F+%2B&w=TWO'
    report['cases'].append(dict(name='passive-binary-empty',passed=True,target=observed,state=settled()))
    specifications=[('normal','normal',1,2,'success'),('rt-only','rt',1,1,'rt'),
        ('empty-cp','empty',0,1,'fallback'),('custom-error','error',0,1,'fallback'),
        ('bad-return','bad',0,1,'fallback'),('cp-error','cp-error',1,1,'drop'),
        ('top-timeout','top',0,1,'fallback'),('function-timeout','slow',0,1,'fallback'),
        ('cp-timeout','cp-slow',1,1,'drop'),('invalid-timeout','invalid',0,1,'fallback'),
        ('close','close',1,1,'drop'),('redirect-off','redir-off',1,2,'success'),
        ('redirect-on','redir-on',1,3,'success'),('loop','loop',1,2,'drop'),
        ('limit','limit',1,11,'drop'),('workflow-timeout','workflow-timeout',1,1,'drop')]
    for profile,label,actions,count,outcome in specifications:
        command('profile-'+profile)
        command('metrics-reset')
        run='k11-'+label+'-'+uuid.uuid4().hex[:12]
        result=send('/entry?q='+run+'&w=%252F+%2B',run)
        observed=snapshot(run,18790)
        current=settled()
        metrics=command('metrics-stop')
        checks=dict(action_count=observed['action_count']==actions,request_count=observed['event_count']==count)
        if outcome=='success':
            checks['success_state']=result.get('json',{}).get('cookie_ok') is True and result.get('json',{}).get('token_ok') is True
            checks['custom_twice']=current['counts']['custom']==2
            checks['raw_second_payload']=base64.b64decode(observed['recent_events'][-1]['body_base64']).endswith(b'&two=%252F+%2B')
        elif outcome=='rt': checks['one_custom_disabled']=current['counts']['custom']==0
        elif outcome=='fallback': checks['original_once']=observed['recent_events'][0]['target'].startswith('/entry?')
        elif outcome=='drop': checks['explicit_extension_drop_page']=dropped(result)
        if profile=='normal':
            checks['first_token_empty']=metrics['custom_calls'][0]['csrf'] is None
            checks['second_token_updated']=metrics['custom_calls'][1]['csrf']==observed['session'][1]
        if profile in ('redirect-off','redirect-on'): checks['last_state_matches_cp']=metrics['custom_calls'][-1]['csrf']==observed['session'][1]
        if profile=='loop': checks['loop_reported']='REDIRECT_LOOP' in current['custom_text']
        if profile=='limit': checks['limit_reported']='REDIRECT_LIMIT' in current['custom_text']
        if profile in ('loop','limit'): checks['last_received_state_retained']=current['token']==observed['session'][1]
        checks['no_edt_disk_io']=not current['counts']['edt_io']
        if profile in ('normal','rt-only','redirect-off','redirect-on','loop','limit','workflow-timeout'):
            checks['every_target_response_in_observed_http_hook']=current['counts']['http']==count
        case=dict(name=profile,run=run,checks=checks,passed=all(checks.values()),target=observed,response=result,state=current,custom_calls=metrics['custom_calls'])
        report['cases'].append(case)
        print(profile,'PASS' if case['passed'] else 'FAIL',flush=True)
        if not case['passed']: raise AssertionError('K11 functional mismatch: '+profile)
        # Finite timed-out jobs keep their slot until they really finish.
        if profile in ('top-timeout','function-timeout','cp-timeout'): time.sleep(.35)
    for profile,label,count in (('normal','pair',8),('busy','busy',3)):
        command('profile-'+profile); command('metrics-reset')
        runs=['k11-'+label+'-'+uuid.uuid4().hex[:12] for unused in range(count)]
        with ThreadPoolExecutor(max_workers=count) as pool:
            responses=list(pool.map(lambda run:send('/entry?q='+run+'&w=TWO',run),runs))
        checks=[]
        targets=[]
        for run,response in zip(runs,responses):
            target=snapshot(run,18790); targets.append(target)
            checks.append(target['action_count']==1 and target['event_count']==(2 if profile=='normal' else 1))
            if profile=='normal': checks.append(response.get('json',{}).get('token_ok') is True and response['json'].get('cookie_ok') is True)
            else: checks.append(response['status']==200)
        report['cases'].append(dict(name='concurrent-'+label,passed=all(checks),targets=targets,state=settled()))
        assert all(checks),'Concurrent once-only/state pairing failed'
    for change in ('clear-state','proxy-off'):
        command('profile-held'); command('metrics-reset')
        run='k11-held-'+uuid.uuid4().hex[:12]
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(send,'/entry?q='+run+'&w=TWO',run)
            end=time.monotonic()+3
            while time.monotonic()<end:
                gate=exchange('/k11/control?case='+run,target_port=18790,proxy_port=None)['json']
                if gate['entered']: break
                time.sleep(.01)
            assert gate['entered'],'RT gate not reached'
            command(change)
            exchange('/k11/control?op=release&case='+run,target_port=18790,proxy_port=None)
            response=future.result()
        target=snapshot(run,18790)
        current=settled()
        if change=='clear-state':
            passed=target['action_count']==1 and target['event_count']==1 and dropped(response) and current['token'] is None and not current['cookies']
        else:
            passed=target['action_count']==1 and target['event_count']==2 and response.get('json',{}).get('token_ok') is True and not current['proxy']
        report['cases'].append(dict(name='during-rt-'+change,passed=passed,target=target,response=response,state=current))
        assert passed,'Generation/config snapshot mismatch: '+change
    command('profile-passive')
    report['passed']=all(case['passed'] for case in report['cases'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists(): parser.error('Refusing to overwrite/replay')
    report=dict(kind='K11-live-directed-wire',source_sha256=hashlib.sha256(Path(__file__).resolve().parents[2].joinpath('BoberProxy.py').read_bytes()).hexdigest(),passed=False)
    try: run_functional(report)
    except BaseException:
        report['error']=traceback.format_exc()
        try: report['state_after_failure']=state()
        except BaseException: pass
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report.get(key) for key in ('passed','error')},indent=2))
    raise SystemExit(0 if report['passed'] else 1)
