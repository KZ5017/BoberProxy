"""Normal and finite interleaved native-cookie workflow, one client send each."""
import argparse
import base64
import json
import threading
import time
import uuid
from pathlib import Path
from probe_proxy import exchange,snapshot
from probe_si00_wire import command,read_json


def records(path):
    if not path.exists(): return []
    result=[]
    for line in path.read_text().splitlines():
        try:result.append(json.loads(line))
        except ValueError:pass
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--scenario',choices=['normal','interleave'],required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    if args.report.exists():raise RuntimeError('Use a new report path')
    runtime=Path(__file__).resolve().parent/'runtime'
    state=read_json(runtime/'si00-wire-state.json')
    if not state or state.get('state')!='ready':raise RuntimeError('Observer not ready')
    run='si00-'+args.scenario+'-'+uuid.uuid4().hex[:10]
    trace=runtime/'si00-workflow-custom.jsonl'
    release=runtime/('si00-release-'+run+'.json')
    assert not release.exists()
    command(runtime,state,'cleanup')
    replies,errors=[],[]
    injected=None
    def send():
        try:
            replies.append(exchange('/si00/entry?run='+run+'&q='+run+'&w=%252F+%2B',target_port=18781,timeout=6))
        except Exception as exc:errors.append(dict(type=type(exc).__name__,message=str(exc)))
    client=threading.Thread(target=send,daemon=True)
    client.start()
    if args.scenario=='interleave':
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and client.is_alive():
            if any(record.get('run')==run and record.get('gated') for record in records(trace)):
                try:
                    injected=command(runtime,state,'seed',value='FOREIGN')
                    release.write_text(json.dumps(dict(run=run)),encoding='utf-8')
                except Exception as exc:errors.append(dict(type=type(exc).__name__,message=str(exc)))
                break
            time.sleep(0.01)
    client.join(7)
    if client.is_alive():errors.append(dict(type='ClientPending',message='Inspect outcome; never replay'))
    observed=snapshot(run,18781)
    custom=[record for record in records(trace) if record.get('run')==run]
    # A flush/inspect command is safe only after the application client completed.
    cleanup=dict(cleanup_complete=False)
    if not client.is_alive():
        try:cleanup=command(runtime,state,'cleanup')
        except Exception as exc:errors.append(dict(type=type(exc).__name__,message=str(exc)))
    wire=[record for record in records(runtime/'si00-wire-trace.jsonl')
          if record.get('instance')==state['instance'] and record.get('run')==run]
    events=observed['recent_events']
    reply=replies[0].get('json',{}) if replies else {}
    expected_action=('one='+run+'&two=%252F+%2B').encode('ascii')
    expected_check=('csrf=csrf.'+run+'.1&one='+run+'&two=%252F+%2B').encode('ascii')
    checks=dict(no_transport_error=not errors,action_once=observed['action_count']==1,
        exactly_two_target_requests=observed['event_count']==2,
        two_custom_calls=len(custom)==2,raw_payloads_preserved=bool(len(events)==2
            and base64.b64decode(events[0]['body_base64'])==expected_action
            and base64.b64decode(events[1]['body_base64'])==expected_check),
        correct_methods_and_targets=bool(len(events)==2 and all(e['method']=='POST' for e in events)
            and events[0]['target'].startswith('/si00/action?') and events[1]['target'].startswith('/si00/check?')),
        local_token_correct=reply.get('token_ok') is True,
        no_unowned_cookies=all(e['other_cookie_count']==0 for e in events),
        own_cleanup_complete=cleanup['cleanup_complete'])
    if args.scenario=='normal':checks['normal_cookie_correct']=reply.get('cookie_ok') is True
    else:checks['controlled_interleave_completed']=injected is not None
    capabilities=dict(native_cookie_matches_local_token=reply.get('cookie_ok') is True,
        custom_token_matches_own_RT=len(custom)==2 and custom[-1]['csrf_token']=='csrf.'+run+'.1')
    report=dict(kind='SI00-unmodified-main-native-cookie-workflow',scenario=args.scenario,run=run,
        checks=checks,capabilities=capabilities,passed=all(checks.values()),observed=observed,
        custom_records=custom,wire_records=wire,replies=replies,errors=errors,injected=injected,cleanup=cleanup,
        main_settings='Templates/CheckPage/custom/CSRF ON, own cookies OFF; native rule/collection ON; Intercept/AutoFollow OFF.',
        note='For interleave, measurement PASS is separate from native isolation capability.')
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'],checks=checks,capabilities=capabilities),indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
