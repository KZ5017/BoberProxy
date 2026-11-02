"""One human-forwarded K11 request/response; no automatic replay."""
import argparse
import hashlib
import json
from pathlib import Path
import traceback
import uuid
from probe_proxy import exchange,snapshot


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
    if args.report.exists():parser.error('Refusing overwrite/replay')
    runtime=Path(__file__).resolve().parent/'runtime'
    digest=hashlib.sha256(Path(__file__).resolve().parents[2].joinpath('BoberProxy.py').read_bytes()).hexdigest()
    run='k11-manual-'+uuid.uuid4().hex[:12]
    report=dict(kind='K11-real-manual-Proxy-interception-pair',run=run,source_sha256=digest,passed=False)
    try:
        for role in ('before','after'):
            initial=json.loads((runtime/('k11-manual-'+role+'.json')).read_text())
            assert initial['role']==role and initial['source_sha256']==digest
            assert initial.get('instrumentation')=='same-real-proxy-message','Load the same-message manual test entry'
        print('K11 manual request started; forward request and response once each',flush=True)
        response=exchange('/echo?case=k11-manual',target_port=18790,timeout=180,headers=[('X-Bober-Test-Run',run)])
        observations={}
        for role in ('before','after'):
            data=json.loads((runtime/('k11-manual-'+role+'.json')).read_text())
            observations[role]=[event for event in data['events'] if event['run']==run]
        target=snapshot(run,18790)
        checks=dict(response_ok=response['status']==200,exactly_one_target_request=target['event_count']==1 and target['action_count']==0)
        for role,events in observations.items():
            checks[role+'_request_response_pair']=len(events)==2 and set(event['request'] for event in events)=={True,False}
            checks[role+'_DO_INTERCEPT_preserved']=len(events)==2 and all(event['after']==1 for event in events)
        checks['same_native_message_reference']=len({event['reference'] for events in observations.values() for event in events})==1
        report.update(response=response,target=target,observations=observations,checks=checks,passed=all(checks.values()))
    except BaseException:
        report['error']=traceback.format_exc()
        try:report['target_after_failure']=snapshot(run,18790)
        except BaseException:pass
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report.get(key) for key in ('passed','checks','error')},indent=2))
    raise SystemExit(0 if report['passed'] else 1)
