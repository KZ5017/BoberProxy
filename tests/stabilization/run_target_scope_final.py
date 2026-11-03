# -*- coding: utf-8 -*-
"""Direct-root final traffic; never reads the removed wrapper command channel."""
import argparse,base64,json,time
from target_scope_wire import Client,RUNTIME,save_report
parser=argparse.ArgumentParser();parser.add_argument('--report',required=True);args=parser.parse_args()
c=Client();run=c.runid('final-direct');trace=RUNTIME/'tg-final-custom-trace.jsonl'
before=trace.read_bytes().splitlines() if trace.exists() else []
response=c.request(run,path='/scope/entry?q=%252F+%2B&w='+run)
target=c.target(run);after=trace.read_bytes().splitlines() if trace.exists() else []
calls=[json.loads(row) for row in after[len(before):]]
checks=dict(status=response['status']==200 and json.loads(response['body'])['accepted'],
    once=(target['actions'],target['checks'],target['event_count'])==(1,1,2),two_calls=len(calls)==2,
    payload=len(calls)==2 and all(r['payload1']=='%252F+%2B' and r['payload2']==run for r in calls),
    tokens=len(calls)==2 and calls[0]['csrf_token'] is None and calls[1]['csrf_token']=='csrf.A.%s.1'%run)
for e in target['events']:
    checks['raw_'+e['target'].split('?')[0]]=('one=%252F+%2B&two='+run).encode() in base64.b64decode(e['body_base64'])
viewer=run+'-viewer';results={}
for path in ('/scope/entry','/scope/bytes','/scope/empty'):
    r=c.request(viewer,path=path+'?run='+viewer);results[path]=dict(status=r['status'],body_bytes=len(base64.b64decode(r['body_base64'])))
checks['viewer_bytes']=results['/scope/bytes']==dict(status=200,body_bytes=256)
checks['viewer_empty']=results['/scope/empty']==dict(status=204,body_bytes=0)
time.sleep(.5);late=c.target(run)
checks['no_late_replay']=[target[k] for k in ('actions','checks','event_count')]==[late[k] for k in ('actions','checks','event_count')]
report=dict(kind='TG05-direct-root-final-no-instrumentation',source_sha256=c.source,run=run,viewer_run=viewer,
            checks=checks,passed=all(checks.values()),response=response,target=target,custom=calls,viewer=results)
save_report(args.report,report);print('TG05_FINAL '+('PASS' if report['passed'] else 'FAIL')+' '+viewer)
if not report['passed']:print(checks)
raise SystemExit(0 if report['passed'] else 1)
