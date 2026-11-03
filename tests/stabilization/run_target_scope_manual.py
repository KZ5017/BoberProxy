# -*- coding: utf-8 -*-
"""One manually Forwarded outside-origin request/response; no retries."""
import argparse,json
from target_scope_wire import Client,RUNTIME,save_report
parser=argparse.ArgumentParser();parser.add_argument('--report',required=True);args=parser.parse_args()
c=Client();run=c.runid('manual');before=c.command()
(RUNTIME/'tg-manual-pending.json').write_text(json.dumps(dict(run=run,source_sha256=c.source)))
print('TG05_MANUAL START '+run,flush=True)
response=c.request(run,kind='B',path='/scope/manual?run='+run+'&q=normal&w='+run,timeout=180)
after=c.settle();target=c.target(run,'B')
audit=[r for r in after['audit'] if r['run']==run]
checks=dict(status=response['status']==200,one_original=target['event_count']==1 and target['actions']==target['checks']==0,
    same_message_pair=len(audit)==2 and {r['request'] for r in audit}=={True,False} and len({r['reference'] for r in audit})==1,
    actions_preserved=len(audit)==2 and all(r['before']==r['after']==1 for r in audit),
    no_foreign_state=(before['sid'],before['csrf'])==(after['sid'],after['csrf']),
    no_custom=len(before['custom'])==len(after['custom']))
report=dict(kind='TG05-real-same-Proxy-message-manual-intercept',source_sha256=c.source,run=run,
    checks=checks,passed=all(checks.values()),audit=audit,target=target,response=response)
save_report(args.report,report)
print('TG05_MANUAL '+('PASS' if report['passed'] else 'FAIL'),flush=True)
raise SystemExit(0 if report['passed'] else 1)
