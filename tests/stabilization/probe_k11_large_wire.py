"""Three live 64KiB response windows at 10/s; not a retained-heap profiler."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import time
import traceback
import uuid
from k11_control import command,settled,state
from probe_proxy import exchange,snapshot
from run_k11_live import clean,distribution


def run(report):
    command('profile-passive'); clean()
    report['iterations']=[]
    expected=bytes(range(256))*256
    for iteration in range(1,4):
        clean(); before=state(); command('metrics-reset')
        run='k11-large-'+uuid.uuid4().hex[:12]
        timings=[]; started=time.monotonic()
        for index in range(100):
            time.sleep(max(0,started+index/10-time.monotonic()))
            response=exchange('/bytes?size=65536&sample='+str(index),target_port=18790,
                              headers=[('X-Bober-Test-Run',run)],timeout=10)
            assert response['status']==200 and base64.b64decode(response['body_base64'])==expected
            timings.append(response['seconds']*1000)
        final=settled(); metrics=command('metrics-stop')['metrics']; target=snapshot(run,18790)
        checks=dict(hundred_exact_responses=target['event_count']==100,
                    all_stored_and_displayed=final['stored']==100 and final['displayed']==100,
                    no_new_rejections=final['rejected']==before['rejected'] and not final['log_error'],
                    no_edt_disk_io=not final['counts']['edt_io'],raw_budget_released=final['raw_bytes']==0,
                    heartbeat_p95_at_most_100ms=distribution(metrics['heartbeat_ms'])['p95']<=100,
                    heartbeat_max_at_most_1000ms=distribution(metrics['heartbeat_ms'])['maximum']<=1000,
                    appearance_p99_at_most_1000ms=distribution(metrics['appearance_ms'])['p99']<=1000)
        report['iterations'].append(dict(iteration=iteration,run=run,count=100,body_bytes=65536,rate=10,
            client_ms=distribution(timings),metrics={key:distribution(values) for key,values in metrics.items()},
            final=final,target=target,checks=checks,passed=all(checks.values())))
        assert all(checks.values()),'Large response window failed'
        print('K11 64KiB window %d PASS'%iteration,flush=True)
    report['passed']=True


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
    if args.report.exists():parser.error('Report exists; refusing replay')
    report=dict(kind='K11-live-64KiB-three-windows',source_sha256=hashlib.sha256(Path(__file__).resolve().parents[2].joinpath('BoberProxy.py').read_bytes()).hexdigest(),passed=False)
    try: run(report)
    except BaseException: report['error']=traceback.format_exc()
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report.get(key) for key in ('passed','error')},indent=2))
    raise SystemExit(0 if report['passed'] else 1)
