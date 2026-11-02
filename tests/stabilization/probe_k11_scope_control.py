"""Same-environment external-latency control excluded by the K11 tag scope.

Not an old-version callback baseline. Run only after another live phase ends.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from k11_control import command, settled, state


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--directory',type=Path,required=True)
    args=parser.parse_args();args.directory.mkdir(parents=True,exist_ok=False)
    command('profile-passive'); command('display-none'); settled(); command('clear')
    from run_k11_live import clean
    clean()
    before=state()
    results=[]
    for index in range(1,4):
        report=args.directory/('iteration-%d.json'%index)
        result=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('measure_proxy.py')),
            '--count','200','--rate','25','--target-port','18790','--report',str(report)],
            capture_output=True,timeout=30)
        data=json.loads(report.read_text()) if report.exists() else {}
        results.append(dict(iteration=index,passed=result.returncode==0 and data.get('passed',False)))
        if not results[-1]['passed']: break
    after=state()
    checks=dict(three_windows=len(results)==3 and all(item['passed'] for item in results),
                root_not_called=after['counts']['http']==before['counts']['http'] and after['counts']['proxy']==before['counts']['proxy'],
                root_log_empty=after['stored']==0)
    report=dict(kind='K11-excluded-tag-same-environment-external-latency-control',
                source_sha256=after['source_sha256'],checks=checks,iterations=results,
                before=before,after=after,passed=all(checks.values()),
                boundary='The test observer still checks scope; the root HTTP/Proxy callbacks are excluded. This is not the missing K00 callback timing.')
    (args.directory/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'],checks=checks),indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
