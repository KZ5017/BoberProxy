"""Bound the lifetime of a regex experiment with an external child JVM."""
import argparse
import json
import os
import subprocess
from pathlib import Path


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    java=Path(os.environ['LOCALAPPDATA'])/'Programs/BurpSuite/jre/bin/java.exe'
    jython=Path.home()/'Downloads/jython-standalone-2.7.4.jar'
    burp=java.parents[2]/'burpsuite.jar'
    child=Path(__file__).with_name('probe_filter_isolated_child.py')
    command=[str(java),'-Dpython.cachedir.skip=true','-Djava.awt.headless=true','-Xmx256m',
             '-cp',str(jython)+';'+str(burp),'org.python.util.jython','-B',str(child),'--report',str(args.report)]
    try:
        result=subprocess.run(command,capture_output=True,text=True,timeout=25)
    except subprocess.TimeoutExpired:
        # subprocess.run kills and reaps its own child before raising.
        args.report.write_text(json.dumps(dict(kind='K07-disposable-JVM-parent-timeout',passed=False,
            child_reaped=True,external_timeout_seconds=25)),encoding='utf-8')
        return 1
    if not args.report.exists():
        args.report.write_text(json.dumps(dict(passed=False,error=result.stderr[-4000:])),encoding='utf-8')
    report=json.loads(args.report.read_text())
    report['parent_exit_code']=result.returncode
    report['child_reaped']=True
    report['external_timeout_seconds']=25
    report['passed']=report.get('passed',False) and result.returncode==0
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
