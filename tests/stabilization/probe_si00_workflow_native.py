# -*- coding: utf-8 -*-
"""Scoped custom fixture contract/gate check in a private JVM and directory."""
from __future__ import print_function
import argparse
import json
import os
import sys
import tempfile
import time


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    base=os.path.dirname(os.path.abspath(__file__))
    directory=tempfile.mkdtemp(prefix='si00-custom-private-',dir=os.path.join(base,'runtime'))
    trace=os.path.join(directory,'custom.jsonl')
    with open(os.path.join(base,'fixtures','si00-custom-pass-through.py.in'),'r') as handle:code=handle.read()
    code=code.replace('"__TRACE_PATH__"',repr(trace)).replace('"__GATE_ROOT__"',repr(directory))
    namespace={}
    eval(compile(code,'si00-private-custom','exec'),namespace)
    fn=namespace['custom_codeblock']
    checks={}
    run='si00-normal-0123456789'
    gate='si00-interleave-0123456789'
    release=os.path.join(directory,'si00-release-'+gate+'.json')
    try:
        checks['raw_values_and_none_preserved']=fn(run,'%252F+%2B',None)==(run,'%252F+%2B',None)
        token='csrf.'+run+'.1'
        checks['checkpage_token_preserved']=fn(run,'%252F+%2B',token)==(run,'%252F+%2B',token)
        checks['empty_token_preserved']=fn(run,'','')==(run,'','')
        with open(release,'w') as handle:json.dump(dict(run=gate),handle)
        token='csrf.'+gate+'.1'
        checks['gate_accepts_only_matching_release']=fn(gate,'%252F+%2B',token)==(gate,'%252F+%2B',token)
        missing='si00-interleave-abcdef0123'
        started=time.time()
        try:fn(missing,'RAW','csrf.'+missing+'.1')
        except ValueError as error:checks['missing_release_is_controlled_finite_error']=str(error)=='SI00_GATE_TIMEOUT'
        else:checks['missing_release_is_controlled_finite_error']=False
        elapsed=time.time()-started
        with open(trace) as handle:before=len(handle.readlines())
        other='../../not-a-fixture'
        result=fn(other,'RAW','TOKEN')
        with open(trace) as handle:after=len(handle.readlines())
        checks['non_fixture_payload_no_files_or_trace']=result==(other,'RAW','TOKEN') and before==after
    finally:
        for path in (trace,release):
            if os.path.isfile(path):os.remove(path)
        os.rmdir(directory)
    report=dict(kind='SI00-private-custom-fixture-no-live-channel',checks=checks,
        missing_release_elapsed_seconds=elapsed,passed=all(checks.values()),network_requests=0,
        main_source_executed=False,live_channel_used=False)
    with open(args.report,'w') as handle:json.dump(report,handle,indent=2)
    print('SI00_WORKFLOW_FIXTURE %s (%d checks)' % ('PASS' if report['passed'] else 'FAIL',len(checks)))
    return 0 if report['passed'] else 1


if __name__=='__main__':sys.exit(main())
