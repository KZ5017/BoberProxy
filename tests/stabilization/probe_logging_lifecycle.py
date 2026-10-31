# -*- coding: utf-8 -*-
"""Eight finite full native UI/archive cycles in one standalone JVM. No network."""
import argparse
import json
import sys
from java.lang import Thread
from probe_logging_native import run_checks


def owned_threads():
    result=[]
    for thread in Thread.getAllStackTraces().keySet():
        if not thread.isAlive(): continue
        group=thread.getThreadGroup()
        if str(thread.getName()).startswith('BoberProxy.') or group is not None and str(group.getName()).startswith('BoberProxy.'):
            result.append(str(thread.getName()))
    return sorted(result)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    before=owned_threads()
    cycles=[]
    for index in range(8):
        report=run_checks()
        remaining=owned_threads()
        cycles.append(dict(cycle=index+1,passed=report['passed'] and remaining==before,
                           logic_cases=report['logic_cases'],native_checks=len(report['checks']),
                           source_sha256=report['source_sha256'],remaining_owned_threads=remaining,errors=report['errors']))
        print('K089 lifecycle %d/8: %s' % (index+1,'PASS' if cycles[-1]['passed'] else 'FAIL'))
        sys.stdout.flush()
        if not cycles[-1]['passed']: break
    result=dict(kind='K089-eight-full-native-UI-archive-lifecycles-one-JVM',cycles=cycles,
                baseline_owned_threads=before,network_requests=0,
                source_sha256=cycles[0]['source_sha256'],passed=len(cycles)==8 and all(c['passed'] for c in cycles))
    with open(args.report,'w') as handle: json.dump(result,handle,indent=2)
    return 0 if result['passed'] else 1


if __name__=='__main__': sys.exit(main())
