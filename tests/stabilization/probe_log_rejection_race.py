# -*- coding: utf-8 -*-
"""Finite concurrent admission-counter check. No network or live Burp UI."""
import argparse
import hashlib
import json
import threading
from source_harness import load_namespace, new_ui, Response, SOURCE


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    ns=load_namespace()
    ui=new_ui(ns)
    ui._log_error='controlled existing admission failure'
    config=ui._capture_runtime()
    data=(4,'fixture','GET','/counter-only',200,30,Response(b'HTTP/1.1 200 OK\r\n\r\nX'),False,1)
    trials=[]
    for trial in range(3):
        ui._log_not_accepted=0
        start=threading.Event()
        def run():
            start.wait()
            for unused in range(1000): ui._queue_filter_log(data,config)
        threads=[threading.Thread(target=run) for unused in range(20)]
        for thread in threads: thread.start()
        start.set()
        for thread in threads: thread.join(5)
        trials.append(dict(expected=20000,observed=ui._log_not_accepted,all_threads_finished=not any(t.is_alive() for t in threads)))
    ui.close_custom_runtime()
    with open(SOURCE,'rb') as handle: digest=hashlib.sha256(handle.read()).hexdigest()
    report=dict(kind='K089-concurrent-visible-rejection-counter-no-network',source_sha256=digest,trials=trials,
                passed=all(t['observed']==t['expected'] and t['all_threads_finished'] for t in trials))
    with open(args.report,'w') as handle: json.dump(report,handle,indent=2)
    print(json.dumps(report,indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    import sys
    sys.exit(main())
