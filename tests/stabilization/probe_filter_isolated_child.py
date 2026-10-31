# -*- coding: utf-8 -*-
"""Dedicated disposable JVM ONLY. Never load this file as a Burp extension."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import threading
import time
from java.lang import System, Thread
from javax.swing import JTable, SwingUtilities, JLabel
from javax.swing.table import TableRowSorter
from source_harness import ROOT
from probe_template_native import load_source


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
    worker=ns['FilterWorker']()
    worker.capacity=1
    entered=threading.Event()
    def search():
        entered.set()
        return ns['Pattern'].compile('(a+)+$').matcher('a'*100000+'!').find()
    checks={}
    checks['submitted']=worker.submit(search,lambda *a:None)
    checks['entered']=entered.wait(3)
    time.sleep(0.08)
    checks['one_pending_accepted']=worker.submit(lambda:True,lambda *a:None)
    state=worker.state()
    heartbeat=[]
    SwingUtilities.invokeAndWait(lambda:heartbeat.append(JLabel('EDT alive').getText()))
    checks['edt_heartbeat']=heartbeat==['EDT alive']
    checks['queue_bounded']=state['rows']<=1 and state['controls']<=3 and state['results']<=1
    worker.close()
    checks['closed_admission_rejected']=not worker.submit(lambda:True,lambda *a:None)
    peer=ns['FilterWorker']()
    active=worker.worker.is_alive()
    if active:
        checks['no_reload_worker_accumulation']=not peer.submit(lambda:True,lambda *a:None)
    else:
        checks['no_reload_worker_accumulation']=True
    peer.close()
    report=dict(kind='K07-disposable-JVM-actual-expensive-Java-regex',
        source_sha256=hashlib.sha256(raw).hexdigest(),checks=checks,passed=all(checks.values()),
        observed=state,worker_alive_at_close=active,guaranteed_hard_interrupt=False,
        cleanup='System.exit is used ONLY in this dedicated child JVM after writing the report.')
    with open(args.report,'w') as handle:
        json.dump(report,handle,indent=2)
    # This terminates only the disposable child launched by the parent probe.
    System.exit(0 if report['passed'] else 1)


if __name__=='__main__':
    main()
