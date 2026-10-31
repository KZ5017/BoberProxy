# -*- coding: utf-8 -*-
"""Bounded disposable-JVM storage/heap probe. Never load as a Burp extension."""
from __future__ import print_function
import argparse
import json
import os
import sys
import time


def child(args):
    import hashlib
    from java.lang import System, Runtime
    from source_harness import ROOT, Helpers, Response
    from probe_template_native import load_source
    ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
    archive=ns['LogArchive']()
    archive.root=args.root
    runtime=Runtime.getRuntime()
    def used():
        for unused in range(3):
            System.gc()
            time.sleep(0.05)
        return runtime.totalMemory()-runtime.freeMemory()
    def populate(size):
        for index in range(192):
            body=('%08d' % index)+'X'*(size-8)
            response='HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(body)+body
            snapshot=ns['FrozenLogMessage'](Helpers(),Response(response),'GET /%d HTTP/1.1\r\n\r\n' % index,response)
            archive.put(snapshot,archive.epoch)
    report=dict(kind='K089-disposable-JVM-content-and-metadata-memory',source_sha256=hashlib.sha256(raw).hexdigest(),
                java_version=str(System.getProperty('java.version')),max_heap_bytes=runtime.maxMemory(),checks={})
    try:
        populate(128)
        small=used()
        archive.clear()
        while archive.collect(): pass
        populate(4*1024*1024)
        large=used()
        paths=list(archive.records.values())
        total=sum(sum(max(0,n) for n in record.lengths) for record in paths)
        report.update(small_body_heap_bytes=small,large_body_heap_bytes=large,
                      same_metadata_rows=len(paths),large_content_disk_bytes=total,
                      heap_growth_bytes=large-small)
        report['checks']['content_larger_than_max_heap']=total>runtime.maxMemory()
        report['checks']['heap_not_proportional_to_total_content']=large-small<96*1024*1024
        report['checks']['all_192_content_records_preserved']=len(paths)==192
        first=archive.records[os.path.join(archive.root,'193.httpbin')]
        last=archive.records[os.path.join(archive.root,'384.httpbin')]
        report['checks']['first_and_last_disk_payload_exact']=(first.getResponse().endswith('00000000'+'X'*(4*1024*1024-8))
                                                            and last.getResponse().endswith('00000191'+'X'*(4*1024*1024-8)))
        paths=first=last=None
        archive.clear()
        while archive.collect(): pass
        before_metadata=used()
        store=ns['LogStore']()
        for index in range(100000): store.add('t','fixture','GET','/row/%d' % index,200,128,0,None)
        model=ns['LogTableModel'](store)
        model.rebuild()
        after_metadata=used()
        report.update(metadata_rows=100000,metadata_heap_growth_bytes=after_metadata-before_metadata)
        report['checks']['hundred_thousand_metadata_rows_fit']=model.getRowCount()==100000 and store.entries[0].index==100000 and store.entries[-1].index==1
        store=model=None
    except BaseException:
        import traceback
        report['error']=traceback.format_exc()
    finally:
        root=archive.root
        archive.clear(close=True)
        while archive.collect(): pass
        report['checks']['own_files_and_directory_removed']=not os.path.exists(root)
    report['passed']=all(report['checks'].values()) and not report.get('error')
    with open(args.report,'w') as handle: json.dump(report,handle,indent=2)
    print(json.dumps(dict(passed=report['passed'],checks=report['checks']),indent=2))
    return 0 if report['passed'] else 1


def parent(args):
    import ctypes
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path
    directory=Path(tempfile.gettempdir()).resolve()
    root=Path(tempfile.mkdtemp(prefix='BoberProxy-memory-')).resolve()
    assert root.parent==directory and root.name.startswith('BoberProxy-memory-')
    java=Path(os.environ['LOCALAPPDATA'])/'Programs/BurpSuite/jre/bin/java.exe'
    jython=Path.home()/'Downloads/jython-standalone-2.7.4.jar'
    burp=java.parents[2]/'burpsuite.jar'
    command=[str(java),'--enable-native-access=ALL-UNNAMED','-Xmx384m','-Dpython.cachedir.skip=true','-cp',
             str(jython)+';'+str(burp),'org.python.util.jython','-B',str(Path(__file__).resolve()),
             '--child','--root',str(root),'--report',str(Path(args.report).resolve())]
    samples=[]
    log=Path(args.report).with_suffix('.stdout.txt')
    try:
        with log.open('w') as output:
            process=subprocess.Popen(command,stdout=output,stderr=output)
            deadline=time.monotonic()+180
            class Counters(ctypes.Structure):
                _fields_=[('cb',ctypes.c_ulong),('faults',ctypes.c_ulong)]+[(name,ctypes.c_size_t) for name in
                    ('peak_working_set','working_set','peak_paged_pool','paged_pool','peak_nonpaged_pool','nonpaged_pool','pagefile','peak_pagefile')]
            while process.poll() is None and time.monotonic()<deadline:
                counters=Counters()
                counters.cb=ctypes.sizeof(counters)
                if ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(int(process._handle)),ctypes.byref(counters),counters.cb):
                    samples.append(counters.working_set)
                time.sleep(0.2)
            timed_out=process.poll() is None
            if timed_out: process.kill()
            code=process.wait()
        report=json.loads(Path(args.report).read_text()) if Path(args.report).exists() else dict(passed=False)
        report.update(parent_exit_code=code,child_reaped=True,external_timeout_seconds=180,timed_out=timed_out,
                      process_working_set_peak_sample_bytes=max(samples) if samples else None,
                      process_working_set_samples=len(samples))
        report['passed']=report['passed'] and code==0 and not timed_out
    finally:
        # Only the exact fresh directory created above is eligible for recursive cleanup.
        assert root.parent==directory and root.name.startswith('BoberProxy-memory-')
        if root.exists(): shutil.rmtree(str(root))
    report['parent_verified_owned_directory_absent']=not root.exists()
    Path(args.report).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('checks','error')},indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    parser.add_argument('--child',action='store_true')
    parser.add_argument('--root')
    args=parser.parse_args()
    sys.exit(child(args) if args.child else parent(args))
