"""Python 3 parent for externally bounded K11 load JVMs. No live Burp access."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


class MemoryCounters(ctypes.Structure):
    _fields_ = [('cb',ctypes.c_ulong),('faults',ctypes.c_ulong)] + [
        (name,ctypes.c_size_t) for name in ('peak_working_set','working_set',
        'peak_paged_pool','paged_pool','peak_nonpaged_pool','nonpaged_pool','pagefile','peak_pagefile')]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=False)
    directory = args.directory.resolve()
    java = Path(os.environ['LOCALAPPDATA'])/'Programs/BurpSuite/jre/bin/java.exe'
    jar = Path.home()/'Downloads/jython-standalone-2.7.4.jar'
    burp = java.parents[2]/'burpsuite.jar'
    script = Path(__file__).with_name('probe_k11_load.py').resolve()
    digest = hashlib.sha256((script.parents[2]/'BoberProxy.py').read_bytes()).hexdigest()
    results = []
    for iteration in range(1, 2 if args.smoke else 4):
        temp_parent = Path(tempfile.gettempdir()).resolve()
        if shutil.disk_usage(temp_parent).free < 3*1024**3:
            raise RuntimeError('K11 load requires 3 GiB free on temporary-storage volume')
        root = Path(tempfile.mkdtemp(prefix='BoberProxy-K11-')).resolve()
        assert root.parent == temp_parent and root.name.startswith('BoberProxy-K11-')
        report_path = directory/('iteration-%d.json' % iteration)
        command = [str(java), '--enable-native-access=ALL-UNNAMED', '-Xmx768m',
                   '-Dpython.cachedir.skip=true', '-cp', str(jar)+os.pathsep+str(burp),
                   'org.python.util.jython', '-B', str(script), '--root',str(root),
                   '--report',str(report_path)] + (['--smoke'] if args.smoke else [])
        memory, started = [], time.monotonic()
        resource_stop, requested_stop = False, False
        bound = 180 if args.smoke else 1200
        print('K11 load iteration %d starting; external bound %d s' % (iteration,bound), flush=True)
        try:
            with (directory/('iteration-%d.stdout.txt' % iteration)).open('wb') as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
                try:
                    while process.poll() is None and time.monotonic()-started < bound:
                        counters = MemoryCounters()
                        counters.cb = ctypes.sizeof(counters)
                        if ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(int(process._handle)),ctypes.byref(counters),counters.cb):
                            memory.append(counters.working_set)
                            if counters.working_set > 2*1024**3:
                                resource_stop = True
                                break
                        if (directory/'stop-requested').exists():
                            requested_stop = True
                            break
                        time.sleep(.2)
                    timed_out = process.poll() is None and time.monotonic()-started >= bound
                finally:
                    if process.poll() is None: process.kill()
                    code = process.wait()
            child = json.loads(report_path.read_text()) if report_path.exists() else {}
            result = dict(iteration=iteration, source_sha256=digest, child_report=report_path.name,
                          command=command, seconds=time.monotonic()-started, exit_code=code,
                          timed_out=timed_out, child_reaped=True, external_bound_seconds=bound,
                          resource_guard_stopped=resource_stop, requested_stop=requested_stop,
                          sampled_peak_working_set_bytes=max(memory) if memory else None,
                          memory_sample_count=len(memory), archive_reclaimed_by_child=not (root/'archive').exists(),
                          passed=code==0 and not timed_out and not resource_stop and not requested_stop and child.get('passed',False))
        finally:
            # This exact fresh parent was created here, passed only to our child,
            # and is reclaimed only after that child has been reaped.
            assert root.parent==temp_parent and root.name.startswith('BoberProxy-K11-')
            if root.exists(): shutil.rmtree(str(root))
        result['owned_test_parent_removed'] = not root.exists()
        results.append(result)
        summary = dict(kind='K11-external-full-load-driver',source_sha256=digest,
                       smoke=args.smoke, iterations=results, k11_closed=False,
                       complete=len(results)==(1 if args.smoke else 3),
                       passed=all(r['passed'] for r in results))
        (directory/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
        print('K11 load iteration %d: %s' % (iteration,'PASS' if result['passed'] else 'FAIL'),flush=True)
        if not result['passed']: return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
