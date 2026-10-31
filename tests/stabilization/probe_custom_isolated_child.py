# -*- coding: utf-8 -*-
"""Run only in an externally bounded dedicated JVM, never in the Burp JVM."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import time
from java.lang import System, Thread
from source_harness import load_namespace, Helpers, SOURCE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', required=True, choices=['python-loop', 'java-wait'])
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    ns = load_namespace()
    executor = ns['CustomExecutor'](Helpers())
    passthrough = 'def custom_codeblock(a,b,c):\n    return a,b,c\n'
    warm = executor.wait(executor.submit(passthrough, 2000, ('A', 'B', None)))
    if args.case == 'python-loop':
        source = 'def custom_codeblock(a,b,c):\n    while True:\n        pass\n'
    else:
        source = 'from java.util.concurrent import CountDownLatch\ndef custom_codeblock(a,b,c):\n    getattr(CountDownLatch(1), "await")()\n'
    job = executor.submit(source, 100, ('A', 'B', None))
    outcome = executor.wait(job)
    worker = executor.worker
    checks = dict(warm_success=warm[0], timeout_visible=not outcome[0] and 'CUSTOM_TIMEOUT' in outcome[2],
                  running_user_code_remains=executor.state()['active'] and worker.is_alive())
    busy = [executor.wait(executor.submit(passthrough, 100, ('A', 'B', None))) for _ in range(25)]
    checks['all_extra_jobs_busy'] = all(not result[0] and 'CUSTOM_BUSY' in result[2] for result in busy)
    checks['same_worker_after_timeouts'] = executor.worker is worker
    executor.close()
    replacement = ns['CustomExecutor'](Helpers())
    result = replacement.wait(replacement.submit(passthrough, 100, ('A', 'B', None)))
    checks['reload_does_not_replace_stuck_worker'] = not result[0] and 'CUSTOM_BUSY' in result[2]
    replacement.close()
    threads = [thread for thread in Thread.getAllStackTraces().keySet()
               if thread.isAlive() and thread.getThreadGroup() is not None and
               thread.getThreadGroup().getName() == ns['CUSTOM_GATE_NAME']]
    checks['exactly_one_owned_native_thread'] = len(threads) == 1
    with open(SOURCE, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    report = dict(kind='K05-nonterminating-code-dedicated-JVM-only', case=args.case,
                  source_sha256=digest, checks=checks, passed=all(checks.values()),
                  hard_interruption_provided=False,
                  cleanup='System.exit terminates only this dedicated child JVM; parent enforces 45 seconds')
    with open(args.report, 'w') as handle:
        handle.write(json.dumps(report, indent=2) + '\n')
        handle.flush()
    print(json.dumps(report))
    # The parent explicitly launched this disposable JVM. No shutdown hook or
    # infinite-code execution is ever installed in the real Burp application.
    System.exit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
