# -*- coding: utf-8 -*-
"""Finite aggregate checks on private instances; no network or global UI changes.

Live mode uses actual Burp helpers/editors. Standalone mode must run in its own
JVM; existing standalone editor checks can set that JVM's look and feel.
"""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import time
import traceback
from java.lang import System, Runtime, Throwable
from java.lang.management import ManagementFactory
from org.python.core import Py
from javax.swing import SwingUtilities
from source_harness import ROOT


def run_checks(callbacks=None, progress=None, cancelled=None):
    from probe_template_native import run_checks as template
    from probe_k03_native import run_checks as redirect
    from probe_session_native import run_checks as session
    from probe_custom_native import run_checks as custom
    from probe_runtime_native import run_checks as runtime
    from probe_filters_native import run_checks as filters
    from probe_ui03_native import run_checks as editor
    from probe_cleanup_final_native import run_checks as cleanup
    helpers = callbacks.getHelpers() if callbacks else None
    suites = [('template', lambda: template(helpers)),
              ('redirect', lambda: redirect(callbacks, include_http=False)),
              ('session', lambda: session(helpers)),
              ('custom', lambda: custom(helpers)),
              ('runtime', lambda: runtime(callbacks)),
              ('filters', lambda: filters(callbacks)),
              ('editor-layout', lambda: editor(callbacks)),
              ('final-cleanup', lambda: cleanup(callbacks, expected_line='BoberProxy loaded (UI03)'))]
    reports = []
    with open(os.path.join(ROOT, 'BoberProxy.py'), 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    for name, operation in suites:
        if cancelled is not None and cancelled(): break
        started = time.time()
        original_state = Py.getSystemState()
        try:
            result = operation()
        except (BaseException, Throwable):
            result = dict(passed=False, errors=[traceback.format_exc()])
        finally:
            Py.setSystemState(original_state)
            SwingUtilities.invokeAndWait(lambda: Py.setSystemState(original_state))
        reports.append(dict(name=name, seconds=time.time()-started, result=result))
        if progress: progress('K11 ' + name + ': ' + ('PASS' if result['passed'] else 'FAIL'))
    with open(os.path.join(ROOT, 'BoberProxy.py'), 'rb') as handle:
        unchanged = hashlib.sha256(handle.read()).hexdigest() == digest
    return dict(kind='K11-private-functional-regression-no-network',
                source_sha256=digest, source_unchanged=unchanged,
                actual_burp_helpers=bool(callbacks),
                burp_version=list(callbacks.getBurpVersion()) if callbacks else None,
                python=sys.version, java_version=unicode(System.getProperty('java.version')),
                java_vendor=unicode(System.getProperty('java.vendor')),
                os=unicode(System.getProperty('os.name')),
                heap_max_bytes=Runtime.getRuntime().maxMemory(),
                jvm_heap_arguments=[unicode(v) for v in ManagementFactory.getRuntimeMXBean().getInputArguments()
                                    if unicode(v).startswith(('-Xmx','-Xms','-XX:MaxRAM','-XX:InitialRAM'))],
                suites=reports, network_requests=0, k11_closed=False,
                passed=unchanged and len(reports)==len(suites) and all(r['result']['passed'] for r in reports))


def summary(report):
    return 'K11_REGRESSION %s (%d/%d suites)' % (
        'PASS' if report['passed'] else 'FAIL',
        sum(bool(r['result']['passed']) for r in report['suites']), 8)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    if os.path.exists(args.report): raise ValueError('Report already exists')
    result = run_checks(progress=print)
    with open(args.report, 'w') as handle: json.dump(result, handle, indent=2)
    print(summary(result))
    sys.exit(0 if result['passed'] else 1)
