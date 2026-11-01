# -*- coding: utf-8 -*-
"""K10/B aggregate finite native verification, private instances, no network."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import traceback
import unittest
from StringIO import StringIO
from javax.swing import SwingUtilities
from java.lang import Throwable
from source_harness import ROOT, new_ui
from probe_template_native import load_source, run_checks as conversion_checks
from probe_cleanup_native import run_checks as cleanup_checks
from test_cleanup_final import FinalCleanupTests


def run_checks(actual_callbacks=None):
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    ns['_probe_threads'] = []
    class NativeFinal(FinalCleanupTests):
        @classmethod
        def setUpClass(cls): cls.ns = ns
    stream = StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeFinal))
    errors = [] if result.wasSuccessful() else [stream.getvalue()]
    cleanup = cleanup_checks(actual_callbacks, expected_marker='K10-B')
    conversions = conversion_checks(actual_callbacks.getHelpers() if actual_callbacks else None)
    checks = {'six_native_final_cases': result.wasSuccessful()}
    if actual_callbacks:
        def editors():
            private = new_ui(ns)
            private.helpers = actual_callbacks.getHelpers()
            try:
                private.reqTemplateEditor = actual_callbacks.createMessageEditor(ns['SimpleMessageController'](), True)
                private.checkPageEditor = actual_callbacks.createMessageEditor(ns['SimpleMessageController'](), True)
                wire = private.helpers.stringToBytes('POST /private-editor-only HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nA')
                for editor in (private.reqTemplateEditor, private.checkPageEditor): editor.setMessage(wire, True)
                statuses = []
                private.set_status = statuses.append
                private._clear_req_template()
                private._clear_check_template()
                checks['actual_native_template_clear'] = (not private.reqTemplateEditor.getMessage() and not private.checkPageEditor.getMessage() and len(statuses) == 2)
            except (BaseException, Throwable): errors.append(traceback.format_exc())
            finally: private.close_custom_runtime()
        if SwingUtilities.isEventDispatchThread(): editors()
        else: SwingUtilities.invokeAndWait(editors)
    return dict(kind='K10-B-aggregate-native-private-no-network', source_sha256=hashlib.sha256(raw).hexdigest(),
                final_cases=result.testsRun, final_log=stream.getvalue(), checks=checks, errors=errors,
                cleanup=cleanup, conversions=conversions, actual_burp_helpers=bool(actual_callbacks), network_requests=0,
                passed=result.wasSuccessful() and all(checks.values()) and not errors and cleanup['passed'] and conversions['passed'])


def summary(report):
    return 'K10B_FINAL %s (%d final cases; %d cleanup/UI checks; %d logging checks; %d conversion checks)' % (
        'PASS' if report['passed'] else 'FAIL', report['final_cases'], len(report['cleanup']['checks']),
        len(report['cleanup']['logging_regression']['checks']), len(report['conversions']['checks']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    report = run_checks()
    with open(args.report, 'w') as handle: json.dump(report, handle, indent=2)
    print(summary(report))
    if not report['passed']: print(json.dumps(report, indent=2))
    sys.exit(0 if report['passed'] else 1)
