# -*- coding: utf-8 -*-
"""K10/A private native startup, callback and diagnostic checks. No network."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import traceback
import unittest
from StringIO import StringIO
from javax.swing import SwingUtilities, ListSelectionModel, JPanel
from java.io import IOException
from java.lang import Throwable, System
from source_harness import ROOT, CapturedOutput, new_ui
from probe_template_native import load_source
from probe_logging_native import NativeHelpers, run_checks as logging_checks
from test_cleanup import CleanupTests, SECRET


def run_checks(actual_callbacks=None, expected_marker='K10-A', expected_line=None):
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    ns['_probe_threads'] = []
    checks, errors, editors, registrations = {}, [], [], []
    helpers = actual_callbacks.getHelpers() if actual_callbacks else NativeHelpers()

    def edt(operation):
        failures = []
        def invoke():
            try: operation()
            except (BaseException, Throwable): failures.append(traceback.format_exc())
        if SwingUtilities.isEventDispatchThread(): invoke()
        else: SwingUtilities.invokeAndWait(invoke)
        if failures: raise AssertionError('\n'.join(failures))

    class Callbacks(object):
        def getHelpers(self): return helpers
        def setExtensionName(self, name): pass
        def registerExtensionStateListener(self, listener): registrations.append('state')
        def addSuiteTab(self, tab): registrations.append('tab')
        def registerHttpListener(self, listener): registrations.append('http')
        def registerProxyListener(self, listener): registrations.append('proxy')
        def printError(self, message): errors.append(str(message))
        def createMessageEditor(self, controller, editable):
            editors.append(bool(SwingUtilities.isEventDispatchThread()))
            if actual_callbacks: return actual_callbacks.createMessageEditor(controller, editable)
            class Editor(object):
                def __init__(self): self.value = helpers.stringToBytes('')
                def getMessage(self): return self.value
                def getComponent(self): return JPanel()
                def setMessage(self, value, is_request):
                    if value is None: raise ValueError('Message cannot be null')
                    self.value = value
            return Editor()

    extension, ui = ns['BurpExtender'](), None
    try:
        with CapturedOutput() as output:
            extension.registerExtenderCallbacks(Callbacks())
            edt(lambda: None)
        ui = extension.ui
        if ui is None: raise AssertionError('Private UI startup failed')
        checks['startup_only_expected_line'] = output.text().strip() == (expected_line or 'BoberProxy loaded (stabilization %s)' % expected_marker)
        checks['exactly_four_editors_all_on_edt'] = len(editors) == 4 and all(editors)
        checks['native_callbacks_registered'] = registrations == ['state', 'tab', 'http', 'proxy']
        checks['no_unused_editor_or_search_state'] = not any(hasattr(owner, name) for owner, name in (
            (extension, 'msgEditor'), (ui, 'msgEditor'), (ui, '_search_matches'), (ui, '_current_match_idx'), (ui, 'running')))
        checks['multiple_selection_preserved'] = ui.table.getSelectionModel().getSelectionMode() == ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        def toggle():
            ui.proxyModeBtn.doClick(0)
            first = not ui.autoFollowRTChk.isEnabled()
            ui.useCheckPageChk.doClick(0)
            second = ui.autoFollowRTChk.isEnabled() and not ui.autoFollowRTChk.isSelected()
            ui.proxyModeBtn.doClick(0)
            checks['mode_buttons_preserve_enable_and_selection_rules'] = first and second and not ui.autoFollowRTChk.isEnabled() and not ui.autoFollowRTChk.isSelected()
        edt(toggle)
        private = new_ui(ns)
        try:
            def fail(**kwargs): raise IOException(SECRET)
            private.build_request_from_template = fail
            with CapturedOutput() as output: result = private.build_checkpage_request()
            checks['java_checkpage_exception_safe_none_fallback'] = result is None and 'CHECKPAGE_BUILD_FAILED' in output.text() and 'IOException' in output.text() and SECRET not in output.text()
            class BrokenStatus(object):
                def setText(self, value): raise IOException(SECRET)
            private.customStatusArea = BrokenStatus()
            with CapturedOutput() as output: edt(lambda: ns['LoggerUI']._log(private, SECRET))
            checks['java_status_error_has_safe_diagnostic'] = 'CUSTOM_STATUS_UPDATE_FAILED' in output.text() and SECRET not in output.text()
        finally: private.close_custom_runtime()
        class NativeCleanup(CleanupTests):
            @classmethod
            def setUpClass(cls): cls.ns = ns
        stream = StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeCleanup))
        checks['native_diagnostic_cases'] = result.wasSuccessful()
        if not result.wasSuccessful(): errors.append(stream.getvalue())
    except (BaseException, Throwable): errors.append(traceback.format_exc())
    finally:
        extension.extensionUnloaded()
        edt(lambda: None)
        if ui is not None:
            checks['private_unload_closes_timers_and_session'] = ui._custom_ui_closed and ui._filter_timer is None and ui._runtime_publisher.closed
    regression = logging_checks(actual_callbacks)
    return dict(kind='K10-A-private-native-no-network', source_sha256=hashlib.sha256(raw).hexdigest(),
                checks=checks, errors=errors, diagnostic_cases=6, logging_regression=regression,
                actual_burp_helpers=bool(actual_callbacks), network_requests=0,
                java_version=str(System.getProperty('java.version')),
                passed=len(checks) == 10 and all(checks.values()) and not errors and regression['passed'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    report = run_checks()
    with open(args.report, 'w') as handle: json.dump(report, handle, indent=2)
    print('K10A_CLEANUP %s (%d diagnostic cases; %d cleanup/UI checks; %d logging checks)' % (
        'PASS' if report['passed'] else 'FAIL', report['diagnostic_cases'], len(report['checks']), len(report['logging_regression']['checks'])))
    if report['errors']: print('\n'.join(report['errors']))
    if not report['logging_regression']['passed']: print(json.dumps(report['logging_regression'], indent=2))
    sys.exit(0 if report['passed'] else 1)
