# -*- coding: utf-8 -*-
"""K10/A diagnostics: failure paths must stay observable without leaking data."""
from __future__ import print_function
import sys
import unittest
from source_harness import CapturedOutput, load_namespace, new_ui


SECRET = 'K10_SYNTHETIC_PAYLOAD_AND_TOKEN'


class CleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.ns = load_namespace()

    def test_diagnostic_omits_exception_text_and_does_not_stringify_it(self):
        class Hostile(ValueError):
            def __str__(self): raise AssertionError('must not stringify: ' + SECRET)
        with CapturedOutput() as output:
            self.ns['_print_diagnostic']('[BoberProxy] CONTROLLED', Hostile())
        self.assertIn('CONTROLLED (Hostile)', output.text())
        self.assertNotIn(SECRET, output.text())

    def test_broken_output_does_not_raise_from_diagnostic(self):
        class BrokenOutput(object):
            def write(self, value): raise ValueError(SECRET)
        previous = sys.stdout
        try:
            sys.stdout = BrokenOutput()
            self.ns['_print_diagnostic']('[BoberProxy] CONTROLLED', ValueError(SECRET))
        finally: sys.stdout = previous

    def test_http_callback_failure_is_visible_without_exception_contents(self):
        class UI(object):
            _custom_ui_closed = False
            _log_generation = 0
            def _capture_runtime(self): raise ValueError(SECRET)
        extension = self.ns['BurpExtender']()
        extension.ui = UI()
        with CapturedOutput() as output: extension.processHttpMessage(4, False, None)
        self.assertIn('HTTP_LOG_FAILED', output.text())
        self.assertIn('ValueError', output.text())
        self.assertNotIn(SECRET, output.text())

    def test_partial_analysis_failures_remain_visible_and_preserve_admission(self):
        queued = []
        class UI(object):
            _custom_ui_closed = False
            _log_generation = 7
            def _capture_runtime(self): return {}
            def _queue_filter_log(self, *args): queued.append(args)
        class Helpers(object):
            def analyzeRequest(self, value): raise ValueError(SECRET)
            def analyzeResponse(self, value): raise ValueError(SECRET)
        class Message(object):
            def getResponse(self): return b'HTTP/1.1 200 OK\r\n\r\n'
        extension = self.ns['BurpExtender']()
        extension.ui, extension.helpers = UI(), Helpers()
        with CapturedOutput() as output: extension.processHttpMessage(4, False, Message())
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0][2], 7)
        self.assertIn('HTTP_RESPONSE_ANALYSIS_FAILED', output.text())
        self.assertIn('HTTP_REQUEST_ANALYSIS_FAILED', output.text())
        self.assertNotIn(SECRET, output.text())

    def test_checkpage_exception_retains_none_fallback_with_safe_diagnostic(self):
        ui = new_ui(self.ns)
        def fail(**kwargs): raise ValueError(SECRET)
        ui.build_request_from_template = fail
        try:
            with CapturedOutput() as output: result = ui.build_checkpage_request()
            self.assertIsNone(result)
            self.assertIn('CHECKPAGE_BUILD_FAILED', output.text())
            self.assertNotIn(SECRET, output.text())
        finally: ui.close_custom_runtime()

    def test_workflow_output_failure_cannot_prevent_error_status(self):
        class UI(object):
            def _log(self, value): pass
        class BrokenOutput(object):
            def write(self, value): raise ValueError(SECRET)
        extension = self.ns['BurpExtender']()
        extension.ui = UI()
        result = self.ns['ProxyWorkflowResult']('ERROR_BEFORE_SEND', error_code='CONTROLLED')
        previous = sys.stdout
        try:
            sys.stdout = BrokenOutput()
            extension._report_workflow_error(result)
        finally: sys.stdout = previous


if __name__ == '__main__': unittest.main()
