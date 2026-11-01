# -*- coding: utf-8 -*-
"""K10/B observable UI/startup failures, without changing successful workflows."""
from __future__ import print_function
import unittest
from source_harness import CapturedOutput, load_namespace, new_ui
from test_cleanup import SECRET


class FinalCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.ns = load_namespace()

    def setUp(self): self.ui = new_ui(self.ns)
    def tearDown(self): self.ui.close_custom_runtime()

    def test_template_clear_never_sends_null_to_either_editor(self):
        class Editor(object):
            def __init__(self): self.calls = []
            def setMessage(self, value, request): self.calls.append((value, request))
        statuses = []
        self.ui.set_status = statuses.append
        self.ui.reqTemplateEditor, self.ui.checkPageEditor = Editor(), Editor()
        self.ui._clear_req_template()
        self.ui._clear_check_template()
        self.assertEqual(self.ui.reqTemplateEditor.calls, [(b'', True)])
        self.assertEqual(self.ui.checkPageEditor.calls, [(b'', True)])
        self.assertEqual(len(statuses), 2)

    def test_failed_template_clear_is_visible_and_does_not_claim_success(self):
        class BrokenEditor(object):
            def setMessage(self, *args): raise ValueError(SECRET)
        statuses = []
        self.ui.reqTemplateEditor = BrokenEditor()
        self.ui.set_status = statuses.append
        with CapturedOutput() as output: self.ui._clear_req_template()
        self.assertEqual(statuses, [])
        self.assertIn('REQUEST_TEMPLATE_CLEAR_FAILED', self.ui.customStatusArea.getText())
        self.assertIn('ValueError', output.text())
        self.assertNotIn(SECRET, output.text())

    def test_ui_error_reporting_failure_does_not_escape(self):
        def broken_log(message): raise ValueError(SECRET)
        self.ui._log = broken_log
        with CapturedOutput() as output: self.ui._ui_error('CONTROLLED_UI_FAILURE', ValueError(SECRET))
        self.assertIn('CONTROLLED_UI_FAILURE', output.text())
        self.assertIn('STATUS_REPORT_FAILED', output.text())
        self.assertNotIn(SECRET, output.text())

    def test_hostile_parser_exception_keeps_template_fallback(self):
        class Hostile(ValueError):
            def __str__(self): raise ValueError('bad exception text: ' + SECRET)
        def fail(): raise Hostile()
        with CapturedOutput() as output:
            result = self.ui.build_request_from_template(get_editor_message=fail, fallback_resp=b'FALLBACK')
        self.assertEqual(result, b'FALLBACK')
        self.assertIn('TEMPLATE_BUILD_FAILED', self.ui.customStatusArea.getText())
        self.assertIn('Hostile', self.ui.customStatusArea.getText())
        self.assertNotIn(SECRET, output.text())

    def test_failed_filter_load_is_closed_without_showing_default_draft(self):
        events = []
        class Dialog(object):
            def __init__(self, ui): self.dialog = self
            def load_from_parent(self): raise ValueError(SECRET)
            def setVisible(self, visible): events.append('visible')
            def setLocationRelativeTo(self, component): pass
            def _on_cancel(self): events.append('cancelled')
        previous = self.ns.get('FilterDialog')
        self.ns['FilterDialog'] = Dialog
        try:
            with CapturedOutput() as output: self.ui._open_filter_dialog()
            self.assertEqual(events, ['cancelled'])
            self.assertIn('FILTER_DIALOG_FAILED', self.ui.customStatusArea.getText())
            self.assertNotIn(SECRET, output.text())
        finally:
            if previous is None: self.ns.pop('FilterDialog', None)
            else: self.ns['FilterDialog'] = previous

    def test_startup_withdraw_continues_after_close_and_error_output_failures(self):
        events = []
        class UI(object):
            def __init__(self, *args): pass
            def close_custom_runtime(self):
                events.append('close')
                raise ValueError(SECRET)
        class Callbacks(object):
            def getHelpers(self): return None
            def setExtensionName(self, name): pass
            def registerExtensionStateListener(self, listener): pass
            def addSuiteTab(self, tab): events.append('tab')
            def registerHttpListener(self, listener): events.append('http')
            def registerProxyListener(self, listener): raise ValueError(SECRET)
            def removeHttpListener(self, listener): events.append('remove_http')
            def removeSuiteTab(self, tab): events.append('remove_tab')
            def printError(self, text):
                self.message = text
                raise ValueError(SECRET)
        previous = self.ns['LoggerUI']
        self.ns['LoggerUI'] = UI
        callbacks = Callbacks()
        extension = self.ns['BurpExtender']()
        try:
            with CapturedOutput() as output:
                utilities = self.ns['swing'].SwingUtilities
                operation = lambda: extension.registerExtenderCallbacks(callbacks)
                if utilities.isEventDispatchThread(): operation()
                else: utilities.invokeAndWait(operation)
            self.assertIsNone(extension.ui)
            self.assertEqual(events, ['tab', 'http', 'close', 'remove_http', 'remove_tab'])
            self.assertIn('UI_INITIALIZATION_FAILED', output.text())
            self.assertIn('UI_CLEANUP_FAILED', output.text())
            self.assertIn('ERROR_OUTPUT_FAILED', output.text())
            self.assertNotIn(SECRET, output.text())
            self.assertNotIn(SECRET, callbacks.message)
        finally: self.ns['LoggerUI'] = previous


if __name__ == '__main__': unittest.main()
