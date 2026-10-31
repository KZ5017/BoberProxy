# -*- coding: utf-8 -*-
"""K06 finite source/session and EDT checks. No network or live configuration edits."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import time
import traceback
import unittest
from StringIO import StringIO
from javax.swing import JPanel, JTextArea, JScrollPane, SwingUtilities, JTable
from javax.swing.table import TableRowSorter
from burp import IMessageEditorController
from java.lang import System

from source_harness import ROOT, Helpers, CapturedOutput
from probe_template_native import load_source
from test_runtime_session import RuntimeSessionTests


def run_checks(actual_callbacks=None):
    helpers = actual_callbacks.getHelpers() if actual_callbacks else Helpers()
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    ns['_probe_threads'] = []
    checks, errors, current, registrations = {}, [], [], []

    def ui_call(operation):
        failures = []
        def invoke():
            try:
                operation()
            except BaseException:
                failures.append(traceback.format_exc())
        if SwingUtilities.isEventDispatchThread():
            invoke()
        else:
            SwingUtilities.invokeAndWait(invoke)
        if failures:
            raise RuntimeError('\n'.join(failures))

    def wait_for(predicate):
        end = time.time() + 3
        while time.time() < end:
            if predicate():
                return True
            time.sleep(0.01)
        return False

    class NativeSessions(RuntimeSessionTests):
        @classmethod
        def setUpClass(cls):
            cls.ns = ns
    stream = StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(NativeSessions))
    checks['native_session_ordering_regressions'] = result.wasSuccessful()
    if not result.wasSuccessful():
        errors.append(stream.getvalue())

    class ProbeController(IMessageEditorController):
        def getHttpService(self):
            return helpers.buildHttpService('127.0.0.1', 18765, False)
        def getRequest(self):
            return helpers.stringToBytes('GET /k06-editor-only HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        def getResponse(self):
            return None

    class Editor(object):
        def __init__(self):
            self.area = JTextArea()
            self.panel = JScrollPane(self.area)
        def getComponent(self):
            return self.panel
        def getMessage(self):
            return helpers.stringToBytes(self.area.getText())
        def setMessage(self, message, request):
            self.area.setText(helpers.bytesToString(message) if message is not None else '')

    class Callbacks(object):
        def getHelpers(self):
            return helpers
        def createMessageEditor(self, controller, editable):
            checks['editors_created_on_edt'] = SwingUtilities.isEventDispatchThread()
            if actual_callbacks:
                return actual_callbacks.createMessageEditor(ProbeController(), editable)
            return Editor()
        def registerExtensionStateListener(self, listener):
            registrations.append(('state', listener))
        def registerHttpListener(self, listener):
            registrations.append(('http', listener))
        def registerProxyListener(self, listener):
            registrations.append(('proxy', listener))
        def addSuiteTab(self, tab):
            registrations.append(('tab', tab))
        def setExtensionName(self, name):
            pass
        def printError(self, text):
            errors.append(str(text))

    try:
        extension = ns['BurpExtender']()
        cb = Callbacks()
        with CapturedOutput():
            # Called from the loader thread, source must schedule its own UI.
            extension.registerExtenderCallbacks(cb)
            ui_call(lambda: None)
        ui = extension.ui
        if ui is None:
            raise AssertionError('Source registration failed: ' + repr(errors))
        current.append(ui)
        checks['source_ui_constructed_on_edt'] = ui._creation_on_edt
        checks['snapshot_ready_before_listeners'] = ui._runtime_config is not None and [x[0] for x in registrations] == ['state','tab','http','proxy']
        initial = ui._capture_runtime()
        checks['initial_options_off'] = not any(initial.get(name) for name in ('proxy','use_cp','follow','cookies','csrf'))
        checks['initial_custom_off'] = not initial.get('custom')[0]
        ui_call(lambda: ui._publish_runtime())
        checks['unchanged_snapshot_keeps_version'] = initial.version == ui._capture_runtime().version
        ui_call(lambda: ui.payloadParamField.setText('K06_PAYLOAD'))
        checks['document_edit_publishes_version'] = wait_for(lambda: ui._capture_runtime().get('payload1') == 'K06_PAYLOAD')
        checks['old_snapshot_unchanged'] = initial.get('payload1') == 'q'
        ui_call(lambda: ui.proxyModeBtn.doClick(0))
        checks['item_event_publishes_switch'] = wait_for(lambda: ui._capture_runtime().get('proxy'))

        payload = ''.join(chr(i) for i in range(256)).decode('latin-1')
        data = u'POST /k06-bytes HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 256\r\n\r\n' + payload
        wire = helpers.stringToBytes(data)
        ui_call(lambda: ui.reqTemplateEditor.setMessage(wire, True))
        checks['native_editor_bytes_published'] = wait_for(lambda: ui._capture_runtime().get('rt') == data.encode('latin-1'))
        frozen = ui._capture_runtime()
        ui_call(lambda: ui.reqTemplateEditor.setMessage(helpers.stringToBytes('GET /changed HTTP/1.1\r\n\r\n'), True))
        checks['editor_programmatic_change_published'] = wait_for(lambda: ui._capture_runtime().get('rt') != frozen.get('rt'))
        checks['old_template_all_256_bytes_immutable'] = frozen.get('rt') == data.encode('latin-1')

        # From outside the EDT, these methods use the published version only.
        saved = ui._collect_runtime_values
        calls = []
        def forbidden():
            calls.append(True)
            raise AssertionError('Off-EDT snapshot collection')
        ui._collect_runtime_values = forbidden
        try:
            snapshot = ui._capture_runtime()
            ui.should_log(4, True, None, snapshot)
            checks['callback_snapshot_has_no_widget_reads'] = not calls
        finally:
            ui._collect_runtime_values = saved

        ui.set_status('K06_EDT_STATUS')
        ui_call(lambda: checks.update(real_status_label_updated=ui.statusLabel.getText() == 'K06_EDT_STATUS'))
        ui_call(lambda: ui.close_custom_runtime())
        ui_call(lambda: None)
        version = ui._capture_runtime().version
        ui_call(lambda: ui.payloadParamField.setText('AFTER_CLOSE'))
        ui_call(lambda: ui.set_status('AFTER_CLOSE'))
        ui_call(lambda: checks.update(
            unload_stops_publisher=not ui._runtime_publisher.timer.isRunning(),
            unload_detaches_listeners=not ui._runtime_publisher.documents and not ui._runtime_publisher.items,
            unload_preserves_snapshot=ui._capture_runtime().version == version,
            unload_cannot_publish_status=ui.statusLabel.getText() == 'K06_EDT_STATUS',
            unload_closes_coordinator=ui.sessions.closed))

        # Unload before queued initialize: never register an orphan UI/listener.
        registrations[:] = []
        cancelled = ns['BurpExtender']()
        def cancel_before_dispatch():
            # Simulate the loader scheduling initialization behind this EDT job.
            worker = __import__('threading').Thread(target=lambda: cancelled.registerExtenderCallbacks(cb))
            worker.start()
            worker.join(2)
            if worker.is_alive():
                raise AssertionError('Registration waited for the EDT')
            cancelled.extensionUnloaded()
        ui_call(cancel_before_dispatch)
        ui_call(lambda: None)
        checks['unload_before_initialize_creates_no_orphan'] = cancelled.ui is None and [x[0] for x in registrations] == ['state']

        # A partial registration failure must close the private UI and detach
        # any already installed callback/tab, without leaving a poll timer.
        partial = []
        class FailingCallbacks(Callbacks):
            def addSuiteTab(self, tab):
                partial.append(tab)
            def registerHttpListener(self, listener):
                raise ValueError('K06 controlled registration failure')
            def removeSuiteTab(self, tab):
                partial.append('removed')
            def printError(self, text):
                partial.append(str(text))
        failed = ns['BurpExtender']()
        failed.registerExtenderCallbacks(FailingCallbacks())
        ui_call(lambda: None)
        ui_call(lambda: None)
        checks['partial_registration_failure_cleans_ui'] = (failed.ui is None and partial[0]._custom_ui_closed
            and not partial[0]._runtime_publisher.timer.isRunning() and 'removed' in partial
            and 'K06 controlled registration failure' in str(partial[-1]))

        cancelled_registrations = []
        for cancel_at in ('tab', 'http', 'proxy'):
            class UnloadDuringRegistration(Callbacks):
                def __init__(self):
                    self.active, self.created = [], []
                def install(self, kind):
                    self.active.append(kind)
                    if kind == cancel_at:
                        subject.extensionUnloaded()
                        # The host removes registrations that exist at unload;
                        # a registration installed afterwards would be orphaned.
                        self.active[:] = []
                def addSuiteTab(self, tab):
                    self.created.append(tab)
                    self.install('tab')
                def registerHttpListener(self, listener):
                    self.install('http')
                def registerProxyListener(self, listener):
                    self.install('proxy')
                def removeSuiteTab(self, tab):
                    self.active[:] = [x for x in self.active if x != 'tab']
                def removeHttpListener(self, listener):
                    self.active[:] = [x for x in self.active if x != 'http']
                def removeProxyListener(self, listener):
                    self.active[:] = [x for x in self.active if x != 'proxy']
            subject = ns['BurpExtender']()
            cancelling_cb = UnloadDuringRegistration()
            subject.registerExtenderCallbacks(cancelling_cb)
            ui_call(lambda: None)
            ui_call(lambda: None)
            cancelled_registrations.append(dict(stage=cancel_at, remaining=list(cancelling_cb.active),
                passed=subject.ui is None and not cancelling_cb.active
                and cancelling_cb.created[0]._custom_ui_closed
                and not cancelling_cb.created[0]._runtime_publisher.timer.isRunning()))
        checks['unload_during_registration_cannot_leave_resources'] = all(row['passed'] for row in cancelled_registrations)
    except BaseException:
        checks['native_ui_flow'] = False
        errors.append(traceback.format_exc())
    finally:
        for ui in current:
            ui_call(ui.close_custom_runtime)
        ui_call(lambda: None)
    return dict(kind='K06-native-session-configuration-EDT-no-network',
                actual_burp_helpers=bool(actual_callbacks), native_message_editors=bool(actual_callbacks),
                source_sha256=hashlib.sha256(raw).hexdigest(), checks=checks, errors=errors,
                session_cases=result.testsRun, session_log=stream.getvalue(),
                registration_cancellation=locals().get('cancelled_registrations', []),
                passed=bool(checks) and all(checks.values()) and not errors,
                python=sys.version, java_version=str(System.getProperty('java.version')))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    report = run_checks()
    with open(args.report, 'w') as handle:
        handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
