# -*- coding: utf-8 -*-
"""Standalone native Swing registration smoke; callbacks/messages are doubles."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
from javax.swing import JPanel, SwingUtilities, JTable
from javax.swing.table import TableRowSorter
from burp import IProxyListener
from source_harness import ROOT, Helpers, as_bytes
from test_transport import Intercepted, Message, Service


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    directory = os.path.join(ROOT, 'tests', 'stabilization')
    temporary = os.path.join(directory, 'runtime', 'wrapper-smoke')
    if not os.path.isdir(os.path.join(temporary, 'runtime')):
        os.makedirs(os.path.join(temporary, 'runtime'))
    class Editor(object):
        def getComponent(self):
            return JPanel()
    class Callbacks(object):
        def __init__(self):
            self.listeners = []
            self.errors = []
        def getExtensionFilename(self):
            return os.path.join(temporary, 'synthetic-entry.py')
        def getHelpers(self):
            return Helpers()
        def createMessageEditor(self, *args):
            return Editor()
        def addSuiteTab(self, tab):
            self.tab = tab
        def registerHttpListener(self, listener):
            self.http_listener = listener
        def registerProxyListener(self, listener):
            self.listeners.append(listener)
        def setExtensionName(self, name):
            self.name = name
        def printOutput(self, value):
            pass
        def printError(self, value):
            self.errors.append(value)
        def getBurpVersion(self):
            return ['STANDALONE-SMOKE-DOUBLE']
    import probe_k03_native
    original = probe_k03_native.run_checks
    probe_k03_native.run_checks = lambda callbacks: dict(passed=True, checks={'registration_stub': True}, errors=[])
    checks, errors = {}, []
    try:
        path = os.path.join(directory, 'burp_k03_instrumented.py')
        namespace = {'__name__': 'k03_wrapper_smoke'}
        with open(path, 'rb') as handle:
            eval(compile(handle.read(), path, 'exec'), namespace)
        cb = Callbacks()
        def register():
            try:
                extension = namespace['BurpExtender']()
                extension.registerExtenderCallbacks(cb)
                checks['one_proxy_listener'] = len(cb.listeners) == 1 and isinstance(cb.listeners[0], IProxyListener)
                checks['real_swing_tab_created'] = cb.tab.getUiComponent() is not None
                checks['http_and_proxy_share_real_main'] = cb.http_listener is extension.main and cb.listeners[0] is extension.main
                class LocalService(Service):
                    def getHost(self):
                        return '127.0.0.1'
                    def getPort(self):
                        return 18766
                class LocalMessage(Message):
                    def getHttpService(self):
                        return LocalService()
                class LocalIntercepted(Intercepted):
                    def getMessageReference(self):
                        return 1
                message = LocalIntercepted()
                message.message = LocalMessage()
                message.message.request = as_bytes('GET /echo HTTP/1.1\r\nX-Bober-K03-Probe: request-drop\r\n\r\n')
                cb.listeners[0].processProxyMessage(True, message)
                checks['instrumented_main_preserves_received_drop'] = message.action == message.ACTION_DROP
                checks['no_registration_errors'] = not cb.errors
            except BaseException:
                import traceback
                errors.append(traceback.format_exc())
        SwingUtilities.invokeAndWait(register)
    finally:
        probe_k03_native.run_checks = original
    with open(os.path.join(ROOT, 'BoberProxy.py'), 'rb') as handle:
        source_hash = hashlib.sha256(handle.read()).hexdigest()
    result = dict(kind='standalone-wrapper-real-swing-callback-doubles', source_sha256=source_hash,
                  checks=checks, errors=errors, passed=bool(checks) and all(checks.values()) and not errors,
                  real_network_tested=False, native_probe_deliberately_stubbed=True)
    with open(args.report, 'w') as handle:
        handle.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
