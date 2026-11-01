# -*- coding: utf-8 -*-
"""SI00 first gate: owned cookie API only; no traffic or main UI changes."""
from burp import IBurpExtender, IExtensionStateListener, ISessionHandlingAction
from java.lang import System, Throwable
import hashlib
import json
import os
import sys
import threading


class BurpExtender(IBurpExtender, IExtensionStateListener, ISessionHandlingAction):
    def registerExtenderCallbacks(self, callbacks):
        self._probe_closed = False
        self._probe_callbacks = callbacks
        self._probe_registered = False
        self._probe_action_calls = 0
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        self._probe_path = os.path.join(directory, 'runtime', 'si00-burp-cookie-api.json')
        self._probe_source = os.path.join(directory, '..', '..', 'BoberProxy.py')
        callbacks.setExtensionName('BoberProxy SI00 session API inspection')
        callbacks.registerExtensionStateListener(self)
        if self._probe_closed:
            return
        try:
            callbacks.registerSessionHandlingAction(self)
            self._probe_registered = True
            if self._probe_closed:
                self.extensionUnloaded()
                return
            self._probe_thread = threading.Thread(target=self._verify, name='BoberProxy.SI00.cookie-api')
            self._probe_thread.setDaemon(True)
            self._probe_thread.start()
        except (BaseException, Throwable):
            if self._probe_registered:
                callbacks.removeSessionHandlingAction(self)
                self._probe_registered = False
            raise

    def getActionName(self):
        return 'BoberProxy SI00 observer (no request changes)'

    def performAction(self, currentRequest, macroItems):
        # This first gate never changes or sends a request, even if selected by a rule.
        self._probe_action_calls += 1

    def _verify(self):
        from si00_cookie_probe import run_checks
        callbacks = self._probe_callbacks
        with open(self._probe_source, 'rb') as handle:
            source_hash = hashlib.sha256(handle.read()).hexdigest()
        def persist(report):
            report['source_sha256'] = source_hash
            report['burp_version'] = list(callbacks.getBurpVersion())
            report['java_version'] = str(System.getProperty('java.version'))
            report['session_action_name'] = self.getActionName()
            report['session_action_registered'] = self._probe_registered
            report['session_action_calls'] = self._probe_action_calls
            parent = os.path.dirname(self._probe_path)
            if not os.path.isdir(parent): os.makedirs(parent)
            with open(self._probe_path, 'w') as handle: json.dump(report, handle, indent=2)
        try:
            report = run_checks(callbacks, closed=lambda: self._probe_closed, persist=persist)
            with open(self._probe_source, 'rb') as handle:
                unchanged = hashlib.sha256(handle.read()).hexdigest() == source_hash
            report['checks']['main_source_unchanged'] = unchanged
            report['checks']['session_action_registered'] = self._probe_registered
            report['passed'] = report['passed'] and unchanged and self._probe_registered
            persist(report)
            if not self._probe_closed:
                callbacks.printOutput('SI00_COOKIE_API %s (%d checks)\n%s' % (
                    'PASS' if report['passed'] else 'FAIL', len(report['checks']), self._probe_path))
                if not report['cleanup_complete']:
                    callbacks.printError('SI00 OWNED_COOKIE_CLEANUP_INCOMPLETE; see synthetic ownership manifest: ' + self._probe_path)
                elif report['errors']:
                    callbacks.printError('SI00 cookie API probe failed; see report error types.')
        except (BaseException, Throwable) as error:
            if not self._probe_closed:
                callbacks.printError('SI00_REPORT_FAILED (' + type(error).__name__ + ')')

    def extensionUnloaded(self):
        self._probe_closed = True
        if self._probe_registered:
            self._probe_callbacks.removeSessionHandlingAction(self)
            self._probe_registered = False
