# -*- coding: utf-8 -*-
"""Run the unchanged main source with before/after instrumentation in one callback.

Separate legacy extensions may receive independent compatibility wrappers in
current Burp. This entry point uses the same actual IInterceptedProxyMessage
before and after invoking the real production method, not a message double.
Remove this test wrapper and load BoberProxy.py directly after validation.
"""
import hashlib
import json
import os
import sys
import traceback

from burp import IBurpExtender
from java.lang import Exception as JavaException


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        from source_harness import ROOT
        from probe_template_native import load_source
        from k03_action_listener import ActionListener
        namespace, source_bytes = load_source(os.path.join(ROOT, 'BoberProxy.py'))
        MainExtender = namespace['BurpExtender']

        class Instrumented(MainExtender):
            def processProxyMessage(self, messageIsRequest, intercepted):
                self._k03_before.processProxyMessage(messageIsRequest, intercepted)
                try:
                    MainExtender.processProxyMessage(self, messageIsRequest, intercepted)
                finally:
                    self._k03_after.processProxyMessage(messageIsRequest, intercepted)

        self.main = Instrumented()
        self.main._k03_before = ActionListener(callbacks, 'before', directory)
        self.main._k03_after = ActionListener(callbacks, 'after', directory)
        MainExtender.registerExtenderCallbacks(self.main, callbacks)
        callbacks.setExtensionName('BoberProxy K03 instrumented validation')
        callbacks.printOutput('K03_INSTRUMENTED READY (real main source; same-message before/after trace)')
        try:
            from probe_k03_native import run_checks
            result = run_checks(callbacks)
            result['burp_version'] = list(callbacks.getBurpVersion())
            result['instrumentation'] = 'before-and-after-same-real-proxy-callback'
            result['loaded_main_source_sha256'] = hashlib.sha256(source_bytes).hexdigest()
            path = os.path.join(directory, 'runtime', 'k03-burp-native.json')
            with open(path, 'w') as handle:
                handle.write(json.dumps(result, indent=2) + '\n')
            callbacks.printOutput('K03_NATIVE %s (%d checks)\n%s' % (
                'PASS' if result['passed'] else 'FAIL', len(result['checks']), path))
            if result['errors']:
                callbacks.printError('\n'.join(result['errors']))
        except (Exception, JavaException):
            callbacks.printError(traceback.format_exc())

