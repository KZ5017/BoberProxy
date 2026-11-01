# -*- coding: utf-8 -*-
"""Private finite K10/A verification; no traffic or live-main setting changes."""
from burp import IBurpExtender, IExtensionStateListener
from java.lang import Throwable
import json
import os
import sys
import threading
import traceback


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy K10-A cleanup verification')
        callbacks.registerExtensionStateListener(self)
        self.closed = False
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        def verify():
            try:
                from probe_cleanup_native import run_checks
                report = run_checks(callbacks)
                report['burp_version'] = list(callbacks.getBurpVersion())
                path = os.path.join(directory, 'runtime', 'k10a-burp-cleanup.json')
                with open(path, 'w') as handle: json.dump(report, handle, indent=2)
                if not self.closed:
                    callbacks.printOutput('K10A_CLEANUP %s (%d diagnostic cases; %d cleanup/UI checks; %d logging checks)\n%s' % (
                        'PASS' if report['passed'] else 'FAIL', report['diagnostic_cases'], len(report['checks']), len(report['logging_regression']['checks']), path))
                    errors = report['errors'] + report['logging_regression']['errors']
                    if errors: callbacks.printError('\n'.join(errors))
            except (BaseException, Throwable):
                if not self.closed: callbacks.printError(traceback.format_exc())
        self.thread = threading.Thread(target=verify, name='BoberProxy.K10A.finite-verification')
        self.thread.setDaemon(True)
        self.thread.start()
    def extensionUnloaded(self): self.closed = True
