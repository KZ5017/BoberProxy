# -*- coding: utf-8 -*-
"""Private UI03 code-editor verification; no traffic or main settings changes."""
from burp import IBurpExtender, IExtensionStateListener
from java.lang import Throwable
import json
import os
import sys
import threading
import traceback


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy UI03 code editor verification')
        callbacks.registerExtensionStateListener(self)
        self.closed = False
        directory = os.path.dirname(unicode(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        def verify():
            try:
                from probe_ui03_native import run_checks, summary
                report = run_checks(callbacks)
                report['burp_version'] = list(callbacks.getBurpVersion())
                path = os.path.join(directory, 'runtime', 'ui03-burp-editor.json')
                with open(path, 'w') as handle:
                    json.dump(report, handle, indent=2)
                if not self.closed:
                    callbacks.printOutput(summary(report) + '\n' + path)
                    if not report['passed']:
                        errors = report['errors'] + report['regression']['errors'] + report['regression']['regression']['errors']
                        if errors: callbacks.printError('\n'.join(errors))
            except (BaseException, Throwable):
                if not self.closed: callbacks.printError(traceback.format_exc())
        worker = threading.Thread(target=verify, name='BoberProxy.UI03.finite-verification')
        worker.setDaemon(True)
        worker.start()
    def extensionUnloaded(self):
        self.closed = True
