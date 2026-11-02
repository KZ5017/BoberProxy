# -*- coding: utf-8 -*-
"""K11 private functional gate. No traffic; does not alter the main instance."""
from burp import IBurpExtender, IExtensionStateListener
from java.lang import Throwable
import json
import os
import sys
import threading
import traceback
import uuid


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy K11 final regression')
        callbacks.registerExtensionStateListener(self)
        self.closed = False
        directory = os.path.dirname(unicode(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        def verify():
            try:
                from probe_k11_native import run_checks, summary
                report = run_checks(callbacks, progress=callbacks.printOutput,
                                    cancelled=lambda: self.closed)
                path = os.path.join(directory, 'runtime', 'k11-burp-regression-' + uuid.uuid4().hex + '.json')
                with open(path, 'w') as handle: json.dump(report, handle, indent=2)
                if not self.closed: callbacks.printOutput(summary(report) + '\n' + path)
            except (BaseException, Throwable):
                if not self.closed: callbacks.printError(traceback.format_exc())
        worker = threading.Thread(target=verify, name='BoberProxy.K11.finite-regression')
        worker.setDaemon(True)
        worker.start()

    def extensionUnloaded(self):
        self.closed = True
