# -*- coding: utf-8 -*-
"""Finite private UI01 layout/editor check; no traffic or main settings changes."""
from burp import IBurpExtender, IExtensionStateListener
from java.lang import Throwable
import json
import os
import sys
import threading
import traceback


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('BoberProxy UI01 layout verification')
        callbacks.registerExtensionStateListener(self)
        self.closed = False
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        def verify():
            try:
                from probe_sidebar_native import run_checks, summary
                report = run_checks(callbacks)
                report['burp_version'] = list(callbacks.getBurpVersion())
                path = os.path.join(directory,'runtime','ui016-burp-layout.json')
                with open(path,'w') as handle: json.dump(report,handle,indent=2)
                if not self.closed:
                    callbacks.printOutput(summary(report)+'\n'+path)
                    errors=report['errors']+report['regression']['errors']
                    if errors: callbacks.printError('\n'.join(errors))
            except (BaseException, Throwable):
                if not self.closed: callbacks.printError(traceback.format_exc())
        self.thread=threading.Thread(target=verify,name='BoberProxy.UI01.finite-verification')
        self.thread.setDaemon(True)
        self.thread.start()
    def extensionUnloaded(self): self.closed=True
