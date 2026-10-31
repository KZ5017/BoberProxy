# -*- coding: utf-8 -*-
"""Finite private K08-K09 runtime verification; no traffic/main UI changes."""
from burp import IBurpExtender, IExtensionStateListener
from java.lang import Throwable
import json
import os
import sys
import threading
import traceback


class BurpExtender(IBurpExtender,IExtensionStateListener):
    def registerExtenderCallbacks(self,callbacks):
        callbacks.setExtensionName('BoberProxy K08-K09 log verification')
        callbacks.registerExtensionStateListener(self)
        self.closed=False
        directory=os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0,directory)
        def verify():
            try:
                from probe_logging_native import run_checks
                report=run_checks(callbacks)
                report['burp_version']=list(callbacks.getBurpVersion())
                path=os.path.join(directory,'runtime','k089-burp-logging.json')
                with open(path,'w') as handle: json.dump(report,handle,indent=2)
                if not self.closed:
                    callbacks.printOutput('K089_LOGGING %s (%d storage cases; %d native/UI checks)\n%s' % (
                        'PASS' if report['passed'] else 'FAIL',report['logic_cases'],len(report['checks']),path))
                    if report['errors']: callbacks.printError('\n'.join(report['errors']))
            except (BaseException,Throwable):
                if not self.closed: callbacks.printError(traceback.format_exc())
        self.thread=threading.Thread(target=verify,name='BoberProxy.K089.finite-verification')
        self.thread.setDaemon(True)
        self.thread.start()
    def extensionUnloaded(self): self.closed=True
