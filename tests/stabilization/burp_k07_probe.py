# -*- coding: utf-8 -*-
"""Finite private K07 probes. No traffic, no live main-extension setting edits."""
from burp import IBurpExtender, IExtensionStateListener
import json
import os
import sys
import threading
import traceback


class BurpExtender(IBurpExtender,IExtensionStateListener):
    def registerExtenderCallbacks(self,callbacks):
        callbacks.setExtensionName('BoberProxy K07 filter verification')
        callbacks.registerExtensionStateListener(self)
        self.closed=False
        directory=os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0,directory)
        def verify():
            try:
                from probe_filters_native import run_checks
                report=run_checks(callbacks)
                report['burp_version']=list(callbacks.getBurpVersion())
                path=os.path.join(directory,'runtime','k07-burp-filters.json')
                with open(path,'w') as handle:
                    json.dump(report,handle,indent=2)
                if not self.closed:
                    callbacks.printOutput('K07_FILTERS %s (%d logic cases; %d native/UI checks)\n%s' % (
                        'PASS' if report['passed'] else 'FAIL',report['logic_cases'],len(report['checks']),path))
                    if report['errors']:
                        callbacks.printError('\n'.join(report['errors']))
            except BaseException:
                if not self.closed:
                    callbacks.printError(traceback.format_exc())
        self.thread=threading.Thread(target=verify,name='BoberProxy.K07.finite-verification')
        self.thread.setDaemon(True)
        self.thread.start()
    def extensionUnloaded(self):
        self.closed=True
