# -*- coding: utf-8 -*-
"""Private native/UI target-scope checks; no HTTP requests or main-instance changes."""
from burp import IBurpExtender
import os,sys,json
class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        directory=os.path.dirname(unicode(callbacks.getExtensionFilename()))
        sys.path.insert(0,directory)
        from probe_target_scope_native import run_checks, summary
        callbacks.setExtensionName('BoberProxy Target Scope verification')
        report=run_checks(callbacks)
        path=os.path.join(directory,'runtime','tg-burp-native.json')
        with open(path,'w') as handle: json.dump(report,handle,indent=2)
        callbacks.printOutput(summary(report))
        callbacks.printOutput(path)
