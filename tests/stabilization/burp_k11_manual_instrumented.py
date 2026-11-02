# -*- coding: utf-8 -*-
"""Same-real-message manual interception proof, unchanged root source.

No file command channel. Only the existing narrow manual guard forces actions.
Remove this entry and reload the root directly after the single manual pair.
"""
from burp import IBurpExtender
from javax.swing import SwingUtilities
import os
import sys


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        directory=os.path.dirname(unicode(callbacks.getExtensionFilename()))
        sys.path.insert(0,directory)
        from source_harness import ROOT
        from probe_template_native import load_source
        from k11_manual import ManualObserver
        ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
        Main=ns['BurpExtender']
        before,after=ManualObserver(),ManualObserver()
        before.ROLE,after.ROLE='before','after'
        before.registerExtenderCallbacks(callbacks,register_proxy=False)
        after.registerExtenderCallbacks(callbacks,register_proxy=False)
        class Observed(Main):
            def processProxyMessage(this,request,message):
                before.processProxyMessage(request,message)
                try: Main.processProxyMessage(this,request,message)
                finally: after.processProxyMessage(request,message)
        class RootCallbacks(object):
            def __getattr__(this,name): return getattr(callbacks,name)
            def getExtensionFilename(this): return os.path.join(ROOT,'BoberProxy.py')
        if SwingUtilities.isEventDispatchThread(): raise ValueError('Load via the extension loader thread')
        self.main=Observed()
        Main.registerExtenderCallbacks(self.main,RootCallbacks())
        SwingUtilities.invokeAndWait(lambda:None)
        if self.main.ui is None: raise ValueError('Main UI did not initialize')
        callbacks.setExtensionName('BoberProxy K11 same-message manual verification')
        callbacks.printOutput('K11_MANUAL_INSTRUMENTED READY (same real Proxy message; unchanged main source)')
