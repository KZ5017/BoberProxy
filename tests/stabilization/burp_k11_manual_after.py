# -*- coding: utf-8 -*-
import os
import sys
from burp import IBurpExtender


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        sys.path.insert(0,os.path.dirname(unicode(callbacks.getExtensionFilename())))
        from k11_manual import ManualObserver
        self.observer=ManualObserver()
        self.observer.ROLE='after'
        self.observer.registerExtenderCallbacks(callbacks)
