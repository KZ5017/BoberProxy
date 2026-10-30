# -*- coding: utf-8 -*-
"""Load before the main K03 extension; see K03 validation instructions."""
import os
import sys
from burp import IBurpExtender


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        sys.path.insert(0, os.path.dirname(str(callbacks.getExtensionFilename())))
        from k03_action_listener import install
        self.listener = install(callbacks, 'before')
