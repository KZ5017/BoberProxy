# -*- coding: utf-8 -*-
"""Standalone bounded TG05 entry-point smoke, before live loading only."""
import os, sys, json, traceback
from javax.swing import JPanel, SwingUtilities
from source_harness import ROOT
from probe_logging_native import NativeHelpers
from burp_target_scope_instrumented import BurpExtender

class Editor(object):
    def __init__(self): self.value=NativeHelpers().stringToBytes('')
    def getMessage(self): return self.value
    def setMessage(self, value, request): self.value=value
    def getComponent(self): return JPanel()
class Callbacks(object):
    def getHelpers(self): return NativeHelpers()
    def getExtensionFilename(self): return os.path.join(ROOT,'tests','stabilization','burp_target_scope_instrumented.py')
    def setExtensionName(self, value): pass
    def registerExtensionStateListener(self, value): pass
    def registerHttpListener(self, value): pass
    def registerProxyListener(self, value): pass
    def addSuiteTab(self, value): pass
    def createMessageEditor(self, controller, editable): return Editor()
    def printOutput(self, value): print(value)
    def printError(self, value): raise AssertionError(value)

probe=BurpExtender(); checks={}; errors=[]
try:
    probe.registerExtenderCallbacks(Callbacks())
    def run():
        for kind in ('none','A','B','T'):
            state=probe.apply(dict(action='profile',kind=kind))
            checks['profile_'+kind]=state['proxy']==(kind!='none') and state['cp']
        state=probe.apply(dict(action='profile',kind='A',prefix=True,active=False))
        checks['prefix_passive']=state['scope']=='http://127.0.0.1:18810/scope' and not state['proxy']
        state=probe.apply(dict(action='scope',kind='B'))
        checks['scope_reset']=state['sid'] is None and state['csrf'] is None and not state['proxy']
    SwingUtilities.invokeAndWait(run)
except BaseException: errors.append(traceback.format_exc())
finally:
    if hasattr(probe,'main'): probe.main.extensionUnloaded()
    SwingUtilities.invokeAndWait(lambda:None)
    if hasattr(probe,'thread'): probe.thread.join(2)
report=dict(kind='TG05-private-entry-smoke-no-network',checks=checks,errors=errors,passed=len(checks)==6 and all(checks.values()) and not errors)
with open(sys.argv[1],'w') as f:json.dump(report,f,indent=2)
print('TG05_ENTRY_SMOKE '+('PASS' if report['passed'] else 'FAIL'))
sys.exit(0 if report['passed'] else 1)
