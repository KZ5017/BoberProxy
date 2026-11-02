# -*- coding: utf-8 -*-
"""Native interface smoke for final manual observers, private temporary files."""
import argparse
import hashlib
import json
import os
import shutil
import tempfile
import traceback
from burp import IInterceptedProxyMessage
from java.lang import Throwable
from javax.swing import JPanel, SwingUtilities
from source_harness import ROOT
from probe_k11_load import LoadHelpers
from burp_k089_storage_probe import SyntheticMessage
from k11_manual import ManualObserver


def run():
    root=tempfile.mkdtemp(prefix='BoberProxy-manual-native-')
    assert os.path.dirname(os.path.realpath(root))==os.path.realpath(tempfile.gettempdir())
    checks,errors={},[]
    try:
        directory=os.path.join(root,'tests','stabilization')
        os.makedirs(os.path.join(directory,'runtime'))
        with open(os.path.join(root,'BoberProxy.py'),'wb') as handle: handle.write('# synthetic helper fixture\n')
        helpers=LoadHelpers()
        class Callbacks(object):
            def __init__(self): self.states=[];self.proxies=[]
            def getExtensionFilename(self): return os.path.join(directory,'probe.py')
            def getHelpers(self): return helpers
            def setExtensionName(self,value): pass
            def registerExtensionStateListener(self,value): self.states.append(value)
            def registerProxyListener(self,value): self.proxies.append(value)
            def registerHttpListener(self,value): pass
            def addSuiteTab(self,value): pass
            def createMessageEditor(self,*args):
                class Editor(object):
                    def __init__(self):self.value=helpers.stringToBytes('')
                    def getMessage(self):return self.value
                    def setMessage(self,value,request):self.value=value
                    def getComponent(self):return JPanel()
                return Editor()
            def printOutput(self,value): pass
            def printError(self,value): errors.append(unicode(value))
        class Proxy(IInterceptedProxyMessage):
            def __init__(self):
                self._action=0
                self._info=SyntheticMessage(helpers,helpers.stringToBytes('GET /echo?case=k11-manual HTTP/1.1\r\nX-Bober-Test-Run: k11-manual-native\r\n\r\n'),helpers.stringToBytes('HTTP/1.1 200 OK\r\n\r\n'))
                self._info.setHttpService(helpers.buildHttpService('127.0.0.1',18790,False))
            def getMessageInfo(self): return self._info
            def getMessageReference(self): return 37
            def getInterceptAction(self): return self._action
            def setInterceptAction(self,value): self._action=value
        before,after=ManualObserver(),ManualObserver()
        before.ROLE,after.ROLE='before','after'
        before.registerExtenderCallbacks(Callbacks()); after.registerExtenderCallbacks(Callbacks())
        message=Proxy()
        for request in (True,False):
            message.setInterceptAction(0)
            before.processProxyMessage(request,message)
            after.processProxyMessage(request,message)
        checks['both_native_phases_forced_and_observed']=len(after.events)==2 and all(e['after']==1 and e['reference']==37 for e in after.events)
        before.extensionUnloaded(); after.extensionUnloaded()
        checks['both_closed']=before.closed and after.closed
        with open(after.path) as handle: recorded=json.load(handle)
        checks['own_report_exact']=recorded['events']==after.events
        from burp_k11_manual_instrumented import BurpExtender
        callbacks=Callbacks();entry=BurpExtender()
        try:
            entry.registerExtenderCallbacks(callbacks)
            checks['only_one_real_proxy_listener_registered']=len(callbacks.proxies)==1
            proxy=Proxy()
            for request in (True,False):
                proxy.setInterceptAction(0)
                entry.main.processProxyMessage(request,proxy)
            with open(os.path.join(directory,'runtime','k11-manual-after.json')) as handle:composed=json.load(handle)
            checks['current_source_preserves_same_native_object']=len(composed['events'])==2 and all(event['before']==1 and event['after']==1 for event in composed['events'])
            checks['same_message_mode_recorded']=composed['instrumentation']=='same-real-proxy-message'
        finally:
            for listener in callbacks.states:listener.extensionUnloaded()
            SwingUtilities.invokeAndWait(lambda:None)
            checks['composed_ui_closed']=entry.main.ui._custom_ui_closed and entry.main.ui._filter_timer is None
    except (BaseException,Throwable): errors.append(traceback.format_exc())
    finally:
        resolved=os.path.realpath(root)
        assert os.path.dirname(resolved)==os.path.realpath(tempfile.gettempdir()) and os.path.basename(resolved).startswith('BoberProxy-manual-native-')
        shutil.rmtree(resolved)
    checks['own_fixture_removed']=not os.path.exists(root)
    with open(os.path.join(ROOT,'BoberProxy.py'),'rb') as handle: digest=hashlib.sha256(handle.read()).hexdigest()
    return dict(kind='K11-manual-observer-native-private-no-network',checks=checks,errors=errors,source_sha256=digest,passed=bool(checks) and all(checks.values()) and not errors)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report',required=True);args=parser.parse_args()
    if os.path.exists(args.report): raise ValueError('Report exists')
    result=run()
    with open(args.report,'w') as handle: json.dump(result,handle,indent=2)
    print(json.dumps(result,indent=2))
    import sys
    sys.exit(0 if result['passed'] else 1)
