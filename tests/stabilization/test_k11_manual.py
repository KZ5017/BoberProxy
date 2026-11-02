"""Scope/lifecycle tests for manual observers; isolated API doubles, no Burp."""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest


class ManualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous={key:sys.modules.get(key) for key in ('burp','java','java.lang')}
        burp=types.ModuleType('burp')
        for name in ('IBurpExtender','IProxyListener','IExtensionStateListener'):
            setattr(burp,name,type(name,(),{}))
        java=types.ModuleType('java'); java.__path__=[]
        lang=types.ModuleType('java.lang'); lang.Throwable=Exception
        sys.modules.update({'burp':burp,'java':java,'java.lang':lang})
        scope={'unicode':str}
        source=Path(__file__).with_name('k11_manual.py')
        exec(compile(source.read_bytes(),str(source),'exec'),scope)
        cls.Observer=scope['ManualObserver']
    @classmethod
    def tearDownClass(cls):
        for key,value in cls.previous.items():
            if value is None: sys.modules.pop(key,None)
            else: sys.modules[key]=value
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='BoberProxy-manual-scope-')
        root=Path(self.temp.name); self.directory=root/'tests'/'stabilization'
        (self.directory/'runtime').mkdir(parents=True)
        (root/'BoberProxy.py').write_bytes(b'# synthetic fixture\n')
        owner=self
        class Callbacks:
            def getExtensionFilename(self): return str(owner.directory/'probe.py')
            def getHelpers(self): return self
            def bytesToString(self,value): return value.decode('latin-1')
            def setExtensionName(self,name): pass
            def registerExtensionStateListener(self,listener): pass
            def registerProxyListener(self,listener): pass
            def printOutput(self,text): pass
            def printError(self,text): raise AssertionError(text)
        self.callbacks=Callbacks()
    def tearDown(self): self.temp.cleanup()
    def message(self,path='/echo?case=k11-manual',host='127.0.0.1',port=18790,tag='k11-manual-unit'):
        class Message:
            ACTION_DO_INTERCEPT=1
            action=0
            def getMessageInfo(self): return self
            def getHttpService(self): return self
            def getHost(self): return host
            def getPort(self): return port
            def getRequest(self): return ('GET '+path+' HTTP/1.1\r\nX-Bober-Test-Run: '+tag+'\r\n\r\n').encode()
            def getMessageReference(self): return 17
            def getInterceptAction(self): return self.action
            def setInterceptAction(self,value): self.action=value
        return Message()
    def observer(self,role):
        result=self.Observer(); result.ROLE=role; result.registerExtenderCallbacks(self.callbacks)
        return result
    def test_before_after_pair_and_duplicate_hook(self):
        before,after=self.observer('before'),self.observer('after')
        message=self.message()
        for request in (True,False):
            message.action=0
            before.processProxyMessage(request,message)
            before.processProxyMessage(request,message)
            self.assertEqual(message.action,1)
            after.processProxyMessage(request,message)
            self.assertEqual(message.action,1)
        self.assertEqual(len(before.events),2); self.assertEqual(len(after.events),2)
        self.assertEqual(before.events[0]['reference'],after.events[0]['reference'])
        self.assertEqual(len(json.loads(Path(after.path).read_text())['events']),2)
    def test_other_target_path_or_tag_never_forces_intercept(self):
        observer=self.observer('before')
        for options in (dict(host='example.invalid'),dict(port=18765),dict(path='/echo?case=other'),dict(tag='foreign')):
            message=self.message(**options)
            observer.processProxyMessage(True,message)
            self.assertEqual(message.action,0)
        self.assertEqual(observer.events,[])
    def test_unload_prevents_late_interception(self):
        observer=self.observer('before'); observer.extensionUnloaded()
        message=self.message(); observer.processProxyMessage(True,message)
        self.assertEqual(message.action,0)
    def test_embedded_observers_mark_same_real_message(self):
        observer=self.Observer();observer.ROLE='before'
        observer.registerExtenderCallbacks(self.callbacks,register_proxy=False)
        data=json.loads(Path(observer.path).read_text())
        self.assertEqual(data['instrumentation'],'same-real-proxy-message')


if __name__=='__main__': unittest.main(verbosity=2)
