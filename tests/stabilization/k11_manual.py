# -*- coding: utf-8 -*-
"""Fixed before/after observers for one manual request/response intercept.

Only GET /echo?case=k11-manual, k11-manual-* tag, loopback port18790.
Load Before, then the root extension, then After. No automatic requests.
"""
from burp import IBurpExtender, IProxyListener, IExtensionStateListener
from java.lang import Throwable
import hashlib
import json
import os
import threading


class ManualObserver(IBurpExtender, IProxyListener, IExtensionStateListener):
    ROLE = None
    def registerExtenderCallbacks(self, callbacks, register_proxy=True):
        self.callbacks, self.helpers, self.closed = callbacks, callbacks.getHelpers(), False
        self.events, self.seen, self.lock = [],set(),threading.Lock()
        self.instrumentation = 'separate-legacy-listener' if register_proxy else 'same-real-proxy-message'
        directory=os.path.dirname(unicode(callbacks.getExtensionFilename()))
        self.path=os.path.join(directory,'runtime','k11-manual-'+self.ROLE+'.json')
        root=os.path.dirname(os.path.dirname(directory))
        with open(os.path.join(root,'BoberProxy.py'),'rb') as handle:
            self.source_hash=hashlib.sha256(handle.read()).hexdigest()
        callbacks.setExtensionName('BoberProxy K11 manual '+self.ROLE)
        callbacks.registerExtensionStateListener(self)
        if register_proxy: callbacks.registerProxyListener(self)
        self.save()
        callbacks.printOutput('K11_MANUAL_'+self.ROLE.upper()+' READY (one tagged loopback request/response only)')

    def save(self):
        with open(self.path,'w') as handle:
            json.dump(dict(role=self.ROLE,source_sha256=self.source_hash,instrumentation=self.instrumentation,events=self.events),handle,indent=2)

    def processProxyMessage(self, request, intercepted):
        if self.closed: return
        try:
            info=intercepted.getMessageInfo()
            if info is None: return
            service=info.getHttpService()
            if service is None or service.getHost()!='127.0.0.1' or service.getPort()!=18790: return
            raw=info.getRequest()
            if raw is None: return
            text=unicode(self.helpers.bytesToString(raw))
            lines=text.split('\r\n')
            target=lines[0].split(' ')[1]
            prefix='http://127.0.0.1:18790'
            if target.startswith(prefix): target=target[len(prefix):]
            if target!='/echo?case=k11-manual': return
            tags=[line.split(':',1)[1].strip() for line in lines[1:] if line.lower().startswith('x-bober-test-run:')]
            if len(tags)!=1 or not tags[0].startswith('k11-manual-'): return
            key=(int(intercepted.getMessageReference()),bool(request))
            with self.lock:
                if key in self.seen: return
                self.seen.add(key)
                before=int(intercepted.getInterceptAction())
                if self.ROLE=='before': intercepted.setInterceptAction(intercepted.ACTION_DO_INTERCEPT)
                self.events.append(dict(run=tags[0],reference=key[0],request=key[1],before=before,after=int(intercepted.getInterceptAction())))
                self.events=self.events[-16:]
                self.save()
        except (BaseException,Throwable):
            import traceback
            self.callbacks.printError(traceback.format_exc())

    def extensionUnloaded(self): self.closed=True
