# -*- coding: utf-8 -*-
"""Actual SI00 wire observer entry; requests only after a scoped command."""
from burp import IBurpExtender, IExtensionStateListener
from java.lang import Throwable
import os
import sys
import threading
import uuid


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._closed, self._installed, self._probe = False, [], None
        self._callbacks = callbacks
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        from si00_wire import WireProbe, load_config
        runtime = os.path.join(directory, 'runtime')
        config = load_config(os.path.join(runtime, 'si00-wire-config.json'))
        callbacks.setExtensionName('BoberProxy SI00 wire observation')
        callbacks.registerExtensionStateListener(self)
        if self._closed: return
        probe = WireProbe(callbacks, runtime, uuid.uuid4().hex, config)
        self._probe = probe
        if probe.jar(): raise ValueError('SI00 cookie namespace is not empty; inspect the prior own-test manifest')
        try:
            for action in probe.actions:
                callbacks.registerSessionHandlingAction(action)
                self._installed.append(('action', action))
                if self._closed:
                    self.extensionUnloaded()
                    return
            for kind, register in [('http', callbacks.registerHttpListener), ('proxy', callbacks.registerProxyListener)]:
                register(probe)
                self._installed.append((kind, probe))
                if self._closed:
                    self.extensionUnloaded()
                    return
            self._thread = threading.Thread(target=self._run, name='BoberProxy.SI00.wire-observer')
            self._thread.setDaemon(True)
            self._thread.start()
        except (BaseException, Throwable):
            self.extensionUnloaded()
            raise

    def _run(self):
        try: self._probe.run()
        except (BaseException, Throwable) as error:
            self._callbacks.printError('SI00_WIRE_WORKER_FAILED (' + type(error).__name__ + ')')

    def extensionUnloaded(self):
        self._closed = True
        if self._probe is not None: self._probe.closed = True
        errors = []
        for kind, item in reversed(self._installed):
            try:
                if kind == 'action': self._callbacks.removeSessionHandlingAction(item)
                elif kind == 'http': self._callbacks.removeHttpListener(item)
                else: self._callbacks.removeProxyListener(item)
            except (BaseException, Throwable) as error: errors.append(type(error).__name__)
        self._installed[:] = []
        if errors: self._callbacks.printError('SI00_WIRE_HANDLER_WITHDRAW_FAILED: ' + ','.join(errors))
