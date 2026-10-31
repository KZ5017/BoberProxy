# -*- coding: utf-8 -*-
"""Finite private persisted-message API characterization; no network/main UI edits."""
from burp import IBurpExtender, IExtensionStateListener, IHttpRequestResponse
from java.lang import System, Throwable
from java.net import URL
import hashlib
import json
import os
import threading
import traceback


class SyntheticMessage(IHttpRequestResponse):
    def __init__(self, helpers, request, response):
        # Public JavaBean names (request, response, comment...) dispatch setters
        # in Jython. Private backing names must never alias those properties.
        self._probe_service = helpers.buildHttpService('127.0.0.1', 18765, False)
        self._probe_request, self._probe_response = request, response
        self._probe_comment, self._probe_highlight = 'K089 synthetic only', 'blue'
    def getHttpService(self): return self._probe_service
    def setHttpService(self, value): self._probe_service = value
    def getRequest(self): return self._probe_request
    def setRequest(self, value): self._probe_request = value
    def getResponse(self): return self._probe_response
    def setResponse(self, value): self._probe_response = value
    def getComment(self): return self._probe_comment
    def setComment(self, value): self._probe_comment = value
    def getHighlight(self): return self._probe_highlight
    def setHighlight(self, value): self._probe_highlight = value
    def getHost(self): return self._probe_service.getHost()
    def getPort(self): return self._probe_service.getPort()
    def getProtocol(self): return self._probe_service.getProtocol()
    def getUrl(self): return URL('http://127.0.0.1:18765/k089/storage-probe')
    def getStatusCode(self): return 200
    def setHost(self, value): raise NotImplementedError()
    def setPort(self, value): raise NotImplementedError()
    def setProtocol(self, value): raise NotImplementedError()


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.closed = False
        self.callbacks = callbacks
        callbacks.setExtensionName('BoberProxy K08-K09 storage API inspection')
        callbacks.registerExtensionStateListener(self)
        self.thread = threading.Thread(target=self.verify, name='BoberProxy.K089.storage-inspection')
        self.thread.setDaemon(True)
        self.thread.start()

    def verify(self):
        checks, observations, errors, owned = {}, {}, [], []
        callbacks = self.callbacks
        helpers = callbacks.getHelpers()
        def digest(data):
            if data is None:
                return None
            return hashlib.sha256(helpers.bytesToString(data).encode('latin-1')).hexdigest()
        def after_delete(message, method):
            try:
                value = getattr(message, method)()
                return dict(outcome='returned', length=len(value) if value is not None else None,
                            sha256=digest(value))
            except (Exception, Throwable) as error:
                return dict(outcome='raised', error_type=type(error).__name__)
        try:
            body = ''.join(chr(n) for n in range(256)) * 4096
            request = helpers.stringToBytes('POST /k089/storage-probe HTTP/1.1\r\nHost: 127.0.0.1:18765\r\nContent-Length: 256\r\n\r\n' + body[:256])
            response = helpers.stringToBytes('HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(body) + body)
            original = SyntheticMessage(helpers, request, response)
            persisted = callbacks.saveBuffersToTempFiles(original)
            owned.append(persisted)
            checks['persisted_created'] = persisted is not None
            observations['persisted_class'] = str(persisted.getClass().getName())
            observations['public_methods'] = sorted(set(str(m.getName()) for m in persisted.getClass().getMethods()))
            checks['request_exact_binary'] = digest(persisted.getRequest()) == digest(request)
            checks['response_exact_one_mib_binary'] = digest(persisted.getResponse()) == digest(response)
            checks['service_preserved'] = (persisted.getHttpService().getHost() == '127.0.0.1'
                                          and persisted.getHttpService().getPort() == 18765)
            checks['annotations_preserved'] = (persisted.getComment() == original.getComment()
                                               and persisted.getHighlight() == original.getHighlight())
            first, second = persisted.getResponse(), persisted.getResponse()
            observations['repeat_read_same_array_identity'] = System.identityHashCode(first) == System.identityHashCode(second)
            original.setRequest(helpers.stringToBytes('changed original'))
            original.setResponse(None)
            checks['independent_of_original_mutation'] = (digest(persisted.getRequest()) == digest(request)
                                                         and digest(persisted.getResponse()) == digest(response))
            other = callbacks.saveBuffersToTempFiles(SyntheticMessage(helpers, request, response))
            owned.append(other)
            checks['delete_api_available'] = hasattr(persisted, 'deleteTempFiles')
            persisted.deleteTempFiles()
            checks['explicit_delete_returns'] = True
            observations['request_after_delete'] = after_delete(persisted, 'getRequest')
            observations['response_after_delete'] = after_delete(persisted, 'getResponse')
            checks['other_message_survives_delete'] = digest(other.getResponse()) == digest(response)
            try:
                persisted.deleteTempFiles()
                observations['repeat_delete'] = 'returned'
            except (Exception, Throwable) as error:
                observations['repeat_delete'] = type(error).__name__
            first = second = original = request = response = body = None
        except (Exception, Throwable):
            errors.append(traceback.format_exc())
        finally:
            for message in owned:
                try:
                    message.deleteTempFiles()
                except (Exception, Throwable):
                    errors.append('Owned-message cleanup failed: ' + traceback.format_exc())
        report = dict(kind='K08-K09-real-Burp-private-persisted-message-characterization',
                      checks=checks, observations=observations, errors=errors,
                      passed=bool(checks) and all(checks.values()) and not errors,
                      burp_version=list(callbacks.getBurpVersion()), python_java_version=str(System.getProperty('java.version')),
                      network_requests=0, main_extension_settings_changed=False,
                      claim='Read/mutation/delete API behavior only; no deterministic JVM GC or total heap bound claim.')
        directory = os.path.join(os.path.dirname(str(callbacks.getExtensionFilename())), 'runtime')
        if not os.path.isdir(directory):
            os.makedirs(directory)
        path = os.path.join(directory, 'k089-burp-storage-inspection.json')
        with open(path, 'w') as handle:
            json.dump(report, handle, indent=2)
        if not self.closed:
            callbacks.printOutput('K089_STORAGE %s (%d checks)\n%s' % (
                'PASS' if report['passed'] else 'FAIL', len(checks), path))
            if errors:
                callbacks.printError('\n'.join(errors))

    def extensionUnloaded(self):
        self.closed = True
