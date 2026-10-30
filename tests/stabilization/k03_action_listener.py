# -*- coding: utf-8 -*-
"""Temporary before/after listeners, restricted to tagged loopback test traffic."""
import json
import os
import threading

from burp import IProxyListener
from java.lang import System, Exception as JavaException


CASES = set(['request-drop', 'response-drop', 'follow-rules', 'dont-intercept',
             'manual-both', 'active-ready'])


class ActionListener(IProxyListener):
    def __init__(self, callbacks, role, directory):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.role = role
        self.path = os.path.join(directory, 'runtime', 'k03-actions.jsonl')
        self.lock = threading.Lock()

    def processProxyMessage(self, messageIsRequest, intercepted):
        try:
            info = intercepted.getMessageInfo()
            service = info.getHttpService()
            if str(service.getHost()) not in ('127.0.0.1', 'localhost', '::1') or int(service.getPort()) not in (18766, 18767, 18768):
                return
            text = self.helpers.bytesToString(info.getRequest())
            case = None
            for line in text.split('\r\n\r\n', 1)[0].split('\r\n')[1:]:
                if line.lower().startswith('x-bober-k03-probe:'):
                    case = str(line.split(':', 1)[1].strip())
                    break
            if case not in CASES:
                return
            before = int(intercepted.getInterceptAction())
            if self.role == 'before':
                if messageIsRequest and case in ('request-drop', 'active-ready') or not messageIsRequest and case == 'response-drop':
                    intercepted.setInterceptAction(intercepted.ACTION_DROP)
                elif case == 'dont-intercept' and messageIsRequest:
                    intercepted.setInterceptAction(intercepted.ACTION_DONT_INTERCEPT)
                elif case == 'follow-rules' and messageIsRequest:
                    intercepted.setInterceptAction(intercepted.ACTION_FOLLOW_RULES)
                elif case == 'manual-both' and not messageIsRequest:
                    intercepted.setInterceptAction(intercepted.ACTION_DO_INTERCEPT)
            record = dict(role=self.role, case=case, request=bool(messageIsRequest),
                          reference=int(intercepted.getMessageReference()), before=before,
                          after=int(intercepted.getInterceptAction()),
                          first_line=str(text.split('\r\n', 1)[0]), monotonic_ns=System.nanoTime())
            with self.lock:
                with open(self.path, 'ab') as handle:
                    handle.write((json.dumps(record, ensure_ascii=True) + '\n').encode('ascii'))
        except (Exception, JavaException):
            import traceback
            self.callbacks.printError('K03 action probe error\n' + traceback.format_exc())


def install(callbacks, role):
    directory = os.path.dirname(str(callbacks.getExtensionFilename()))
    callbacks.setExtensionName('BoberProxy K03 ' + ('Before guard' if role == 'before' else 'After observer'))
    listener = ActionListener(callbacks, role, directory)
    callbacks.registerProxyListener(listener)
    callbacks.printOutput('K03_%s READY (tagged loopback ports 18766-18768 only)' % role.upper())
    return listener
