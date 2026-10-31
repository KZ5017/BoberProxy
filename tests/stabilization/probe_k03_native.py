# -*- coding: utf-8 -*-
"""Native K03 helper/interface checks; real bounded HTTP only with callbacks.

The in-Burp probe uses two finite 200 ms loopback delays and a 100 ms test
budget in a separate source namespace. Production's 30000 ms budget is never
modified. No external host receives a test request.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys
import traceback
import uuid

from burp import IInterceptedProxyMessage, IHttpRequestResponse, IHttpService
from source_harness import (ROOT, Callbacks, Check, Editor, Field, Helpers,
                            CapturedOutput, as_text, new_ui)
from probe_template_native import load_source


def run_checks(callbacks=None):
    helpers = callbacks.getHelpers() if callbacks is not None else Helpers()
    namespace, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    checks, errors, details = {}, [], []
    wire = helpers.stringToBytes
    actual_helpers = callbacks is not None

    def check(name, operation):
        try:
            checks[name] = bool(operation())
        except BaseException:
            checks[name] = False
            errors.append(name + '\n' + traceback.format_exc())

    with CapturedOutput():
        ui = new_ui(namespace)
        ui.helpers = helpers
        ui.callbacks = callbacks if callbacks is not None else Callbacks()
        ui.autoUpdateCookies = True
        ui.autoUpdateCsrf = True
        ui.csrfRegexArea = Field(r'token="([^"]*)"')
        replies = [wire('HTTP/1.1 200 OK\r\nSet-Cookie: sid=LAST\r\n\r\ntoken="LAST"')]
        sends, updates = [], []
        original_update = ui._update_cookies_and_csrf
        def update(value):
            updates.append(value)
            original_update(value)
        ui._update_cookies_and_csrf = update
        def send(host, port, https, request):
            sends.append((host, port, https, request))
            return namespace['HttpSendResult'](attempted=True, response_bytes=replies.pop(0))
        ui._send_http_request = send
        first = wire('HTTP/1.1 302 Found\r\nLocation: next?raw=%252F+%2B#part\r\nSet-Cookie: sid=FIRST\r\n\r\ntoken="FIRST"')
        request = wire('POST /a/start HTTP/1.1\r\nHost: ignored.invalid:9\r\nUser-Agent: K03-Native\r\nAuthorization: SYNTHETIC\r\n\r\nBODY')
        followed = ui._follow_redirects_chain(request, first, 'demo', 8443, True)
        check('real_helper_redirect_result', lambda: followed.error_code is None and followed.hops == 1)
        check('service_directory_port_and_raw_query', lambda: len(sends) == 1 and sends[0][:3] == ('demo', 8443, True)
              and as_text(sends[0][3]).startswith('GET /a/next?raw=%252F+%2B HTTP/1.1\r\nHost: demo:8443\r\n'))
        check('each_response_updates_once_including_last', lambda: len(updates) == 2 and ui.csrfManager.get_token() == 'LAST'
              and ui.cookieManager.jar.get('sid') == 'LAST')
        check('minimal_get_headers_and_cookie', lambda: 'User-Agent: K03-Native' in as_text(sends[0][3])
              and 'sid=FIRST' in as_text(sends[0][3]) and 'Authorization:' not in as_text(sends[0][3])
              and as_text(sends[0][3]).split('\r\n\r\n', 1)[1] == '')
        check('ipv6_native_header', lambda: as_text(helpers.buildHttpMessage(
            ['GET / HTTP/1.1', 'Host: ' + namespace['_redirect_host_header']('::1', 8443, True)], wire('')))
              .startswith('GET / HTTP/1.1\r\nHost: [::1]:8443\r\n'))
        try:
            namespace['_redirect_destination']('http://demo:8080/a', 'http://other:65536/x')
            checks['jython_invalid_explicit_port_rejected'] = False
        except ValueError:
            checks['jython_invalid_explicit_port_rejected'] = True

        class NativeService(IHttpService):
            def getHost(self):
                return 'demo'
            def getPort(self):
                return 80
            def getProtocol(self):
                return 'http'

        class NativeMessage(IHttpRequestResponse):
            def __init__(self):
                self._raw_request = wire('GET /unmatched HTTP/1.1\r\nHost: demo\r\n\r\n')
            def getRequest(self):
                return self._raw_request
            def getResponse(self):
                return wire('HTTP/1.1 200 OK\r\n\r\n')
            def getHttpService(self):
                return NativeService()
            def setRequest(self, value):
                self._raw_request = value

        class NativeIntercepted(IInterceptedProxyMessage):
            def __init__(self, action):
                self._action = action
                self._message = NativeMessage()
            def getMessageInfo(self):
                return self._message
            def getInterceptAction(self):
                return self._action
            def setInterceptAction(self, action):
                self._action = action

        extender = object.__new__(namespace['BurpExtender'])
        extender.ui, extender.helpers = ui, helpers
        action_matrix = []
        ui._update_cookies_and_csrf = lambda value: None
        for proxy_on in (False, True):
            ui._proxy_mode_active = proxy_on
            for is_request in (False, True):
                for action in (IInterceptedProxyMessage.ACTION_DO_INTERCEPT,
                               IInterceptedProxyMessage.ACTION_DONT_INTERCEPT,
                               IInterceptedProxyMessage.ACTION_DROP,
                               IInterceptedProxyMessage.ACTION_FOLLOW_RULES):
                    message = NativeIntercepted(action)
                    extender.processProxyMessage(is_request, message)
                    action_matrix.append(message.getInterceptAction() == action)
        check('real_interface_prior_action_matrix', lambda: len(action_matrix) == 16 and all(action_matrix)
              and ui._workflow_counter == 4)
        from java.io import IOException
        def java_failure(value):
            raise IOException('Synthetic native state update failure')
        ui._update_cookies_and_csrf = java_failure
        message = NativeIntercepted(IInterceptedProxyMessage.ACTION_DO_INTERCEPT)
        extender.processProxyMessage(False, message)
        check('java_exception_cannot_change_passive_action', lambda: message.getInterceptAction() == IInterceptedProxyMessage.ACTION_DO_INTERCEPT)

        if callbacks is not None:
            budget = namespace['WORKFLOW_TIMEOUT_MS']
            try:
                namespace['WORKFLOW_TIMEOUT_MS'] = 100
                for case, expected_count in (('slow-rt', 1), ('slow-hop', 2)):
                    run = 'k03-budget-' + uuid.uuid4().hex[:12]
                    live = new_ui(namespace)
                    live.helpers, live.callbacks = helpers, callbacks
                    live._http_sender = namespace['HttpRequestSender'](callbacks, helpers)
                    live.useCheckPageTemplate = True
                    live.autoFollowRTChk = Check(selected=True)
                    live.autoUpdateCsrf = True
                    live.csrfRegexArea = Field(r'value="([^"]*)"')
                    # Field doubles have no K04 Swing document notifications.
                    if hasattr(live, '_on_csrf_regex_changed'):
                        live._on_csrf_regex_changed()
                    live.reqTemplateEditor = Editor(wire('POST /k03/a/start?case=p4yl04dm4rk3r HTTP/1.1\r\n'
                        'Host: 127.0.0.1:18766\r\nX-Bober-Test-Run: ' + run + '\r\nContent-Length: 0\r\n\r\n'))
                    live.checkPageEditor = Editor(wire('POST /k03/check HTTP/1.1\r\nHost: 127.0.0.1:18766\r\n\r\n'))
                    began = namespace['_monotonic_ms']()
                    result = live.proxy_flow_process_request(wire('GET /entry?q=' + case + ' HTTP/1.1\r\n\r\n'),
                                                              '127.0.0.1', 18766, False)
                    elapsed = namespace['_monotonic_ms']() - began
                    control = callbacks.makeHttpRequest(helpers.buildHttpService('127.0.0.1', 18766, 'http'),
                        wire('GET /__control/events?run=' + run + ' HTTP/1.1\r\nHost: 127.0.0.1:18766\r\nConnection: close\r\n\r\n'))
                    observed = json.loads(as_text(control.getResponse()).split('\r\n\r\n', 1)[1])
                    check('blocking_api_' + case, lambda: result.status == namespace['ProxyWorkflowResult'].ERROR_AFTER_SEND
                          and result.error_code == 'WORKFLOW_TIMEOUT' and elapsed >= 100
                          and observed['action_count'] == 1 and observed['event_count'] == expected_count
                          and all(e['target'] != '/k03/check' for e in observed['recent_events']))
                    details.append(dict(scenario=case, test_budget_ms=100, production_budget_ms=budget,
                                        elapsed_ms=elapsed, status=result.status, error_code=result.error_code,
                                        observed=observed, cached_token=live.csrfManager.get_token()))
            finally:
                namespace['WORKFLOW_TIMEOUT_MS'] = budget

    return dict(kind='in-burp-native-helpers-and-bounded-loopback-api' if actual_helpers else 'standalone-native-interfaces-helper-doubles',
                source_sha256=hashlib.sha256(raw).hexdigest(), passed=bool(checks) and all(checks.values()),
                checks=checks, errors=errors, deadline_cases=details, actual_burp_helpers=actual_helpers,
                action_constants=dict(follow_rules=int(IInterceptedProxyMessage.ACTION_FOLLOW_RULES),
                                      dont_intercept=int(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT),
                                      do_intercept=int(IInterceptedProxyMessage.ACTION_DO_INTERCEPT),
                                      drop=int(IInterceptedProxyMessage.ACTION_DROP)),
                synthetic_proxy_messages=True, production_budget_ms=namespace['WORKFLOW_TIMEOUT_MS'],
                note='The 100 ms budget belongs only to an isolated probe namespace; blocking calls are observed, never claimed interrupted.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    result = run_checks()
    with open(args.report, 'w') as handle:
        handle.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
