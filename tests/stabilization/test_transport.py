# -*- coding: utf-8 -*-
"""K01 invariants: API choice, delivery uncertainty, preflight, proxy actions."""
from __future__ import print_function

import unittest
import os

from source_harness import APIClass, Callbacks, Check, Field, Helpers, ROOT, Response, as_bytes, load_namespace
from test_source_logic import SourceCase


class SenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load_namespace()

    def send(self, callbacks, helpers=None):
        sender = self.ns['HttpRequestSender'](callbacks, helpers or Helpers())
        self.assertEqual(callbacks.calls, [], 'Capability discovery must not send a probe')
        return sender, sender.send('demo', 443, True, as_bytes('POST / HTTP/1.1\r\n\r\n'))

    def test_service_api_is_preferred_without_probe_request(self):
        callbacks = Callbacks(both=True)
        sender, result = self.send(callbacks)
        self.assertEqual(sender.api_kind, 'service')
        self.assertIsNone(result.error_code)
        self.assertEqual(result.response_bytes, callbacks.response)
        self.assertEqual([len(args) for args in callbacks.calls], [2])

    def test_legacy_raw_response_uses_one_four_argument_call(self):
        callbacks = Callbacks(legacy=True)
        sender, result = self.send(callbacks)
        self.assertEqual(sender.api_kind, 'legacy')
        self.assertEqual(result.response_bytes, callbacks.response)
        self.assertEqual([len(args) for args in callbacks.calls], [4])

    def test_send_exception_does_not_try_the_other_overload(self):
        class FailingCallbacks(Callbacks):
            def makeHttpRequest(self, *args):
                self.calls.append(args)
                raise IOError('Simulated error after server acceptance')
        callbacks = FailingCallbacks(both=True)
        _, result = self.send(callbacks)
        self.assertTrue(result.attempted)
        self.assertEqual(result.error_code, 'HTTP_SEND_FAILED')
        self.assertEqual(len(callbacks.calls), 1)

    def test_response_read_error_is_also_delivery_uncertainty(self):
        class BadResponse(object):
            def getResponse(self):
                raise ValueError('Response lookup failed')
        class BadCallbacks(Callbacks):
            def makeHttpRequest(self, *args):
                self.calls.append(args)
                return BadResponse()
        callbacks = BadCallbacks(both=True)
        _, result = self.send(callbacks)
        self.assertTrue(result.attempted)
        self.assertEqual(result.error_code, 'HTTP_SEND_FAILED')
        self.assertEqual(len(callbacks.calls), 1)

    def test_service_build_failure_does_not_claim_attempted_send(self):
        class BadHelpers(Helpers):
            def buildHttpService(self, *args):
                raise ValueError('Invalid service')
        callbacks = Callbacks()
        _, result = self.send(callbacks, BadHelpers())
        self.assertFalse(result.attempted)
        self.assertEqual(result.error_code, 'HTTP_SEND_FAILED')
        self.assertEqual(callbacks.calls, [])

    def test_unsupported_api_fails_before_any_send(self):
        callbacks = Callbacks()
        callbacks.getClass = lambda: APIClass([])
        _, result = self.send(callbacks)
        self.assertFalse(result.attempted)
        self.assertEqual(result.error_code, 'HTTP_API_UNAVAILABLE')
        self.assertEqual(callbacks.calls, [])

    def test_null_object_response_is_not_polled_or_retried(self):
        class NullCallbacks(Callbacks):
            def makeHttpRequest(self, *args):
                self.calls.append(args)
                return None
        callbacks = NullCallbacks()
        _, result = self.send(callbacks)
        self.assertTrue(result.attempted)
        self.assertEqual(result.error_code, 'HTTP_NO_RESPONSE')
        self.assertEqual(len(callbacks.calls), 1)

    def test_legacy_null_bytes_are_not_polled(self):
        callbacks = Callbacks(response=None, legacy=True)
        _, result = self.send(callbacks)
        self.assertTrue(result.attempted)
        self.assertEqual(result.error_code, 'HTTP_NO_RESPONSE')
        self.assertEqual(len(callbacks.calls), 1)

    def test_empty_response_is_not_success(self):
        _, result = self.send(Callbacks(response=as_bytes('')))
        self.assertEqual(result.error_code, 'HTTP_NO_RESPONSE')

    def test_wrong_response_type_is_an_explicit_error(self):
        _, result = self.send(Callbacks(response=object()))
        self.assertEqual(result.error_code, 'HTTP_INVALID_RESPONSE')


class WorkflowTests(SourceCase):
    def run_workflow(self):
        return self.ui.proxy_flow_process_request(
            as_bytes('GET /entry?q=ONE&w=TWO HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)

    def test_empty_checkpage_is_rejected_before_build_or_send(self):
        self.ui.useCheckPageTemplate = True
        self.ui.checkPageEditor.message = as_bytes('')
        builds = []
        self.ui.build_request_from_template = lambda **kw: builds.append(kw)
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_BEFORE_SEND)
        self.assertEqual(result.error_code, 'CP_TEMPLATE_EMPTY')
        self.assertEqual(builds, [])
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_malformed_checkpage_is_rejected_before_send(self):
        self.ui.useCheckPageTemplate = True
        self.ui.checkPageEditor.message = as_bytes('This is not an HTTP request')
        result = self.run_workflow()
        self.assertEqual(result.error_code, 'CP_TEMPLATE_INVALID')
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_missing_request_template_is_a_pre_send_error(self):
        self.ui.reqTemplateEditor.message = None
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_BEFORE_SEND)
        self.assertEqual(result.error_code, 'RT_TEMPLATE_EMPTY')

    def test_checkpage_build_failure_preserves_sent_state(self):
        self.ui.useCheckPageTemplate = True
        self.ui.build_checkpage_request = lambda **kw: None
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(result.error_code, 'CP_BUILD_FAILED')
        self.assertIsNone(result.request_bytes)
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_unexpected_checkpage_exception_preserves_sent_state(self):
        self.ui.useCheckPageTemplate = True
        def fail(**kwargs):
            raise ValueError('Controlled CheckPage error')
        self.ui.build_checkpage_request = fail
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(result.error_code, 'WORKFLOW_FAILED')
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_request_build_failure_does_not_send(self):
        self.ui.useCheckPageTemplate = True
        self.ui.build_request_from_template = lambda **kwargs: None
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_BEFORE_SEND)
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_no_response_stops_before_checkpage(self):
        self.ui.useCheckPageTemplate = True
        self.ui.callbacks = Callbacks(response=None)
        builds = []
        self.ui.build_checkpage_request = lambda **kw: builds.append(kw)
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(result.error_code, 'HTTP_NO_RESPONSE')
        self.assertEqual(builds, [])
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_checkpage_uses_the_preflight_template_snapshot(self):
        self.ui.useCheckPageTemplate = True
        outer_ui = self.ui
        class EditingCallbacks(Callbacks):
            def makeHttpRequest(self, *args):
                result = Callbacks.makeHttpRequest(self, *args)
                outer_ui.checkPageEditor.message = as_bytes('')
                return result
        self.ui.callbacks = EditingCallbacks()
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertTrue(result.request_bytes.startswith(as_bytes('POST /workflow/check ')))

    def test_preflight_does_not_add_a_custom_call(self):
        self.ui.useCheckPageTemplate = True
        self.ui.custom_codeblock_status = True
        calls = []
        def transform(p1, timeout, p2, csrf):
            calls.append((p1, p2, csrf))
            return True, (p1, p2, csrf), None
        self.ui.run_user_code = transform
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def configure_real_failure_fixture(self):
        path = os.path.join(ROOT, 'tests', 'stabilization', 'fixtures', 'custom-fail-on-checkpage.py')
        with open(path, 'rb') as handle:
            self.ui.customCodeArea = Field(handle.read().decode('utf-8'))
        self.ui.custom_codeblock_status = True
        self.ui.timeoutField = Field('2000')
        self.ui.autoUpdateCsrf = True
        self.ui.csrfRegexArea = Field(r'token="([^"]*)"')
        self.ui.autoFollowRTChk = Check(enabled=False)
        self.ui.callbacks = Callbacks(response=as_bytes('HTTP/1.1 200 OK\r\n\r\ntoken="FROM_ACTION"'))
        self.ui.useCheckPageTemplate = True

    def test_real_custom_failure_fixture_stops_after_one_rt(self):
        self.configure_real_failure_fixture()
        self.assertIsNone(self.ui.csrfManager.get_token())
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(result.error_code, 'CP_BUILD_FAILED')
        self.assertEqual(len(self.ui.callbacks.calls), 1)
        self.assertIsNone(result.request_bytes)

    def test_failure_fixture_with_cached_token_stops_before_any_rt(self):
        self.configure_real_failure_fixture()
        self.ui.csrfManager.set_token('OLD_TOKEN')
        result = self.run_workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_BEFORE_SEND)
        self.assertEqual(result.error_code, 'RT_BUILD_FAILED')
        self.assertEqual(self.ui.callbacks.calls, [])


class Service(object):
    def getHost(self):
        return 'demo'

    def getPort(self):
        return 80

    def getProtocol(self):
        return 'http'


class Message(object):
    def __init__(self):
        self.request = as_bytes('GET /entry?q=ONE HTTP/1.1\r\nHost: demo\r\n\r\n')
        self.replacements = []

    def getRequest(self):
        return self.request

    def getHttpService(self):
        return Service()

    def setRequest(self, request):
        self.replacements.append(request)
        self.request = request


class Intercepted(object):
    _next_reference = 0
    # Native IInterceptedProxyMessage values, verified by the K03 Burp probe.
    ACTION_DO_INTERCEPT = 1
    ACTION_DONT_INTERCEPT = 2
    ACTION_DROP = 3
    ACTION_FOLLOW_RULES = 0

    def __init__(self):
        Intercepted._next_reference += 1
        self.reference = Intercepted._next_reference
        self.message = Message()
        self.action = self.ACTION_FOLLOW_RULES

    def getMessageInfo(self):
        return self.message

    def getMessageReference(self):
        return self.reference

    def setInterceptAction(self, value):
        self.action = value

    def getInterceptAction(self):
        return self.action


class ProxyActionTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.extender = object.__new__(self.ns['BurpExtender'])
        self.extender.ui = self.ui
        self.extender.helpers = self.ui.helpers
        self.ui._proxy_mode_active = True
        self.intercepted = Intercepted()

    def test_ready_replaces_only_the_proxy_request(self):
        self.extender.processProxyMessage(True, self.intercepted)
        self.assertEqual(self.intercepted.action, Intercepted.ACTION_DONT_INTERCEPT)
        self.assertEqual(len(self.intercepted.message.replacements), 1)
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_pre_send_failure_forwards_original_with_diagnostic(self):
        self.ui.useCheckPageTemplate = True
        self.ui.checkPageEditor.message = as_bytes('')
        self.extender.processProxyMessage(True, self.intercepted)
        self.assertEqual(self.intercepted.action, Intercepted.ACTION_DONT_INTERCEPT)
        self.assertEqual(self.intercepted.message.replacements, [])
        self.assertEqual(self.ui.callbacks.calls, [])
        self.assertIn('CP_TEMPLATE_EMPTY', self.ui.customStatusArea.getText())

    def test_post_send_failure_drops_original_instead_of_forwarding_it(self):
        self.ui.useCheckPageTemplate = True
        self.ui.build_checkpage_request = lambda **kw: None
        self.extender.processProxyMessage(True, self.intercepted)
        self.assertEqual(self.intercepted.action, Intercepted.ACTION_DROP)
        self.assertEqual(self.intercepted.message.replacements, [])
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_replace_failure_after_internal_send_also_drops(self):
        self.ui.useCheckPageTemplate = True
        def fail(request):
            raise ValueError('Cannot replace request')
        self.intercepted.message.setRequest = fail
        self.extender.processProxyMessage(True, self.intercepted)
        self.assertEqual(self.intercepted.action, Intercepted.ACTION_DROP)
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_unclassified_workflow_failure_does_not_risk_another_operation(self):
        def fail(*args):
            raise RuntimeError('Unknown send state')
        self.ui.proxy_flow_process_request = fail
        self.extender.processProxyMessage(True, self.intercepted)
        self.assertEqual(self.intercepted.action, Intercepted.ACTION_DROP)

    def test_diagnostic_failure_cannot_undo_post_send_drop(self):
        self.ui.useCheckPageTemplate = True
        self.ui.build_checkpage_request = lambda **kw: None
        def fail(result):
            raise RuntimeError('Diagnostic unavailable')
        self.extender._report_workflow_error = fail
        self.extender.processProxyMessage(True, self.intercepted)
        self.assertEqual(self.intercepted.action, Intercepted.ACTION_DROP)
        self.assertEqual(len(self.ui.callbacks.calls), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
