# -*- coding: utf-8 -*-
"""K03 scheduling, redirect destinations, state updates and Proxy decisions."""
from __future__ import print_function

import unittest

from source_harness import Callbacks, Check, Response, as_bytes, as_text
from test_source_logic import SourceCase
from test_transport import Intercepted, Message


def response(status=302, location='next', token=''):
    return as_bytes('HTTP/1.1 %d Fixture\r\n' % status +
                    ('Location: ' + location + '\r\n' if location is not None else '') +
                    '\r\n' + token)


class SequenceCallbacks(Callbacks):
    def __init__(self, responses, on_send=None):
        Callbacks.__init__(self)
        self.responses = list(responses)
        self.on_send = on_send

    def makeHttpRequest(self, *args):
        if not self.responses:
            raise AssertionError('Unexpected additional HTTP send')
        self.response = self.responses.pop(0)
        if self.on_send:
            self.on_send(len(self.calls))
        return Callbacks.makeHttpRequest(self, *args)


class RedirectTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.original_clock = self.ns['_monotonic_ms']
        self.original_budget = self.ns['WORKFLOW_TIMEOUT_MS']

    def tearDown(self):
        self.ns['_monotonic_ms'] = self.original_clock
        self.ns['WORKFLOW_TIMEOUT_MS'] = self.original_budget
        SourceCase.tearDown(self)

    def follow(self, location='next', max_redirects=10, initial_method='POST', **kwargs):
        return self.ui._follow_redirects_chain(
            as_bytes(initial_method + ' /a/start?x=1 HTTP/1.1\r\nHost: unrelated.invalid:9\r\n'
                     'User-Agent: K03-UA\r\nAuthorization: Bearer SYNTHETIC\r\nCookie: template=old\r\n'
                     'Content-Type: application/x-www-form-urlencoded\r\n\r\nORIGINAL_BODY'),
            response(location=location, token='INITIAL'), 'demo', 8443, True,
            max_redirects=max_redirects, **kwargs)

    def workflow_request(self):
        return self.ui.proxy_flow_process_request(
            as_bytes('GET /entry?q=ONE&w=TWO HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 8443, True)

    def fake_clock(self, budget=50):
        now = [0]
        self.ns['_monotonic_ms'] = lambda: now[0]
        self.ns['WORKFLOW_TIMEOUT_MS'] = budget
        return now

    def test_relative_destinations_use_service_path_query_and_port(self):
        base, method = self.ns['_redirect_base'](
            'POST /a/start?x=1 HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n', 'demo', 8443, True)
        self.assertEqual(base, 'https://demo:8443/a/start?x=1')
        self.assertEqual(method, 'POST')
        cases = [('next', ('demo', 8443, True, '/a/next')),
                 ('../next', ('demo', 8443, True, '/next')),
                 ('/next', ('demo', 8443, True, '/next')),
                 ('?q=2', ('demo', 8443, True, '/a/start?q=2')),
                 ('?', ('demo', 8443, True, '/a/start')),
                 ('//other:9443/x', ('other', 9443, True, '/x')),
                 ('http://other/x', ('other', 80, False, '/x')),
                 ('https://other:443/x#part', ('other', 443, True, '/x')),
                 ('#part', ('demo', 8443, True, '/a/start?x=1')),
                 ('next;p=1?x=%252F+%2B#fragment', ('demo', 8443, True, '/a/next;p=1?x=%252F+%2B'))]
        for location, expected in cases:
            self.assertEqual(self.ns['_redirect_destination'](base, location), expected, location)

    def test_absolute_request_target_cannot_change_service_origin(self):
        base, _ = self.ns['_redirect_base'](
            'GET http://unrelated.invalid:9/a/start?x=1 HTTP/1.1\r\n\r\n', 'demo', 8443, True)
        self.assertEqual(base, 'https://demo:8443/a/start?x=1')

    def test_ipv6_authority_and_nondefault_port_are_preserved(self):
        base, _ = self.ns['_redirect_base']('GET /a/start HTTP/1.1\r\n\r\n', '2001:db8::1', 8443, True)
        self.assertEqual(base, 'https://[2001:db8::1]:8443/a/start')
        self.assertEqual(self.ns['_redirect_destination'](base, '../next#part'),
                         ('2001:db8::1', 8443, True, '/next'))
        self.assertEqual(self.ns['_redirect_host_header']('::1', 80, False), '[::1]')

    def test_invalid_locations_fail_without_guessing_a_destination(self):
        invalid = ['ftp://other/x', 'javascript:alert(1)', 'http:///x', '//',
                   'https://user:pass@other/x', 'http://other:bad/x', 'http://other:0/x',
                   'http://other:65536/x', 'http://other:/x', 'http://[broken/x',
                   'next path', 'http://other\\evil/x', '://broken']
        for location in invalid:
            self.ui.callbacks = Callbacks(response=response(200, None))
            self.ui._http_sender = None
            result = self.follow(location)
            self.assertEqual(result.error_code, 'REDIRECT_INVALID_LOCATION', location)
            self.assertEqual(self.ui.callbacks.calls, [], location)

    def test_control_characters_are_not_accepted_inside_a_location_value(self):
        for location in ('next\r\nX: injected', 'next\x00part', 'next\tpart', 'next\x7fpart'):
            with self.assertRaises(ValueError):
                self.ns['_redirect_destination']('https://demo:8443/a/start', location)

    def test_minimal_get_preserves_only_user_agent_and_managed_cookies(self):
        self.ui.autoUpdateCookies = True
        self.ui.cookieManager.jar['sid'] = 'SYNTHETIC'
        self.ui.callbacks = Callbacks(response=response(200, None))
        result = self.follow('http://other:8080/next#fragment')
        self.assertIsNone(result.error_code)
        service, request = self.ui.callbacks.calls[0]
        self.assertEqual(service, ('other', 8080, 'http'))
        text = as_text(request)
        self.assertTrue(text.startswith('GET /next HTTP/1.1\r\nHost: other:8080\r\n'))
        self.assertIn('User-Agent: K03-UA', text)
        self.assertIn('Cookie: sid=SYNTHETIC', text)
        self.assertNotIn('Authorization:', text)
        self.assertNotIn('template=old', text)
        self.assertNotIn('Content-Type:', text)
        self.assertNotIn('ORIGINAL_BODY', text)
        self.assertEqual(text.split('\r\n\r\n', 1)[1], '')

    def test_all_existing_3xx_statuses_keep_get_policy(self):
        for status in (301, 302, 303, 307, 308):
            self.ui.callbacks = Callbacks(response=response(200, None))
            self.ui._http_sender = None
            result = self.ui._follow_redirects_chain(as_bytes('POST /start HTTP/1.1\r\n\r\nBODY'),
                                                     response(status, '/next'), 'demo', 80, False)
            self.assertIsNone(result.error_code)
            self.assertTrue(self.ui.callbacks.calls[0][1].startswith(as_bytes('GET /next ')))

    def test_no_redirect_updates_initial_response_once(self):
        updates = []
        self.ui._update_cookies_and_csrf = updates.append
        initial = response(200, None)
        result = self.ui._follow_redirects_chain(as_bytes('GET / HTTP/1.1\r\n\r\n'), initial, 'demo', 80, False)
        self.assertEqual(result.response_bytes, initial)
        self.assertEqual(updates, [initial])
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_ten_hops_update_all_eleven_responses_once(self):
        replies = [response(302, '?hop=%d' % (i + 1), str(i)) for i in range(1, 10)] + [response(200, None, 'LAST')]
        self.ui.callbacks = SequenceCallbacks(replies)
        updates = []
        self.ui._update_cookies_and_csrf = updates.append
        result = self.follow('?hop=1')
        self.assertIsNone(result.error_code)
        self.assertEqual(result.hops, 10)
        self.assertEqual(len(self.ui.callbacks.calls), 10)
        self.assertEqual(updates, [response(location='?hop=1', token='INITIAL')] + replies)

    def test_eleven_hops_stop_at_ten_after_updating_last_response(self):
        replies = [response(302, '?hop=%d' % (i + 1), str(i)) for i in range(1, 11)]
        self.ui.callbacks = SequenceCallbacks(replies)
        updates = []
        self.ui._update_cookies_and_csrf = updates.append
        result = self.follow('?hop=1')
        self.assertEqual(result.error_code, 'REDIRECT_LIMIT')
        self.assertEqual(result.hops, 10)
        self.assertEqual(len(updates), 11)
        self.assertEqual(updates[-1], replies[-1])

    def test_zero_hops_still_update_initial_response(self):
        updates = []
        self.ui._update_cookies_and_csrf = updates.append
        result = self.follow(max_redirects=0)
        self.assertEqual(result.error_code, 'REDIRECT_LIMIT')
        self.assertEqual(len(updates), 1)
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_get_self_loop_is_detected_before_another_send(self):
        result = self.follow('?x=1', initial_method='GET')
        self.assertEqual(result.error_code, 'REDIRECT_LOOP')
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_post_to_get_same_url_is_allowed_once_then_loop_is_detected(self):
        self.ui.callbacks = Callbacks(response=response(302, '?x=1'))
        result = self.follow('?x=1')
        self.assertEqual(result.error_code, 'REDIRECT_LOOP')
        self.assertEqual(result.hops, 1)
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_redirect_send_failure_has_no_retry_or_checkpage_fallback(self):
        class Failing(Callbacks):
            def makeHttpRequest(self, *args):
                self.calls.append(args)
                raise IOError('Controlled redirect send failure')
        self.ui.callbacks = Failing(both=True)
        result = self.follow()
        self.assertEqual(result.error_code, 'HTTP_SEND_FAILED')
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_selection_is_required_and_captured_before_rt_send(self):
        for selected, enabled, changed in ((False, True, True), (True, True, False), (True, False, True)):
            self.ui.useCheckPageTemplate = True
            self.ui.autoFollowRTChk = Check(selected=selected, enabled=enabled)
            self.ui._http_sender = None
            self.ui.callbacks = SequenceCallbacks([response(302, '/next')],
                on_send=lambda n: setattr(self.ui.autoFollowRTChk, 'selected', changed))
            follows = []
            updates = []
            self.ui._update_cookies_and_csrf = updates.append
            def follow(*args, **kwargs):
                follows.append(kwargs)
                return self.ns['RedirectResult'](args[1])
            self.ui._follow_redirects_chain = follow
            result = self.workflow_request()
            self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
            self.assertEqual(len(follows), 1 if selected and enabled else 0)
            self.assertEqual(len(updates), 0 if selected and enabled else 1)

    def test_no_checkpage_means_no_internal_send_or_redirect(self):
        self.ui.autoFollowRTChk = Check(selected=True)
        result = self.workflow_request()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_shared_deadline_includes_rt_and_multiple_redirects(self):
        now = self.fake_clock()
        self.ui.useCheckPageTemplate = True
        self.ui.autoFollowRTChk = Check(selected=True)
        self.ui.callbacks = SequenceCallbacks([response(302, '/one'), response(302, '/two'), response(302, '/three')],
                                              on_send=lambda n: now.__setitem__(0, now[0] + 20))
        updates = []
        self.ui._update_cookies_and_csrf = updates.append
        result = self.workflow_request()
        self.assertEqual(result.error_code, 'WORKFLOW_TIMEOUT')
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(len(self.ui.callbacks.calls), 3)
        self.assertEqual(len(updates), 3)
        self.assertIsNone(result.request_bytes)

    def test_deadline_before_rt_send_preserves_no_send_state(self):
        now = self.fake_clock()
        original_build = self.ui.build_request_from_template
        def slow_build(**kwargs):
            now[0] = 51
            return original_build(**kwargs)
        self.ui.build_request_from_template = slow_build
        result = self.workflow_request()
        self.assertEqual(result.error_code, 'WORKFLOW_TIMEOUT')
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_BEFORE_SEND)
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_late_blocking_rt_response_is_updated_but_no_cp_is_sent(self):
        now = self.fake_clock()
        self.ui.useCheckPageTemplate = True
        self.ui.callbacks = SequenceCallbacks([response(200, None)], on_send=lambda n: now.__setitem__(0, 60))
        updates = []
        self.ui._update_cookies_and_csrf = updates.append
        result = self.workflow_request()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(result.error_code, 'WORKFLOW_TIMEOUT')
        self.assertEqual(len(updates), 1)
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_expired_budget_after_cp_build_is_not_returned_as_ready(self):
        now = self.fake_clock()
        self.ui.useCheckPageTemplate = True
        def slow_cp(**kwargs):
            now[0] = 60
            return as_bytes('GET /cp HTTP/1.1\r\n\r\n')
        self.ui.build_checkpage_request = slow_cp
        result = self.workflow_request()
        self.assertEqual(result.error_code, 'WORKFLOW_TIMEOUT')
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertIsNone(result.request_bytes)

    def test_invalid_redirect_after_rt_is_an_explicit_post_send_error(self):
        self.ui.useCheckPageTemplate = True
        self.ui.autoFollowRTChk = Check(selected=True)
        self.ui.callbacks = Callbacks(response=response(302, 'file:///bad'))
        result = self.workflow_request()
        self.assertEqual(result.error_code, 'REDIRECT_INVALID_LOCATION')
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_cp_uses_last_redirect_token_with_original_service(self):
        self.ui.useCheckPageTemplate = True
        self.ui.autoFollowRTChk = Check(selected=True)
        self.ui.autoUpdateCsrf = True
        self.ui.callbacks = SequenceCallbacks([response(302, 'http://other:8080/next', 'token="FIRST"'), response(200, None, 'token="LAST"')])
        result = self.workflow_request()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertIn('csrf=LAST', as_text(result.request_bytes))
        self.assertEqual(self.ui.callbacks.calls[0][0], ('demo', 8443, 'https'))
        self.assertEqual(self.ui.callbacks.calls[1][0], ('other', 8080, 'http'))


class PassiveActionTests(SourceCase):
    def test_request_and_response_preserve_prior_actions_in_passive_or_unmatched_modes(self):
        class ReplyMessage(Message):
            def getResponse(self):
                return response(200, None)
        for proxy_on in (False, True):
            self.ui._proxy_mode_active = proxy_on
            extender = object.__new__(self.ns['BurpExtender'])
            extender.ui, extender.helpers = self.ui, self.ui.helpers
            for request in (False, True):
                for action in (0, 1, 2, 3):
                    intercepted = Intercepted()
                    intercepted.message = ReplyMessage()
                    intercepted.message.request = as_bytes('GET /unmatched HTTP/1.1\r\n\r\n')
                    intercepted.action = action
                    updates = []
                    original_update = self.ui.sessions.update
                    self.ui.sessions.update = lambda ctx, data: (updates.append(data), original_update(ctx, data))[1]
                    if not request:
                        extender.processProxyMessage(True, intercepted)
                    extender.processProxyMessage(request, intercepted)
                    self.ui.sessions.update = original_update
                    self.assertEqual(intercepted.action, action)
                    self.assertEqual(len(updates), 0 if request else 1)
                    self.assertEqual(intercepted.message.replacements, [])

    def test_missing_response_data_does_not_change_existing_interception(self):
        extender = object.__new__(self.ns['BurpExtender'])
        extender.ui, extender.helpers = self.ui, self.ui.helpers
        for value in (None, as_bytes('')):
            class ReplyMessage(Message):
                def getResponse(self):
                    return value
            intercepted = Intercepted()
            intercepted.message = ReplyMessage()
            intercepted.action = intercepted.ACTION_DO_INTERCEPT
            extender.processProxyMessage(False, intercepted)
            self.assertEqual(intercepted.action, intercepted.ACTION_DO_INTERCEPT)

    def test_matched_active_request_keeps_automatic_forward_behavior(self):
        extender = object.__new__(self.ns['BurpExtender'])
        extender.ui, extender.helpers = self.ui, self.ui.helpers
        self.ui._proxy_mode_active = True
        intercepted = Intercepted()
        intercepted.action = intercepted.ACTION_DROP
        extender.processProxyMessage(True, intercepted)
        self.assertEqual(intercepted.action, intercepted.ACTION_DONT_INTERCEPT)
        self.assertEqual(len(intercepted.message.replacements), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
