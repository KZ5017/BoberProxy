# -*- coding: utf-8 -*-
"""K06 controlled ordering: leases, generations and frozen configuration."""
from __future__ import print_function
import threading
import time

from source_harness import as_bytes, as_text, Callbacks, Response
from test_source_logic import SourceCase
from test_transport import Intercepted


def reply(value, extra=''):
    return as_bytes('HTTP/1.1 200 OK\r\nSet-Cookie: sid=' + value + '\r\n' + extra +
                    '\r\ntoken="' + value + '"')


class RuntimeSessionTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.ui.autoUpdateCookies = self.ui.autoUpdateCsrf = True
        self.co = self.ui.sessions
        self.threads = []

    def tearDown(self):
        self.co.close()
        for thread in self.threads:
            thread.join(2)
            self.assertFalse(thread.is_alive(), 'Controlled session thread did not finish')
        SourceCase.tearDown(self)

    def context(self, key, managed=True, config=None):
        ctx, error = self.co.register(key, config or self.ui._capture_runtime(), managed)
        self.assertIsNone(error)
        return ctx

    def begin(self, ctx, budget=2000):
        self.assertIsNone(self.co.begin(ctx, self.ns['_monotonic_ms']() + budget))

    def spawn(self, operation):
        thread = threading.Thread(target=operation)
        thread.daemon = True
        self.threads.append(thread)
        thread.start()
        return thread

    def wait_for(self, predicate):
        end = time.time() + 2
        while not predicate() and time.time() < end:
            time.sleep(0.001)
        self.assertTrue(predicate(), 'Controlled ordering point not reached')

    def test_passive_response_does_not_replace_owner_local_state(self):
        owner = self.context(1)
        self.begin(owner)
        self.co.update(owner, reply('A'))
        passive = self.context(2, False)
        self.co.response(2, reply('B', 'Set-Cookie: other=B\r\n'))
        self.assertEqual(owner.cookies.jar, {'sid': 'A'})
        self.assertEqual(owner.csrf.get_token(), 'A')
        self.assertEqual(self.ui.cookieManager.jar, {'sid': 'B', 'other': 'B'})
        self.assertEqual(self.ui.csrfManager.get_token(), 'B')
        self.assertIsNone(passive.config)
        self.assertTrue(self.co.commit(owner))
        self.co.response(1, as_bytes('HTTP/1.1 204 No Content\r\n\r\n'))
        next_owner = self.context(3)
        self.begin(next_owner)
        self.assertEqual(next_owner.cookies.jar, {'sid': 'B', 'other': 'B'})
        self.assertEqual(next_owner.csrf.get_token(), 'B')

    def test_next_owner_waits_until_final_proxy_response(self):
        first, second = self.context(1), self.context(2)
        self.begin(first)
        self.assertTrue(self.co.commit(first))
        outcomes = []
        self.spawn(lambda: outcomes.append(self.co.begin(second, self.ns['_monotonic_ms']() + 2000)))
        self.wait_for(lambda: second in self.co.waiting)
        self.assertEqual(outcomes, [])
        self.co.response(1, reply('FINAL_A'))
        self.wait_for(lambda: bool(outcomes))
        self.assertEqual(outcomes, [None])
        self.assertIs(self.co.owner, second)
        self.assertEqual(second.csrf.get_token(), 'FINAL_A')

    def test_clear_releases_owner_and_waiter_seeds_new_epoch(self):
        first, second = self.context(1), self.context(2)
        self.begin(first)
        self.co.update(first, reply('A'))
        results = []
        self.spawn(lambda: results.append(self.co.begin(second, self.ns['_monotonic_ms']() + 2000)))
        self.wait_for(lambda: second in self.co.waiting)
        self.co.clear('cookies')
        self.wait_for(lambda: bool(results))
        self.assertEqual(results, [None])
        self.assertEqual(second.cookies.jar, {})
        self.assertEqual(second.csrf.get_token(), 'A', 'Clear Cookies only clears cookies')
        self.assertEqual(second.epoch, self.co.epoch)
        self.assertFalse(self.co.valid(first))
        self.assertEqual(self.co.response(1, reply('LATE'))[0], 'SESSION_STALE_RESPONSE')
        self.assertIs(self.co.owner, second, 'Old completion must not release the new owner')
        self.assertEqual(self.ui.cookieManager.jar, {})

    def test_clear_csrf_invalidates_both_publication_channels(self):
        old = self.context(1, False)
        self.ui.cookieManager.update_from_response(reply('KEEP'))
        self.ui.csrfManager.update_from_response(reply('OLD'))
        self.co.clear('csrf')
        self.assertEqual(self.co.response(1, reply('LATE'))[0], 'SESSION_STALE_RESPONSE')
        self.assertEqual(self.ui.cookieManager.jar, {'sid': 'KEEP'})
        self.assertIsNone(self.ui.csrfManager.get_token())

    def test_clear_while_parser_waits_does_not_block_or_publish(self):
        owner = self.context(1)
        self.begin(owner)
        entered, release = threading.Event(), threading.Event()
        original = owner.csrf._decode
        def blocked(data):
            entered.set()
            if not release.wait(2):
                raise AssertionError('Parser release missing')
            return original(data)
        owner.csrf._decode = blocked
        results = []
        self.spawn(lambda: results.append(self.co.update(owner, reply('LATE'))))
        self.assertTrue(entered.wait(2))
        try:
            self.co.clear('cookies')
            self.assertEqual(self.ui.cookieManager.jar, {})
        finally:
            release.set()
        self.wait_for(lambda: bool(results))
        self.assertEqual(results[0][0], 'SESSION_STALE_RESPONSE')
        self.assertIsNone(self.ui.csrfManager.get_token())

    def test_late_parser_cannot_overwrite_newer_response_or_lose_other_cookie(self):
        old = self.context(1)
        self.begin(old)
        entered, release = threading.Event(), threading.Event()
        decode = old.cookies._decode
        def blocked(data):
            entered.set()
            if not release.wait(2):
                raise AssertionError('Parser release missing')
            return decode(data)
        old.cookies._decode = blocked
        self.spawn(lambda: self.co.update(old, reply('OLD', 'Set-Cookie: only_old=YES\r\n')))
        self.assertTrue(entered.wait(2))
        try:
            self.context(2, False)
            self.co.response(2, reply('NEW', 'Set-Cookie: only_new=YES\r\n'))
        finally:
            release.set()
        self.wait_for(lambda: self.ui.cookieManager.jar.get('only_old') == 'YES')
        self.assertEqual(self.ui.cookieManager.jar, {'sid': 'NEW', 'only_old': 'YES', 'only_new': 'YES'})
        self.assertEqual(self.ui.csrfManager.get_token(), 'NEW')
        self.assertEqual(old.csrf.get_token(), 'OLD')

    def test_missing_final_response_keeps_lease_until_explicit_recovery(self):
        first = self.context(1)
        self.begin(first)
        self.co.commit(first)
        first.deadline = self.ns['_monotonic_ms']() - 1
        second = self.context(2)
        self.assertEqual(self.co.begin(second, self.ns['_monotonic_ms']() + 2000), 'SESSION_RESPONSE_PENDING')
        self.assertIs(self.co.owner, first)
        self.co.finish(second, original_response=True)
        self.co.clear('csrf')
        third = self.context(3)
        self.begin(third)

    def test_queue_capacity_and_deadline_do_not_release_owner(self):
        first = self.context(1)
        self.begin(first)
        self.co.max_waiters = 0
        second = self.context(2)
        self.assertEqual(self.co.begin(second, self.ns['_monotonic_ms']() + 20), 'SESSION_BUSY')
        self.co.max_waiters = 32
        self.assertEqual(self.co.begin(second, self.ns['_monotonic_ms']() + 10), 'SESSION_BUSY')
        self.assertIs(self.co.owner, first)
        self.assertEqual(self.co.waiting, [])

    def test_metadata_capacity_expiry_and_unknown_response_are_explicit(self):
        self.co.max_records = 2
        owner = self.context(1)
        self.begin(owner)
        passive = self.context(2, False)
        _, error = self.co.register(3, self.ui._capture_runtime(), False)
        self.assertEqual(error, 'SESSION_TRACKING_FULL')
        owner.created -= 200000
        passive.created -= 200000
        self.context(3, False)
        self.assertIn(1, self.co.records)
        self.assertNotIn(2, self.co.records)
        self.assertEqual(self.co.response(2, reply('UNKNOWN'))[0], 'SESSION_RESPONSE_UNTRACKED')
        self.assertEqual(self.ui.cookieManager.jar, {})

    def test_close_wakes_waiters_and_rejects_late_response(self):
        first, second = self.context(1), self.context(2)
        self.begin(first)
        results = []
        self.spawn(lambda: results.append(self.co.begin(second, self.ns['_monotonic_ms']() + 2000)))
        self.wait_for(lambda: second in self.co.waiting)
        self.co.close()
        self.wait_for(lambda: bool(results))
        self.assertEqual(results, ['SESSION_CLOSED'])
        self.assertFalse(self.co.valid(first))
        self.assertFalse(self.co.commit(first))
        self.assertEqual(self.co.update(first, reply('LATE'))[0], 'SESSION_STALE_RESPONSE')

    def test_response_uses_request_time_flags_and_regex(self):
        self.context(1, False)
        self.ui.autoUpdateCsrf = self.ui.autoUpdateCookies = False
        self.ui.csrfManager.set_pattern(r'other="([^"]*)"')
        self.co.response(1, reply('FROZEN'))
        self.assertEqual(self.ui.cookieManager.jar, {'sid': 'FROZEN'})
        self.assertEqual(self.ui.csrfManager.get_token(), 'FROZEN')
        self.context(2, False)
        self.ui.autoUpdateCsrf = self.ui.autoUpdateCookies = True
        self.co.response(2, reply('DISABLED_AT_REQUEST'))
        self.assertEqual(self.ui.csrfManager.get_token(), 'FROZEN')

    def test_workflow_freezes_templates_flags_payload_names_and_regex(self):
        self.ui.useCheckPageTemplate = True
        self.ui._publish_runtime()
        snapshot = self.ui._capture_runtime()
        original_cp = snapshot.get('cp')
        ui = self.ui
        class ChangeDuringSend(Callbacks):
            def makeHttpRequest(self, *args):
                self.calls.append(args)
                ui.checkPageEditor.message = as_bytes('GET /WRONG HTTP/1.1\r\n\r\n')
                ui.payloadParamField.setText('wrong')
                ui.autoUpdateCsrf = ui.autoUpdateCookies = False
                ui.useCheckPageTemplate = False
                ui.csrfManager.set_pattern(r'wrong="([^"]*)"')
                ui._publish_runtime()
                return Response(reply('OWN'))
        ui.callbacks = ChangeDuringSend()
        result = ui.proxy_flow_process_request(as_bytes('GET /?q=ONE&w=TWO HTTP/1.1\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        request = as_text(result.request_bytes)
        self.assertIn('/workflow/check', request)
        self.assertIn('sid=OWN', request)
        self.assertIn('csrf=OWN', request)
        self.assertIn('one=ONE&two=TWO', request)
        self.assertEqual(snapshot.get('cp'), original_cp)
        self.assertGreater(ui._capture_runtime().version, snapshot.version)

    def test_callbacks_with_published_config_do_not_read_widgets(self):
        self.ui._proxy_mode_active = True
        self.ui._publish_runtime()
        def forbidden():
            raise AssertionError('Network callback read a live widget')
        self.ui._collect_runtime_values = forbidden
        self.ui.reqTemplateEditor.getMessage = forbidden
        self.ui.payloadParamField.getText = forbidden
        extender = self.ns['BurpExtender']()
        extender.ui, extender.helpers = self.ui, self.ui.helpers
        message = Intercepted()
        extender.processProxyMessage(True, message)
        self.assertEqual(message.action, message.ACTION_DONT_INTERCEPT)
        self.assertIn('/workflow/action', as_text(message.message.getRequest()))
        self.assertEqual(len(self.co.records), 1)
        self.assertFalse(self.ui.should_log(4, True, message.message, self.ui._capture_runtime()))
        message.message.getResponse = lambda: reply('LOG')
        self.assertTrue(self.ui.should_log(4, False, message.message, self.ui._capture_runtime()))

    def test_clear_after_internal_send_stops_before_checkpage(self):
        self.ui.useCheckPageTemplate = True
        ui = self.ui
        class ClearDuringSend(Callbacks):
            def makeHttpRequest(self, *args):
                self.calls.append(args)
                ui.sessions.clear('csrf')
                return Response(reply('LATE'))
        ui.callbacks = ClearDuringSend()
        result = ui.proxy_flow_process_request(as_bytes('GET /?q=ONE HTTP/1.1\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertEqual(result.error_code, 'SESSION_CLEARED')
        self.assertIsNone(result.request_bytes)
        self.assertEqual(len(ui.callbacks.calls), 1)
        self.assertEqual(ui.cookieManager.jar, {})
        self.assertIsNone(ui.csrfManager.get_token())

    def test_reference_rehook_does_not_repeat_workflow_and_null_response_releases(self):
        self.ui._proxy_mode_active = True
        self.ui.useCheckPageTemplate = True
        extender = self.ns['BurpExtender']()
        extender.ui, extender.helpers = self.ui, self.ui.helpers
        message = Intercepted()
        extender.processProxyMessage(True, message)
        extender.processProxyMessage(True, message)
        self.assertEqual(len(self.ui.callbacks.calls), 1)
        self.assertIsNotNone(self.co.owner)
        message.message = None
        extender.processProxyMessage(False, message)
        self.assertIsNone(self.co.owner)
        self.assertEqual(len(self.co.records), 0)
