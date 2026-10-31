# -*- coding: utf-8 -*-
"""Behavioral baseline. Expected failures are known unfixed source defects.

An unexpected success requires reviewing/promoting the test after a fix.
No failing assertion is silently accepted as a successful regression check.
"""
from __future__ import print_function

import time
import threading
import unittest

from source_harness import (Callbacks, CapturedOutput, FakeTime, Field, Response,
                            as_bytes, as_text, load_namespace, new_ui)


class SourceCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load_namespace()

    def setUp(self):
        self.ui = new_ui(self.ns)
        self.capture = CapturedOutput()
        self.capture.__enter__()

    def tearDown(self):
        executor = getattr(self.ui, '_custom_executor', None)
        if executor is not None:
            self.ui.close_custom_runtime()
            if executor.worker is not None:
                executor.worker.join(2)
                self.assertFalse(executor.worker.is_alive(), 'Finite probe worker did not finish')
        filter_worker = getattr(self.ui, '_filter_worker', None)
        if filter_worker is not None and filter_worker.worker is not None:
            filter_worker.worker.join(2)
            self.assertFalse(filter_worker.worker.is_alive(), 'Finite filter worker did not finish')
        self.capture.__exit__()
        self.ns['time'] = time
        for thread in self.ns['_probe_threads']:
            thread.join(2)
            if thread.is_alive():
                raise AssertionError('Finite probe worker did not finish')
        self.ns['_probe_threads'][:] = []

    def build(self, payload1='ONE', payload2='TWO'):
        template = as_bytes('GET /?a=p4yl04dm4rk3r&b=53c0undm4rk3r HTTP/1.1\r\nHost: demo\r\n\r\n')
        return self.ui.build_request_from_template(
            get_editor_message=lambda: template,
            helpers=self.ui.helpers, csrf_manager=self.ui.csrfManager,
            incoming_payload1=payload1, incoming_payload2=payload2)

    def workflow(self):
        self.ui.useCheckPageTemplate = True
        self.rt = as_bytes('POST /action HTTP/1.1\r\nHost: demo\r\n\r\n')
        self.ui.build_request_from_template = lambda **kwargs: self.rt
        self.ui.build_checkpage_request = lambda **kwargs: as_bytes('CHECKPAGE')
        return self.ui.proxy_flow_process_request(
            as_bytes('GET /?q=ONE HTTP/1.1\r\nHost: demo\r\n\r\n'),
            'demo', 443, True)

    def redirect(self):
        self.ui.autoUpdateCookies = True
        self.ui.callbacks = Callbacks(as_bytes('HTTP/1.1 200 OK\r\nSet-Cookie: sid=last\r\n\r\n'))
        return self.ui._follow_redirects_chain(
            as_bytes('POST /a/start HTTP/1.1\r\nHost: demo:8443\r\n\r\n'),
            as_bytes('HTTP/1.1 302 Found\r\nLocation: next\r\nSet-Cookie: sid=first\r\n\r\n'),
            'demo', 8443, True, max_redirects=1)


class SessionFixedRegressions(SourceCase):
    def test_P07_deleted_prefix_is_valid_cookie_value(self):
        self.ui.cookieManager.update_from_response(as_bytes('HTTP/1.1 200 OK\r\nSet-Cookie: sid=deletedButValid\r\n\r\n'))
        self.assertEqual(self.ui.cookieManager.jar.get('sid'), 'deletedButValid')

    def test_P08_max_age_zero_deletes_cookie(self):
        self.ui.cookieManager.update_from_response(as_bytes('HTTP/1.1 200 OK\r\nSet-Cookie: sid=old; Max-Age=0\r\n\r\n'))
        self.assertNotIn('sid', self.ui.cookieManager.jar)

    def test_P09_cookie_header_name_is_exact(self):
        self.ui.cookieManager.update_from_response(as_bytes('HTTP/1.1 200 OK\r\nX-Set-Cookie-Info: fake=value\r\n\r\n'))
        self.assertNotIn('fake', self.ui.cookieManager.jar)

    def test_P10_deleted_cookie_not_revived_from_template(self):
        self.ui.cookieManager.update_from_response(as_bytes('HTTP/1.1 200 OK\r\nSet-Cookie: sid=; Max-Age=0\r\n\r\n'))
        request = self.ui.cookieManager.inject_into_request('GET / HTTP/1.1\r\nHost: demo\r\nCookie: sid=old\r\n\r\n')
        self.assertNotIn('sid=old', request)
class CustomFixedRegressions(SourceCase):
    def test_P13_timeout_covers_top_level_user_code(self):
        self.ui.custom_codeblock_status = True
        self.ui.customCodeArea = Field('import time\ntime.sleep(0.20)\ndef custom_codeblock(a,b,c):\n    return a,b,c\n')
        ok, result, error = self.ui.run_user_code('ONE', 50, 'TWO', 'TOKEN')
        self.assertFalse(ok, 'Top-level code exceeded the deadline')
        self.assertIn('CUSTOM_TIMEOUT', error)

class KnownDefects(SourceCase):
    @unittest.expectedFailure
    def test_P14_timeout_does_not_leave_worker_running(self):
        # This desired property needs hard isolation or an explicit accepted limitation.
        entered, release = threading.Event(), threading.Event()
        self.ui.custom_codeblock_status = True
        self.ui.customCodeArea = Field('def custom_codeblock(a,b,c):\n    a[0].set()\n    a[1].wait(2)\n    return "ONE",b,c\n')
        try:
            ok, result, error = self.ui.run_user_code((entered, release), 100, 'TWO', 'TOKEN')
            if not entered.is_set():
                raise RuntimeError('Hard-stop probe never entered user code; cannot count as a known defect')
            self.assertFalse(ok)
            self.assertFalse(self.ui._custom_executor.state()['active'])
        finally:
            release.set()  # Finite probe cleanup even when the expected assertion fails.


class FixedRegressions(SourceCase):
    def test_P03_unselected_autofollow_does_not_follow(self):
        follows = []
        self.ui._follow_redirects_chain = lambda *a, **kw: follows.append(True)
        self.workflow()
        self.assertEqual(follows, [])

    def test_P05_relative_redirect_keeps_directory_and_port(self):
        self.redirect()
        service, request = self.ui.callbacks.calls[0]
        self.assertEqual(service, ('demo', 8443, 'https'))
        self.assertTrue(request.startswith(as_bytes('GET /a/next ')))

    def test_P06_last_redirect_response_updates_cookie(self):
        self.redirect()
        self.assertEqual(self.ui.cookieManager.jar.get('sid'), 'last')

    def test_P01_custom_error_preserves_original_diagnostic(self):
        self.ui.custom_codeblock_status = True
        self.ui.run_user_code = lambda *args: (False, None, 'SENTINEL_CUSTOM_ERROR')
        self.build()
        diagnostic = self.capture.text() + self.ui.customStatusArea.getText()
        self.assertIn('SENTINEL_CUSTOM_ERROR', diagnostic)
        self.assertNotIn('outgoing_payload1', diagnostic)

    def test_P11_inserted_payload_is_not_replaced_again(self):
        request = self.build('53c0undm4rk3r', 'SECOND')
        self.assertIn(as_bytes('a=53c0undm4rk3r&b=SECOND'), request)

    def test_P12_zero_body_length_is_not_missing(self):
        ui = self.ui
        ui.logStore = self.ns['LogStore']()
        ui.logTableModel = self.ns['LogTableModel'](ui.logStore)
        ui.set_status = lambda text: None
        response = as_bytes('HTTP/1.1 204 No Content\r\n\r\n')
        ui.append_log_row(0, 'demo', 'GET', '/', 204, len(response), Response(response), False)
        ui.display_filters = {'BodyLen': {'active': True, 'mode': 'eq', 'values': ['0']}}
        self.assertEqual(ui.logStore.entries[0].body_len, 0)
        self.assertTrue(ui._row_matches_filters(ui.logStore.entries[0]))

    def test_P02_sent_request_not_returned_after_checkpage_error(self):
        self.ui.build_checkpage_request = lambda **kwargs: None
        self.ui.useCheckPageTemplate = True
        rt = as_bytes('POST /action HTTP/1.1\r\nHost: demo\r\n\r\n')
        self.ui.build_request_from_template = lambda **kwargs: rt
        result = self.ui.proxy_flow_process_request(
            as_bytes('GET /?q=ONE HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 443, True)
        self.assertEqual(len(self.ui.callbacks.calls), 1)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_AFTER_SEND)
        self.assertIsNone(result.request_bytes)

    def test_P04_legacy_response_is_not_discarded(self):
        clock = FakeTime()
        self.ns['time'] = clock
        updates = []
        self.ui.callbacks = Callbacks(legacy=True)
        self.ui._update_cookies_and_csrf = lambda data: updates.append(data)
        # Isolate transport from the separate, still-unfixed AutoFollow/update issue.
        self.ui._follow_redirects_chain = lambda *args, **kwargs: args[1]
        result = self.workflow()
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertEqual(len(self.ui.callbacks.calls), 1)
        self.assertEqual(len(updates), 1)
        self.assertEqual(clock.sleeps, [])


class CompatibilityBaseline(SourceCase):
    def test_template_replaces_two_payloads(self):
        self.assertIn(as_bytes('a=ONE&b=TWO'), self.build())

    def test_raw_payload_percent_and_plus_are_unchanged(self):
        self.assertIn(as_bytes('a=%252F+%2B&b=TWO'), self.build('%252F+%2B'))

    def test_query_precedes_nonempty_form_body(self):
        captured = []
        self.ui.build_request_from_template = lambda **kw: captured.append(kw) or as_bytes('BUILT')
        request = as_bytes('POST /?q=QUERY HTTP/1.1\r\nHost: demo\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=BODY&w=%252F+')
        self.ui.proxy_flow_process_request(request, 'demo', 80, False)
        self.assertEqual(captured[0]['incoming_payload1'], 'QUERY')
        self.assertEqual(captured[0]['incoming_payload2'], '%252F+')

    def test_empty_payloads_currently_do_not_activate(self):
        result = self.ui.proxy_flow_process_request(as_bytes('GET /?q=&w= HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].NO_MATCH)

    def test_missing_payload_does_not_activate(self):
        result = self.ui.proxy_flow_process_request(as_bytes('GET / HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].NO_MATCH)

    def test_cookie_merge_keeps_unmanaged_template_cookie(self):
        self.ui.cookieManager.update_from_response(as_bytes('HTTP/1.1 200 OK\r\nSet-Cookie: sid=new\r\n\r\n'))
        request = self.ui.cookieManager.inject_into_request('GET / HTTP/1.1\r\nHost: demo\r\nCookie: sid=old; untouched=x\r\n\r\n')
        self.assertIn('sid=new', request)
        self.assertIn('untouched=x', request)

    def test_csrf_no_match_retains_previous_token(self):
        manager = self.ui.csrfManager
        manager.pattern_to_use = r'token="([^"]*)"'
        self.assertTrue(manager.update_from_response(as_bytes('token="FIRST"'))[0])
        self.assertFalse(manager.update_from_response(as_bytes('no token here'))[0])
        self.assertEqual(manager.get_token(), 'FIRST')
        manager.clear()
        self.assertIsNone(manager.get_token())

    def test_custom_passthrough_contract(self):
        self.ui.custom_codeblock_status = True
        self.ui.customCodeArea = Field('def custom_codeblock(a,b,c):\n    return a,b,c\n')
        ok, result, error = self.ui.run_user_code('ONE', 2000, 'TWO', 'TOKEN')
        self.assertTrue(ok, error)
        self.assertEqual(tuple(result), ('ONE', 'TWO', 'TOKEN'))

    def test_no_checkpage_means_no_internal_request(self):
        self.ui.build_request_from_template = lambda **kw: as_bytes('BUILT')
        result = self.ui.proxy_flow_process_request(as_bytes('GET /?q=ONE HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertEqual(result.request_bytes, as_bytes('BUILT'))
        self.assertEqual(self.ui.callbacks.calls, [])

    def test_log_ids_stay_stable_newest_first(self):
        store = self.ns['LogStore']()
        first = store.add('t', 'demo', 'GET', '/one', 200, 1, 1, None)
        second = store.add('t', 'demo', 'GET', '/two', 200, 1, 1, None)
        self.assertEqual([entry.index for entry in store.entries], [2, 1])
        self.assertIs(store.entries[1], first)
        self.assertIs(store.entries[0], second)


if __name__ == '__main__':
    unittest.main(verbosity=2)
