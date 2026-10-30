# -*- coding: utf-8 -*-
"""K02 payload, diagnostic, framing and byte-preservation contracts.

Also run with native Burp helpers by burp_k02_probe.py; callback sends there
remain doubles. No real network traffic is sent by these tests.
"""
from __future__ import print_function

import unittest

from source_harness import (Callbacks, Field, Helpers, Response, as_bytes,
                            as_text)
from test_source_logic import SourceCase
from test_transport import Intercepted


class TemplateTests(SourceCase):
    def template(self, body='p4yl04dm4rk3r|53c0undm4rk3r|c5rfm4rk3r',
                 headers='', payload1='ONE', payload2='TWO', **kwargs):
        wire = as_bytes('POST /echo HTTP/1.1\r\nHost: demo\r\n' + headers + '\r\n') + as_bytes(body)
        return self.ui.build_request_from_template(
            get_editor_message=lambda: wire, helpers=self.ui.helpers,
            csrf_manager=self.ui.csrfManager,
            incoming_payload1=payload1, incoming_payload2=payload2, **kwargs)

    def body(self, request):
        self.assertIsNotNone(request, self.ui.customStatusArea.getText())
        return as_text(request).split('\r\n\r\n', 1)[1]

    def custom(self, source):
        self.ui.custom_codeblock_status = True
        self.ui.customCodeArea = Field(source)
        self.ui.timeoutField = Field('2000')

    def test_all_original_markers_are_replaced_once(self):
        self.ui.csrfManager.set_token('p4yl04dm4rk3r\\1')
        result = self.template(payload1='53c0undm4rk3r c5rfm4rk3r\\1',
                               payload2='p4yl04dm4rk3r c5rfm4rk3r', auto_update_csrf=True)
        self.assertEqual(self.body(result),
                         '53c0undm4rk3r c5rfm4rk3r\\1|p4yl04dm4rk3r c5rfm4rk3r|p4yl04dm4rk3r\\1')

    def test_cookie_value_is_not_scanned_for_markers(self):
        self.ui.cookieManager.jar['sid'] = 'c5rfm4rk3r'
        self.ui.csrfManager.set_token('TOKEN')
        result = self.template(auto_update_cookies=True, cookie_manager=self.ui.cookieManager,
                               auto_update_csrf=True)
        self.assertIn('sid=c5rfm4rk3r', as_text(result))
        self.assertEqual(self.body(result), 'ONE|TWO|TOKEN')

    def test_disabled_csrf_and_missing_token_keep_original_marker(self):
        for enabled, token in ((False, 'TOKEN'), (True, None)):
            self.ui.csrfManager.set_token(token)
            result = self.template(auto_update_csrf=enabled)
            self.assertEqual(self.body(result), 'ONE|TWO|c5rfm4rk3r')

    def test_custom_none_and_empty_values_remain_empty(self):
        for values in ('None, None, None', "'', '', ''"):
            self.custom('def custom_codeblock(a,b,c):\n    return ' + values + '\n')
            result = self.template(auto_update_csrf=True)
            self.assertEqual(self.body(result), '||c5rfm4rk3r' if values.startswith('None') else '||')

    def test_list_and_tuple_outputs_are_supported(self):
        for values in ("['A','B','C']", "('A','B','C')"):
            self.custom('def custom_codeblock(a,b,c):\n    return ' + values + '\n')
            self.assertEqual(self.body(self.template(auto_update_csrf=True)), 'A|B|C')

    def test_bad_custom_types_do_not_become_repr_or_empty(self):
        for value in ('0', 'False', '42', '{}', 'object()'):
            for values in ((value, "'B'", "'C'"), ("'A'", value, "'C'"), ("'A'", "'B'", value)):
                self.custom('def custom_codeblock(a,b,c):\n    return ' + ','.join(values) + '\n')
                self.assertIsNone(self.template(auto_update_csrf=True))
                diagnostic = self.ui.customStatusArea.getText()
                self.assertIn('Invalid custom return value', diagnostic)
                self.assertNotIn('UnboundLocalError', diagnostic)

    def test_non_byte_unicode_requires_explicit_encoding(self):
        self.custom("def custom_codeblock(a,b,c):\n    return u'\\u20ac', b, c\n")
        self.assertIsNone(self.template())
        self.assertIn('Invalid custom return value', self.ui.customStatusArea.getText())
        self.custom("def custom_codeblock(a,b,c):\n    return u'\\u20ac'.encode('utf-8'), b, c\n")
        self.assertTrue(self.body(self.template()).startswith(u'\xe2\x82\xac|'))

    def test_binary_and_utf8_payload_bytes_are_preserved(self):
        binary = bytearray(range(256))
        result = self.template(body='p4yl04dm4rk3r', payload1=binary)
        self.assertEqual(self.body(result), binary.decode('latin-1'))
        utf8 = u'\u00e1\u20ac'.encode('utf-8')
        self.assertEqual(self.body(self.template(body='p4yl04dm4rk3r', payload1=utf8)),
                         utf8.decode('latin-1'))

    def test_binary_template_body_is_preserved(self):
        binary = bytearray(range(256))
        result = self.template(body=binary.decode('latin-1'))
        self.assertEqual(self.body(result), binary.decode('latin-1'))

    def test_cookie_injection_preserves_binary_and_utf8_bodies(self):
        self.ui.cookieManager.jar['sid'] = 'SYNTHETIC'
        for payload in (bytearray(range(256)), u'\u00e1\u20ac'.encode('utf-8')):
            result = self.template(body='p4yl04dm4rk3r', payload1=payload,
                                   auto_update_cookies=True, cookie_manager=self.ui.cookieManager)
            self.assertEqual(self.body(result), as_text(payload))
            self.assertIn('sid=SYNTHETIC', as_text(result))

    def test_byte_valued_unicode_has_explicit_latin1_mapping(self):
        result = self.template(body='p4yl04dm4rk3r', payload1=u'\u00ff\u0000')
        self.assertEqual(self.body(result), u'\xff\x00')

    def test_helper_parse_failure_does_not_produce_an_empty_request(self):
        class BadHelpers(Helpers):
            def analyzeRequest(self, request):
                raise ValueError('CONTROLLED_PARSE_ERROR')
        self.ui.helpers = BadHelpers()
        self.assertIsNone(self.template())
        self.assertIn('CONTROLLED_PARSE_ERROR', self.ui.customStatusArea.getText())

    def test_missing_or_invalid_analysis_is_an_explicit_error(self):
        for offset in (None, -1, 0, 999999):
            class Analysis(object):
                def getHeaders(self):
                    return ['POST /echo HTTP/1.1', 'Host: demo']
                def getBodyOffset(self):
                    return offset
            class BadHelpers(Helpers):
                def analyzeRequest(self, request):
                    return None if offset is None else Analysis()
            self.ui.helpers = BadHelpers()
            self.assertIsNone(self.template())
            self.assertIn('REQUEST_PARSE_FAILED', self.ui.customStatusArea.getText())

    def test_rebuild_failure_does_not_return_stale_content_length(self):
        class BadHelpers(Helpers):
            def buildHttpMessage(self, headers, body):
                raise ValueError('CONTROLLED_BUILD_ERROR')
        self.ui.helpers = BadHelpers()
        self.assertIsNone(self.template(headers='Content-Length: 999\r\n'))
        self.assertIn('CONTROLLED_BUILD_ERROR', self.ui.customStatusArea.getText())

    def test_unknown_editor_object_is_not_stringified(self):
        result = self.ui.build_request_from_template(get_editor_message=lambda: object(),
                                                     helpers=self.ui.helpers)
        self.assertIsNone(result)
        self.assertIn('TRANSFORM_ERROR', self.ui.customStatusArea.getText())

    def test_content_length_counts_bytes_after_replacement(self):
        for payload in ('', 'X', 'much-longer-than-the-marker' * 4, '\x00\xff'):
            result = self.template(body='p4yl04dm4rk3r', payload1=payload,
                                   headers='Content-Length: 999\r\n')
            head = as_text(result).split('\r\n\r\n', 1)[0]
            lengths = [h.split(':', 1)[1].strip() for h in head.split('\r\n')
                       if h.lower().startswith('content-length:')]
            self.assertEqual(lengths, [str(len(payload))])
            self.assertEqual(self.body(result), as_text(as_bytes(payload)))

    def test_custom_failures_preserve_the_original_reason(self):
        cases = [
            ('def broken(:', 'Compilation error'),
            ('import module_that_does_not_exist_k02', 'module_that_does_not_exist_k02'),
            ("def custom_codeblock(a,b,c):\n    raise ValueError('K02_SENTINEL')\n", 'K02_SENTINEL'),
            ('def custom_codeblock(a,b,c):\n    return a,b\n', 'exactly 3 elements'),
            ('def custom_codeblock(a,b,c):\n    return None\n', 'tuple/list'),
        ]
        for source, reason in cases:
            self.custom(source)
            self.assertIsNone(self.template())
            diagnostic = self.ui.customStatusArea.getText()
            self.assertIn(reason, diagnostic)
            self.assertNotIn('UnboundLocalError', diagnostic)

    def test_finite_custom_timeout_is_a_transform_failure(self):
        self.custom('import time\ndef custom_codeblock(a,b,c):\n    time.sleep(0.08)\n    return a,b,c\n')
        self.ui.timeoutField = Field('1')
        self.assertIsNone(self.template())
        self.assertIn('timeout', self.ui.customStatusArea.getText())

    def test_raw_parameter_priorities_and_activation_are_unchanged(self):
        extract = self.ns['_extract_raw_payloads']
        def request(query='', body='', content_type='application/x-www-form-urlencoded'):
            return 'POST /?' + query + ' HTTP/1.1\r\nContent-Type: ' + content_type + '\r\n\r\n' + body
        cases = [
            ('q=%2F+%252F&q=SECOND&w=%25', 'q=BODY&w=BODY', ('%2F+%252F', '%25')),
            ('q=&q=FIRST&q=SECOND&w=', 'q=BODY&w=FORM', ('FIRST', 'FORM')),
            ('q=&w=', 'q=FORM&w=', ('FORM', '')),
            ('q=NOEQUAL=a%2Bb', '', ('NOEQUAL=a%2Bb', '')),
            ('q&w', '', ('', '')),
        ]
        for query, body, expected in cases:
            self.assertEqual(extract(request(query, body), 'q', 'w'), expected)
        self.assertEqual(extract(request('q=FIRST&q=SECOND&q=THIRD'), 'q', 'q'), ('FIRST', 'SECOND'))
        self.assertEqual(extract(request('q=&q=FIRST', 'q=BODY'), 'q', 'q'), ('FIRST', 'BODY'))
        for content_type in ('application/json', 'multipart/form-data; boundary=test'):
            self.assertEqual(extract(request('', 'q=BODY&w=OTHER', content_type), 'q', 'w'), ('', ''))

    def test_custom_runs_twice_with_step_specific_token_and_raw_inputs(self):
        self.ui.useCheckPageTemplate = True
        self.ui.autoUpdateCsrf = True
        self.ui.csrfManager.set_token('INITIAL')
        calls = []
        def transform(p1, timeout, p2, token):
            calls.append((p1, p2, token))
            return True, (p1, p2, token), None
        self.ui.custom_codeblock_status = True
        self.ui.run_user_code = transform
        self.ui._update_cookies_and_csrf = lambda response: self.ui.csrfManager.set_token('AFTER_RT')
        self.ui._follow_redirects_chain = lambda *args, **kwargs: args[1]
        result = self.ui.proxy_flow_process_request(as_bytes('GET /?q=%252F+&w=W HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertEqual(calls, [('%252F+', 'W', 'INITIAL'), ('%252F+', 'W', 'AFTER_RT')])
        self.assertEqual(len(self.ui.callbacks.calls), 1)

    def test_original_custom_diagnostic_survives_proxy_error_reporting(self):
        self.custom("def custom_codeblock(a,b,c):\n    raise ValueError('VISIBLE_K02_REASON')\n")
        extender = object.__new__(self.ns['BurpExtender'])
        extender.ui = self.ui
        extender.helpers = self.ui.helpers
        self.ui._proxy_mode_active = True
        message = Intercepted()
        extender.processProxyMessage(True, message)
        self.assertEqual(message.action, message.ACTION_DONT_INTERCEPT)
        self.assertEqual(message.message.replacements, [])
        self.assertEqual(self.ui.callbacks.calls, [])
        self.assertIn('RT_BUILD_FAILED', self.ui.customStatusArea.getText())
        self.assertIn('VISIBLE_K02_REASON', self.ui.customStatusArea.getText())

    def test_zero_nonzero_and_missing_body_lengths_filter_distinctly(self):
        self.ui.logStore = self.ns['LogStore']()
        self.ui.logTableModel = self.ns['LogTableModel'](self.ui.logStore)
        self.ui.set_status = lambda value: None
        for response, expected in ((as_bytes('HTTP/1.1 204 No Content\r\n\r\n'), 0),
                                   (as_bytes('HTTP/1.1 200 OK\r\n\r\nX'), 1), (None, '')):
            self.ui.append_log_row(0, 'demo', 'GET', '/', 200, 1, Response(response), False)
            entry = self.ui.logStore.entries[0]
            self.assertEqual(entry.body_len, expected)
            self.ui.display_filters = {'BodyLen': {'active': True, 'mode': 'eq', 'values': ['0']}}
            self.assertEqual(self.ui._row_matches_filters(entry), expected == 0)
            self.ui.display_filters['BodyLen']['mode'] = 'not eq'
            self.assertEqual(self.ui._row_matches_filters(entry), expected != 0)

    def test_table_distinguishes_unknown_body_length_from_zero(self):
        store = self.ns['LogStore']()
        store.add('t', 'demo', 'GET', '/zero', 204, 1, 0, None)
        store.add('t', 'demo', 'GET', '/unknown', '', '', '', None)
        model = self.ns['LogTableModel'](store)
        model.rebuild()
        self.assertIsNone(model.getValueAt(0, 7))
        self.assertEqual(model.getValueAt(1, 7), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
