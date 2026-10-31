# -*- coding: utf-8 -*-
"""K04 cookie/CSRF contracts; real manager code with helper doubles only."""
from __future__ import print_function

import binascii
import gzip
from io import BytesIO
import unittest

from source_harness import Field, as_bytes, as_text
from test_source_logic import SourceCase


def response(*cookies, **kwargs):
    return as_bytes('HTTP/1.1 200 OK\r\n' + ''.join(
        'Set-Cookie: ' + cookie + '\r\n' for cookie in cookies) +
        '\r\n' + kwargs.get('body', ''))


class CookieTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.jar = self.ui.cookieManager
        self.now = [2000000000.0]
        self.jar._now = lambda: self.now[0]

    def inject(self):
        return self.jar.inject_into_request(
            'POST / HTTP/1.1\r\nHost: demo\r\nCookie: sid=template; untouched=x\r\n'
            'Cookie: another=y\r\n\r\n\x00\xffBODY')

    def test_exact_header_names_and_body_is_ignored(self):
        self.jar.update_from_response(as_bytes(
            'HTTP/1.1 200 OK\r\nX-Set-Cookie-Info: fake=x\r\n'
            'Set-Cookie2: fake2=x\r\nsEt-CoOkIe:\tgood = value\r\n'
            'Set-Cookie: bad\r\nSet-Cookie: =empty-name\r\n'
            'Set-Cookie: final=yes\r\n\r\nSet-Cookie: body=no'))
        self.assertEqual(self.jar.jar, {'good': 'value', 'final': 'yes'})

    def test_deleted_and_empty_are_values(self):
        self.jar.update_from_response(response('a=deleted', 'b=deletedButValid', 'c='))
        self.assertEqual(self.jar.jar, {'a': 'deleted', 'b': 'deletedButValid', 'c': ''})

    def test_max_age_zero_and_negative_suppress_template(self):
        for age in ['0', '-1', '-999999999999999999999999']:
            self.jar.clear()
            self.jar.update_from_response(response('sid=old; Max-Age=' + age))
            self.assertNotIn('sid', self.jar.jar)
            self.assertNotIn('sid=', self.inject())
            self.assertIn('untouched=x', self.inject())

    def test_max_age_overrides_expires_both_directions(self):
        self.jar.update_from_response(response('sid=new; Max-Age=60; Expires=Wed, 09 Jun 2021 10:18:14 GMT'))
        self.assertEqual(self.jar.jar['sid'], 'new')
        self.jar.update_from_response(response('sid=gone; Max-Age=0; Expires=Wed, 09 Jun 2099 10:18:14 GMT'))
        self.assertNotIn('sid=', self.inject())

    def test_future_expiry_becomes_tombstone_without_new_response(self):
        self.jar.update_from_response(response('sid=short; Max-Age=2'))
        self.now[0] += 1
        self.assertIn('sid=short', self.inject())
        self.now[0] += 1
        self.assertNotIn('sid=', self.inject())
        self.assertNotIn('sid', self.jar.jar)

    def test_expires_is_utc_and_comma_does_not_split_cookies(self):
        self.jar.update_from_response(response('sid=gone; Expires=Wed, 09 Jun 2021 10:18:14 GMT',
                                               'live=one; Expires=Wed, 09 Jun 2099 10:18:14 GMT'))
        self.assertNotIn('sid=', self.inject())
        self.assertIn('live=one', self.inject())

    def test_legacy_cookie_dates_and_two_digit_years(self):
        for date in ['Wed, 09-Jun-21 10:18:14 GMT', 'Wed Jun  9 10:18:14 2021',
                     'Wed, 09 Jun 69 10:18:14 GMT']:
            self.jar.update_from_response(response('sid=value; Expires=' + date))
            if '69 ' in date:
                self.assertIn('sid=value', self.inject())
            else:
                self.assertNotIn('sid=', self.inject())

    def test_invalid_dates_are_ignored_without_normalization(self):
        for date in ['nonsense', 'Wed, 31 Feb 2021 10:18:14 GMT',
                     'Wed, 09 Jun 1599 10:18:14 GMT', 'Wed, 09 Jun 2021 25:00:00 GMT']:
            self.jar.update_from_response(response('sid=valid; Expires=' + date))
            self.assertIn('sid=valid', self.inject())

    def test_invalid_max_age_falls_back_to_expires(self):
        for age in ['abc', '+5', '1.5', '']:
            self.jar.update_from_response(response('sid=value; Max-Age=' + age +
                '; Expires=Wed, 09 Jun 2021 10:18:14 GMT'))
            self.assertNotIn('sid=', self.inject())

    def test_duplicate_attributes_last_valid_wins(self):
        self.jar.update_from_response(response('sid=value; Max-Age=0; Max-Age=30; Max-Age=bad'))
        self.assertIn('sid=value', self.inject())

    def test_huge_positive_max_age_is_valid_and_bounded(self):
        self.jar.update_from_response(response('sid=value; Max-Age=' + '9' * 5000))
        self.assertIn('sid=value', self.inject())

    def test_tombstone_readdition_and_clear(self):
        self.jar.update_from_response(response('sid=; Max-Age=0'))
        self.assertNotIn('sid=', self.inject())
        self.jar.update_from_response(response('sid=new'))
        self.assertIn('sid=new', self.inject())
        self.jar.update_from_response(response('sid=; Max-Age=0'))
        self.jar.clear()
        self.assertIn('sid=template', self.inject())

    def test_duplicate_headers_and_body_bytes_survive_merge(self):
        self.jar.update_from_response(response('sid=new'))
        text = self.inject()
        self.assertEqual(text.lower().count('\r\ncookie:'), 1)
        self.assertIn('another=y', text)
        self.assertTrue(text.endswith(u'\r\n\r\n\x00\xffBODY'))

    def test_clear_during_decode_prevents_stale_cookie_update(self):
        original = self.jar._decode
        def decode(data):
            self.jar.clear()
            return original(data)
        self.jar._decode = decode
        self.jar.update_from_response(response('sid=stale'))
        self.assertEqual(self.jar.jar, {})
        self.assertIn('sid=template', self.inject())

    def test_global_cookie_model_has_no_host_path_secure_partition(self):
        # Deliberate compatibility limitation, not a multi-origin safety claim.
        self.jar.update_from_response(response('sid=A; Domain=a.invalid; Path=/private; Secure'))
        text = self.jar.inject_into_request('GET /public HTTP/1.1\r\nHost: b.invalid\r\n\r\n')
        self.assertIn('sid=A', text)
        self.jar.update_from_response(response('sid=B; Domain=b.invalid'))
        self.assertIn('sid=B', self.inject())

    def test_invalid_cookie_names_and_controls_do_not_hide_valid_fields(self):
        self.jar.update_from_response(response('bad name=x', 'bad:name=x', 'control=one\x00two', 'good=yes'))
        self.assertEqual(self.jar.jar, {'good': 'yes'})

    def test_dump_expires_and_session_readdition_removes_old_deadline(self):
        self.jar.update_from_response(response('sid=short; Max-Age=1'))
        self.jar.update_from_response(response('sid=session'))
        self.now[0] += 10
        self.assertIn('sid=session', self.jar.dump())
        self.jar.update_from_response(response('sid=short; Max-Age=1'))
        self.now[0] += 1
        self.assertEqual(self.jar.dump(), '<no cookies>')
        self.assertNotIn('sid=', self.inject())


class CsrfTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.manager = self.ui.csrfManager
        self.manager.pattern_to_use = r'token="([^"]*)"'

    def test_no_match_keeps_token_with_distinct_status(self):
        self.assertEqual(self.manager.update_from_response(as_bytes('token="FIRST"')), (True, 'FIRST'))
        self.assertEqual(self.manager.update_from_response(as_bytes('no token')), (False, None))
        self.assertEqual(self.manager.get_token(), 'FIRST')
        self.assertEqual(self.manager.get_status()[0], 'NO_MATCH')

    def test_empty_token_and_clear_are_distinct(self):
        self.assertEqual(self.manager.update_from_response(as_bytes('token=""')), (True, ''))
        self.assertEqual(self.manager.get_token(), '')
        self.assertEqual(self.manager.dump(), '<empty csrf token>')
        self.manager.clear()
        self.assertIsNone(self.manager.get_token())
        self.assertEqual(self.manager.get_status()[0], 'CLEARED')

    def test_invalid_regex_and_missing_group_preserve_token(self):
        self.manager.set_token('OLD')
        for pattern, status in [('[', 'REGEX_INVALID'), ('token', 'REGEX_NO_CAPTURE'),
                                (r'(x){99999999999999999999999}', 'REGEX_INVALID')]:
            self.manager.pattern_to_use = pattern
            self.assertEqual(self.manager.get_status()[0], status)
            self.assertFalse(self.manager.update_from_response(as_bytes('token="NEW"'))[0])
            self.assertEqual(self.manager.get_token(), 'OLD')
            self.assertEqual(self.manager.get_status()[0], status)

    def test_unset_pattern_is_not_no_match_or_error(self):
        self.manager.pattern_to_use = ''
        self.assertEqual(self.manager.get_status()[0], 'REGEX_UNSET')
        self.assertEqual(self.manager.update_from_response(as_bytes('token="X"')), (False, None))

    def test_optional_unmatched_capture_does_not_clear(self):
        self.manager.set_token('OLD')
        self.manager.pattern_to_use = r'(token)?other'
        self.assertFalse(self.manager.update_from_response(as_bytes('other'))[0])
        self.assertEqual(self.manager.get_token(), 'OLD')

    def test_first_of_multiple_captures_and_existing_flags(self):
        self.manager.pattern_to_use = r'TOKEN="(.*?)"(.*)'
        self.assertEqual(self.manager.update_from_response(as_bytes('token="a\nb"tail')), (True, 'a\nb'))

    def test_compile_only_on_changed_pattern(self):
        compiled = self.manager._compiled_pattern
        self.manager.pattern_to_use = self.manager.pattern_to_use
        self.manager.update_from_response(as_bytes('token="X"'))
        self.manager.update_from_response(as_bytes('token="Y"'))
        self.assertIs(self.manager._compiled_pattern, compiled)

    def test_non_ascii_bytes_are_kept(self):
        self.assertEqual(self.manager.update_from_response(as_bytes('token="\xff\x80"')), (True, u'\xff\x80'))

    def test_compressed_bytes_are_not_implicitly_decompressed(self):
        self.manager.set_token('OLD')
        # A deterministic gzip stream whose raw bytes have no token marker.
        data = binascii.unhexlify('1f8b08000000000002ff2bc9cf4ecdb3550af1f776f55302008f7fed750d000000')
        self.assertEqual(gzip.GzipFile(fileobj=BytesIO(data)).read(), as_bytes('token="TOKEN"'))
        self.assertFalse(self.manager.update_from_response(data)[0])
        self.assertEqual(self.manager.get_token(), 'OLD')

    def test_clear_during_decode_rejects_stale_update(self):
        original = self.manager._decode
        def decode(data):
            self.manager.clear()
            return original(data)
        self.manager._decode = decode
        self.assertFalse(self.manager.update_from_response(as_bytes('token="STALE"'))[0])
        self.assertIsNone(self.manager.get_token())

    def test_invalid_input_does_not_replace_token(self):
        self.manager.set_token('OLD')
        self.assertFalse(self.manager.update_from_response(object())[0])
        self.assertEqual(self.manager.get_status()[0], 'DECODE_ERROR')
        self.assertEqual(self.manager.get_token(), 'OLD')

    def test_configuration_is_unicode_and_does_not_use_wire_encoding(self):
        self.manager.pattern_to_use = u'token="([^"]*)"|\u20ac'
        self.assertEqual(self.manager.update_from_response(as_bytes('token="OK"')), (True, 'OK'))

    def test_pattern_edit_during_decode_rejects_old_result(self):
        original = self.manager._decode
        def decode(data):
            self.manager.pattern_to_use = r'other="([^"]*)"'
            return original(data)
        self.manager._decode = decode
        self.assertFalse(self.manager.update_from_response(as_bytes('token="STALE"'))[0])
        self.assertIsNone(self.manager.get_token())


class WorkflowStateTests(SourceCase):
    def test_ten_hops_update_real_stores_once_and_final_deletion_reaches_checkpage(self):
        from source_harness import Check, Editor
        from test_redirects import SequenceCallbacks
        replies = []
        for hop in range(11):
            status = 302 if hop < 10 else 200
            location = 'Location: /next?hop=%d\r\n' % (hop + 1) if hop < 10 else ''
            cookie = 'sid=H%d' % hop if hop < 10 else 'sid=; Max-Age=0'
            replies.append(as_bytes('HTTP/1.1 %d Fixture\r\n' % status + location +
                'Set-Cookie: ' + cookie + '\r\n\r\ntoken="H%d"' % hop))
        self.ui.callbacks = SequenceCallbacks(replies)
        self.ui.useCheckPageTemplate = True
        self.ui.autoFollowRTChk = Check(True)
        self.ui.autoUpdateCookies = self.ui.autoUpdateCsrf = True
        self.ui.checkPageEditor = Editor(as_bytes('POST /check HTTP/1.1\r\nHost: demo\r\n'
            'Cookie: sid=old; untouched=x\r\n\r\ncsrf=c5rfm4rk3r'))
        cookies, tokens = [], []
        original_begin = self.ui.sessions.begin
        def begin(context, deadline):
            error = original_begin(context, deadline)
            if error:
                return error
            original_cookie = context.cookies.update_from_response
            original_csrf = context.csrf.update_from_response
            def cookie_update(data):
                cookies.append(as_text(data))
                return original_cookie(data)
            def csrf_update(data):
                tokens.append(as_text(data))
                return original_csrf(data)
            context.cookies.update_from_response = cookie_update
            context.csrf.update_from_response = csrf_update
            return None
        self.ui.sessions.begin = begin
        result = self.ui.proxy_flow_process_request(as_bytes(
            'GET /entry?q=ONE&w=TWO HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertEqual(len(self.ui.callbacks.calls), 11)
        self.assertEqual(cookies, [as_text(reply) for reply in replies])
        self.assertEqual(tokens, cookies)
        self.assertIn(as_bytes('csrf=H10'), result.request_bytes)
        self.assertNotIn(as_bytes('sid='), result.request_bytes)
        self.assertIn(as_bytes('untouched=x'), result.request_bytes)


class CsrfSwitchTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.manager = self.ui.csrfManager

    def test_all_update_and_injection_switch_combinations(self):
        for cookies, csrf in [(False, False), (False, True), (True, False), (True, True)]:
            self.ui.cookieManager.clear()
            self.manager.clear()
            self.ui.autoUpdateCookies = cookies
            self.ui.autoUpdateCsrf = csrf
            self.ui._update_cookies_and_csrf(response('sid=NEW', body='token="TOKEN"'))
            template = as_bytes('GET /?csrf=c5rfm4rk3r HTTP/1.1\r\nHost: demo\r\nCookie: sid=old\r\n\r\n')
            request = self.ui.build_request_from_template(
                get_editor_message=lambda: template, helpers=self.ui.helpers,
                cookie_manager=self.ui.cookieManager, csrf_manager=self.manager,
                auto_update_cookies=cookies, auto_update_csrf=csrf)
            self.assertEqual(self.ui.cookieManager.jar.get('sid'), 'NEW' if cookies else None)
            self.assertEqual(self.manager.get_token(), 'TOKEN' if csrf else None)
            self.assertIn(as_bytes('sid=NEW' if cookies else 'sid=old'), request)
            self.assertIn(as_bytes('csrf=TOKEN' if csrf else 'csrf=c5rfm4rk3r'), request)


if __name__ == '__main__':
    unittest.main(verbosity=2)
