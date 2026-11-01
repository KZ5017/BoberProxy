# -*- coding: utf-8 -*-
"""K04 real source, Java byte[] and Swing events. No network or live tab.

The Burp wrapper supplies actual helpers; standalone helpers/message editors
are doubles. This probe never changes the running BoberProxy's configuration.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys
import traceback

from javax.swing import JPanel, SwingUtilities, JTable
from javax.swing.table import TableRowSorter
from java.lang import System
from jarray import array
from probe_template_native import load_source
from source_harness import ROOT, Helpers, CapturedOutput, as_text


def run_checks(helpers=None):
    actual_helpers = helpers is not None
    helpers = helpers if actual_helpers else Helpers()
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    checks, errors = {}, []
    wire = helpers.stringToBytes

    def check(name, operation):
        try:
            checks[name] = bool(operation())
        except BaseException:
            checks[name] = False
            errors.append(name + '\n' + traceback.format_exc())

    def reply(cookie):
        return wire('HTTP/1.1 200 OK\r\nSet-Cookie: ' + cookie + '\r\n\r\n')

    jar = ns['CookieManager']()
    request = u'GET / HTTP/1.1\r\nHost: demo\r\nCookie: sid=old; untouched=x\r\n\r\n\xff'
    jar.update_from_response(reply('sid=deletedButValid'))
    check('java_array_deleted_prefix_is_value', lambda: jar.jar.get('sid') == 'deletedButValid')
    jar.update_from_response(reply('sid=; Max-Age=0'))
    check('tombstone_suppresses_unicode_template_cookie', lambda: 'sid=' not in jar.inject_into_request(request))
    check('unmanaged_cookie_and_high_byte_body_survive', lambda: 'untouched=x' in jar.inject_into_request(request)
          and jar.inject_into_request(request).endswith(u'\r\n\r\n\xff'))
    jar.update_from_response(reply('sid='))
    check('empty_cookie_is_readdition', lambda: jar.jar.get('sid') == '' and 'sid=' in jar.inject_into_request(request))
    jar.clear()
    check('clear_restores_template', lambda: 'sid=old' in jar.inject_into_request(request))
    jar.update_from_response(wire('HTTP/1.1 200 OK\r\nX-Set-Cookie-Info: fake=x\r\nSeT-CoOkIe: sid=NEW\r\n\r\n'))
    check('actual_header_name_only', lambda: jar.jar == {'sid': 'NEW'})
    jar.update_from_response(reply('sid=gone; Expires=Wed, 09 Jun 2021 10:18:14 GMT'))
    check('native_utc_expiry_tombstone', lambda: 'sid=' not in jar.inject_into_request(request))
    jar.update_from_response(reply('sid=NEW; Max-Age=60; Expires=Wed, 09 Jun 2021 10:18:14 GMT'))
    check('native_max_age_precedes_expires', lambda: jar.jar.get('sid') == 'NEW')

    csrf = ns['CsrfManager']()
    csrf.pattern_to_use = r'token="([^"]*)"'
    data = u'HTTP/1.1 200 OK\r\n\r\ntoken="\xff\x80"'
    signed = array([ord(c) if ord(c) < 128 else ord(c) - 256 for c in data], 'b')
    check('signed_java_bytes_csrf_preserved', lambda: csrf.update_from_response(signed) == (True, u'\xff\x80'))
    check('native_no_match_retains_token', lambda: not csrf.update_from_response(wire('no token'))[0]
          and csrf.get_token() == u'\xff\x80' and csrf.get_status()[0] == 'NO_MATCH')
    csrf.pattern_to_use = '['
    check('native_invalid_regex_diagnostic', lambda: csrf.get_status()[0] == 'REGEX_INVALID'
          and not csrf.update_from_response(signed)[0] and csrf.get_token() == u'\xff\x80')
    csrf.pattern_to_use = 'token'
    check('native_capture_required', lambda: csrf.get_status()[0] == 'REGEX_NO_CAPTURE')
    csrf.pattern_to_use = r'(x){99999999999999999999999}'
    check('native_oversized_repeat_is_configuration_error', lambda: csrf.get_status()[0] == 'REGEX_INVALID')
    csrf.pattern_to_use = r'token="([^"]*)"'
    check('native_empty_token_is_present', lambda: csrf.update_from_response(wire('token=""')) == (True, '')
          and csrf.dump() == '<empty csrf token>')
    compiled = csrf._compiled_pattern
    csrf.pattern_to_use = r'token="([^"]*)"'
    check('native_unchanged_pattern_reuses_compilation', lambda: csrf._compiled_pattern is compiled)
    csrf.clear()
    check('native_clear_is_missing_token', lambda: csrf.get_token() is None and csrf.dump() == '<no csrf token>')

    class Editor(object):
        def __init__(self): self.value = None
        def getMessage(self):
            return self.value
        def setMessage(self, value, is_request):
            if value is None: raise ValueError('Message cannot be null')
            self.value = value
        def getComponent(self):
            return JPanel()

    class UICallbacks(object):
        def getHelpers(self):
            return helpers
        def createMessageEditor(self, controller, editable):
            return Editor()

    def ui_checks():
        ui = None
        try:
            callbacks = UICallbacks()
            ui = ns['LoggerUI'](callbacks, ns['SimpleMessageController']())
            check('swing_default_regex_compiled_with_options_off', lambda:
                  ui.csrfManager.get_status()[0] == 'REGEX_READY' and not ui.autoUpdateCsrf and not ui.autoUpdateCookies)
            ui.csrfRegexArea.setText('[')
            check('swing_edit_shows_invalid_regex_immediately', lambda:
                  ui.csrfManager.get_status()[0] == 'REGEX_INVALID' and 'REGEX_INVALID' in ui.customStatusArea.getText())
            ui.csrfRegexArea.setText('token')
            check('swing_edit_shows_missing_capture', lambda: 'REGEX_NO_CAPTURE' in ui.customStatusArea.getText())
            ui.csrfRegexArea.setText(r'token="([^"]*)"')
            ui.autoUpdateCsrfChk.doClick()
            ui._publish_runtime()
            ui._update_cookies_and_csrf(wire('HTTP/1.1 200 OK\r\n\r\ntoken="UI"'))
            check('swing_edited_pattern_extracts', lambda: ui.csrfManager.get_token() == 'UI')
            ui.resetCsrfRegexBtn.doClick()
            check('swing_reset_recompiles_default', lambda: ui.csrfManager.pattern_to_use == ui.csrf_default_pattern
                  and ui.csrfManager.get_status()[0] == 'REGEX_READY')
            ui.clearCsrfBtn.doClick()
            ui.showCsrfBtn.doClick()
            check('swing_clear_show_missing', lambda: '<no csrf token>' in ui.customStatusArea.getText())
        except BaseException:
            checks['swing_registration_and_events'] = False
            errors.append(traceback.format_exc())
        finally:
            if ui is not None:
                ui.close_custom_runtime()

    with CapturedOutput():
        if SwingUtilities.isEventDispatchThread():
            ui_checks()
        else:
            SwingUtilities.invokeAndWait(ui_checks)
    return dict(kind='K04-native-manager-and-swing-checks-no-network',
                actual_burp_helpers=actual_helpers, message_editors_are_doubles=True,
                checks=checks, errors=errors, passed=bool(checks) and all(checks.values()) and not errors,
                source_sha256=hashlib.sha256(raw).hexdigest(), python=sys.version,
                java_version=str(System.getProperty('java.version')))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    report = run_checks()
    with open(args.report, 'w') as handle:
        handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
