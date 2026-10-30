# -*- coding: utf-8 -*-
"""Full module import against the installed Burp API, outside the running Burp.

Run with Jython + burpsuite.jar on the Java classpath. No registration callback,
no extension tab, no requests. This does not prove in-application loading.
"""
from __future__ import print_function

import argparse
import codecs
import hashlib
import json
import os
import sys

from burp import IBurpExtender, IHttpListener, IProxyListener
from java.lang import System
from jarray import array
# Unlike the Burp host, standalone Jython has not discovered Swing packages yet.
# Preimport a concrete class; the production source itself stays unchanged.
from javax.swing import JTable, SwingUtilities, JPanel
from javax.swing.table import TableRowSorter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report')
    parser.add_argument('--ui-smoke', action='store_true', help='Real Swing checkbox events; message editors are doubles')
    args = parser.parse_args()
    source = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'BoberProxy.py')
    with open(source, 'rb') as handle:
        raw = handle.read()
    namespace = {'__name__': 'boberproxy_import_probe', '__file__': source}
    eval(compile(raw, source, 'exec'), namespace)
    extender = namespace['BurpExtender']
    response = 'HTTP/1.1 200 OK\r\nSet-Cookie: sid=FIRST\r\n\r\ntoken="TOKEN"'
    java_bytes = array([ord(c) if ord(c) < 128 else ord(c) - 256 for c in response], 'b')
    cookies = namespace['CookieManager']()
    cookies.update_from_response(java_bytes)
    csrf = namespace['CsrfManager']()
    csrf.pattern_to_use = r'token="([^"]*)"'
    csrf.update_from_response(java_bytes)
    checks = dict(extends_burp=issubclass(extender, IBurpExtender),
                  http_listener=issubclass(extender, IHttpListener),
                  proxy_listener=issubclass(extender, IProxyListener),
                  java_bytes_cookie=cookies.jar.get('sid') == 'FIRST',
                  java_bytes_csrf=csrf.get_token() == 'TOKEN')
    table_errors = []

    def check_table():
        try:
            store = namespace['LogStore']()
            store.add('t', 'demo', 'POST', '/two', 200, 10, 1, None)
            store.add('t', 'demo', 'GET', '/one', 200, 10, 1, None)
            model = namespace['LogTableModel'](store)
            model.rebuild()
            table = JTable(model)
            sorter = TableRowSorter(model)
            table.setRowSorter(sorter)
            sorter.toggleSortOrder(3)
            checks['real_swing_model_sort'] = (table.getRowCount() == 2 and table.getValueAt(0, 3) == 'GET')
        except BaseException as error:
            checks['real_swing_model_sort'] = False
            table_errors.append(str(error))

    SwingUtilities.invokeAndWait(check_table)
    if 'HttpRequestSender' in namespace:
        from source_harness import Callbacks, Helpers
        from java.io import IOException
        legacy_callbacks = Callbacks(response=java_bytes, legacy=True)
        legacy_sender = namespace['HttpRequestSender'](legacy_callbacks, Helpers())
        legacy_result = legacy_sender.send('demo', 80, False, java_bytes)
        checks['legacy_real_java_bytes_response'] = bool(
            legacy_result.error_code is None and legacy_result.response_bytes is java_bytes
            and len(legacy_callbacks.calls) == 1 and len(legacy_callbacks.calls[0]) == 4)

        class JavaFailureCallbacks(Callbacks):
            def makeHttpRequest(self, *args):
                self.calls.append(args)
                raise IOException('Controlled native Java send failure')

        failing_callbacks = JavaFailureCallbacks(both=True)
        failing_sender = namespace['HttpRequestSender'](failing_callbacks, Helpers())
        failed = failing_sender.send('demo', 80, False, java_bytes)
        checks['java_exception_has_no_retry'] = bool(
            failed.attempted and failed.error_code == 'HTTP_SEND_FAILED'
            and len(failing_callbacks.calls) == 1)
    ui_errors = []
    if args.ui_smoke:
        from source_harness import Helpers

        class Editor(object):
            def getComponent(self):
                return JPanel()

        class UICallbacks(object):
            def getHelpers(self):
                return Helpers()

            def createMessageEditor(self, controller, editable):
                return Editor()

        def check_toggle():
            try:
                callbacks = UICallbacks()
                controller = namespace['SimpleMessageController']()
                ui = namespace['LoggerUI'](callbacks, controller, None, callbacks)
                checks['initial_checkpage_off'] = not ui.useCheckPageTemplate
                ui.useCheckPageChk.doClick()
                ui.proxyModeBtn.doClick()
                checks['real_swing_checkpage_toggle'] = bool(ui.useCheckPageTemplate and ui.useCheckPageChk.isSelected())
                checks['real_swing_autofollow_enabled'] = bool(ui.autoFollowRTChk.isEnabled())
                ui.autoUpdateChk.doClick()
                ui.autoUpdateCsrfChk.doClick()
                checks['real_swing_cookie_flag'] = bool(ui.autoUpdateCookies)
                checks['real_swing_csrf_flag'] = bool(ui.autoUpdateCsrf)
                html = 'HTTP/1.1 200 OK\r\nSet-Cookie: sid=FROM_UI\r\n\r\n<input name="csrfmiddlewaretoken" value="UI_TOKEN">'
                html_bytes = array([ord(c) for c in html], 'b')
                ui._update_cookies_and_csrf(html_bytes)
                checks['response_updates_cookie_via_text_helper'] = ui.cookieManager.jar.get('sid') == 'FROM_UI'
                checks['response_updates_csrf_with_default_regex'] = ui.csrfManager.get_token() == 'UI_TOKEN'
            except BaseException as error:
                checks['real_swing_checkpage_toggle'] = False
                ui_errors.append(str(error))

        SwingUtilities.invokeAndWait(check_toggle)
    report = dict(kind='standalone-full-jython-import-with-real-burp-api',
                  not_in_application=True, checks=checks, passed=all(checks.values()),
                  standalone_bootstrap='Concrete javax.swing.JTable/TableRowSorter preimports',
                  table_errors=table_errors,
                  ui_smoke_requested=args.ui_smoke, message_editors_are_doubles=args.ui_smoke,
                  ui_errors=ui_errors,
                  transport_callbacks_are_doubles='HttpRequestSender' in namespace,
                  source_sha256=hashlib.sha256(raw).hexdigest(), python=sys.version,
                  java_version=str(System.getProperty('java.version')),
                  java_vendor=str(System.getProperty('java.vendor')))
    if args.report:
        with codecs.open(args.report, 'w', 'utf-8') as handle:
            handle.write(json.dumps(report, indent=2, ensure_ascii=True) + '\n')
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
