# -*- coding: utf-8 -*-
"""K02 native Jython containers, optionally with helpers from running Burp.

Does not register the main extension or send traffic. The old framing builder
is loaded from a generated, ignored snapshot for exact helper-output parity.
"""
from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys
import traceback

from java.lang import String, System
from jarray import array
from javax.swing import JTable, SwingUtilities
from javax.swing.table import TableRowSorter

from source_harness import Helpers, ROOT, CapturedOutput, as_text, new_ui


def java_bytes(text):
    return array([ord(c) if ord(c) < 128 else ord(c) - 256 for c in text], 'b')


def load_source(path):
    with open(path, 'rb') as handle:
        raw = handle.read()
    namespace = {'__name__': 'k02_native_source_probe', '__file__': path}
    eval(compile(raw, path, 'exec'), namespace)
    return namespace, raw


def run_checks(helpers=None):
    native_helpers = helpers is not None
    helpers = helpers if native_helpers else Helpers()
    namespace, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    ui = new_ui(namespace)
    ui.helpers = helpers
    checks, observations = {}, []
    errors = []

    def check(name, operation):
        try:
            checks[name] = bool(operation())
        except BaseException:
            checks[name] = False
            errors.append(name + '\n' + traceback.format_exc())

    def build(target_ui, template, payload):
        return target_ui.build_request_from_template(
            get_editor_message=lambda: template, helpers=helpers,
            csrf_manager=target_ui.csrfManager, incoming_payload1=payload)

    def body(result):
        if result is None:
            raise AssertionError(ui.customStatusArea.getText())
        return as_text(result).split('\r\n\r\n', 1)[1]

    template = java_bytes('POST /echo HTTP/1.1\r\nHost: demo\r\nContent-Length: 1\r\n\r\np4yl04dm4rk3r')
    binary = ''.join(chr(i) for i in range(256))
    with CapturedOutput():
        for name, value in [('jython_str', binary), ('jython_unicode', binary.decode('latin-1')),
                            ('java_byte_array', java_bytes(binary)),
                            ('java_string', String(binary.decode('latin-1'))),
                            ('bytearray', bytearray(range(256)))]:
            check(name + '_all_256_bytes', lambda value=value: body(build(ui, template, value)) == binary.decode('latin-1'))
        check('java_string_non_byte_unicode_rejected',
              lambda: build(ui, template, String(u'\u20ac')) is None)
        literal = "array('b', [65, -1])"
        check('array_repr_remains_literal_text', lambda: body(build(ui, template, literal)) == literal)
        check('java_byte_array_template_body', lambda: body(build(ui, java_bytes(
            'POST /echo HTTP/1.1\r\nHost: demo\r\n\r\n' + binary), 'X')) == binary.decode('latin-1'))
        ui.cookieManager.jar['sid'] = 'SYNTHETIC'
        check('native_binary_with_cookie_injection', lambda: body(ui.build_request_from_template(
            get_editor_message=lambda: template, helpers=helpers, cookie_manager=ui.cookieManager,
            auto_update_cookies=True, incoming_payload1=java_bytes(binary))) == binary.decode('latin-1'))
        class CountingHelpers(object):
            calls = 0
            def bytesToString(self, value):
                self.calls += 1
                return helpers.bytesToString(value)
        counter = CountingHelpers()
        check('java_array_uses_helper_conversion', lambda: namespace['_wire_text'](java_bytes(binary), counter)
              == binary.decode('latin-1') and counter.calls == 1)
        # Native returns from the custom function use the same explicit mapping.
        from source_harness import Field
        ui.custom_codeblock_status = True
        ui.customCodeArea = Field("from java.lang import String\nfrom jarray import array\n"
                                  "def custom_codeblock(a,b,c):\n"
                                  "    return array([0,-1], 'b'), String(u'\\u00ff'), None\n")
        check('native_custom_return_types', lambda: body(build(ui, template, 'X')) == u'\x00\xff')
        ui.custom_codeblock_status = False

        def check_bodylen_table():
            try:
                store = namespace['LogStore']()
                store.add('t', 'demo', 'GET', '/zero', 204, 1, 0, None)
                store.add('t', 'demo', 'GET', '/unknown', '', '', '', None)
                store.add('t', 'demo', 'GET', '/one', 200, 1, 1, None)
                model = namespace['LogTableModel'](store)
                model.rebuild()
                table = JTable(model)
                checks['swing_unknown_bodylen_is_blank'] = table.getValueAt(1, 7) is None
                checks['swing_zero_bodylen_is_zero'] = table.getValueAt(2, 7) == 0
                sorter = TableRowSorter(model)
                table.setRowSorter(sorter)
                sorter.toggleSortOrder(7)
                checks['swing_bodylen_sort_unknown_zero_one'] = [table.getValueAt(i, 7) for i in range(3)] == [None, 0, 1]
            except BaseException:
                checks['swing_bodylen_sort_unknown_zero_one'] = False
                errors.append(traceback.format_exc())

        SwingUtilities.invokeAndWait(check_bodylen_table)

        if native_helpers:
            baseline_path = os.path.join(ROOT, 'tests', 'stabilization', 'runtime', 'k02-baseline-source.py')
            baseline, old_raw = load_source(baseline_path)
            old_ui = new_ui(baseline)
            old_ui.helpers = helpers
            framing_cases = [
                ('shorter', 'Content-Length: 999\r\n', 'X'),
                ('longer', 'Content-Length: 1\r\n', 'LONGER' * 50),
                ('empty_explicit_length', 'Content-Length: 999\r\n', ''),
                ('empty_without_length', '', ''),
                ('bad_length', 'Content-Length: invalid\r\n', 'X'),
                ('duplicate_lengths', 'Content-Length: 1\r\nContent-Length: 999\r\n', 'XYZ'),
                ('chunked', 'Transfer-Encoding: chunked\r\n', '3\r\nABC\r\n0\r\n\r\n'),
                ('te_and_cl', 'Transfer-Encoding: chunked\r\nContent-Length: 999\r\n', '3\r\nABC\r\n0\r\n\r\n'),
            ]
            for name, headers, payload in framing_cases:
                wire = java_bytes('POST /echo HTTP/1.1\r\nHost: demo\r\n' + headers + '\r\np4yl04dm4rk3r')
                old_result, new_result = build(old_ui, wire, payload), build(ui, wire, payload)
                check('framing_parity_' + name, lambda: old_result is not None and new_result is not None
                      and as_text(old_result) == as_text(new_result))
                observations.append(dict(case=name,
                                         baseline_base64=encode(old_result), candidate_base64=encode(new_result)))
            checks['baseline_source_is_checkpoint'] = hashlib.sha256(old_raw).hexdigest() == '3bf88a21442683c6135895125aac49ac09bd52a31be13b9ff75daaf8fcdfb111'
    report = dict(kind='in-burp-real-helpers-no-traffic' if native_helpers else 'standalone-native-jython-fake-helpers',
                  source_sha256=hashlib.sha256(raw).hexdigest(), checks=checks,
                  passed=bool(checks) and all(checks.values()), errors=errors, framing=observations,
                  actual_burp_helpers=native_helpers, transport_callbacks_are_doubles=True,
                  http2_network_tested=False, python=sys.version,
                  java_version=str(System.getProperty('java.version')))
    executor = getattr(ui, '_custom_executor', None)
    if executor is not None:
        ui.close_custom_runtime()
        if executor.worker is not None:
            executor.worker.join(2)
    return report


def encode(value):
    import base64
    return base64.b64encode(as_text(value).encode('latin-1')) if value is not None else None


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
