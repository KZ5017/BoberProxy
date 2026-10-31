# -*- coding: utf-8 -*-
"""Finite K05 capacity, deadline, frozen source and lifecycle regressions."""
from __future__ import print_function

import os
import tempfile
import time
import unittest

from source_harness import Field, as_bytes, as_text, Callbacks
from test_source_logic import SourceCase


PASS = 'def custom_codeblock(a,b,c):\n    return a,b,c\n'
SLOW = 'import time\ntime.sleep(0.20)\n' + PASS


class CustomTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.extra = []
        self.paths = []
        self.executor = self.ui._custom_executor

    def tearDown(self):
        for executor in self.extra:
            executor.close()
            if executor.worker is not None:
                executor.worker.join(2)
        SourceCase.tearDown(self)
        for path in self.paths:
            os.unlink(path)

    def file(self):
        fd, path = tempfile.mkstemp(prefix='bober-k05-')
        os.close(fd)
        self.paths.append(path)
        return path

    def active(self, executor=None):
        executor = executor or self.executor
        end = time.time() + 2
        while time.time() < end:
            if executor.state()['active']:
                return
            time.sleep(0.001)
        self.fail('Finite custom probe did not start')

    def idle(self):
        end = time.time() + 2
        while time.time() < end:
            if not self.executor.state()['active'] and not self.executor.state()['pending']:
                return
            time.sleep(0.001)
        self.fail('Finite custom probe did not finish')

    def submit(self, code=PASS, timeout=2000, executor=None):
        return (executor or self.executor).submit(code, timeout, ('ONE', 'TWO', 'TOKEN'))

    def test_default_and_timeout_validation(self):
        validate = self.ns['_custom_timeout']
        for value, expected in [(1, 1), (500, 500), (30000, 30000), ('1', 1),
                                ('500', 500), (' 30000 ', 30000), ('+500', 500),
                                ('0' * 5000 + '500', 500)]:
            self.assertEqual(validate(value), expected)
        for value in (0, -1, 30001, '', 'NaN', 'inf', '1.5', '1e3', '9' * 5000, True, 2.0, None):
            with self.assertRaises(ValueError):
                validate(value)
            result = self.executor.wait(self.submit(timeout=value))
            self.assertFalse(result[0])
            self.assertIn('CUSTOM_CONFIG_ERROR', result[2])
        self.assertIsNone(self.executor.worker, 'Invalid settings must not create a worker')

    def test_one_active_one_waiting_then_busy(self):
        first = self.submit(SLOW)
        self.active()
        second = self.submit()
        third = self.submit()
        self.assertTrue(self.executor.state()['pending'])
        self.assertIn('CUSTOM_BUSY', self.executor.wait(third)[2])
        self.assertTrue(self.executor.wait(first)[0])
        self.assertTrue(self.executor.wait(second)[0])
        worker = self.executor.worker
        self.assertTrue(self.executor.wait(self.submit())[0])
        self.assertIs(self.executor.worker, worker)

    def test_queue_time_counts_and_expired_job_never_executes(self):
        path = self.file()
        first = self.submit(SLOW)
        self.active()
        code = 'with open(%r,"a") as trace:\n    trace.write("SIDE_EFFECT")\n' % path + PASS
        queued = self.submit(code, timeout=30)
        self.assertIn('CUSTOM_TIMEOUT', self.executor.wait(queued)[2])
        self.assertTrue(self.executor.wait(first)[0])
        self.assertTrue(self.executor.wait(self.submit())[0])
        with open(path) as handle:
            self.assertEqual(handle.read(), '')

    def test_late_top_level_cannot_proceed_to_function_or_replace_worker(self):
        path = self.file()
        source = 'import time\ntime.sleep(0.15)\ndef custom_codeblock(a,b,c):\n    with open(%r,"a") as trace:\n        trace.write("LATE")\n    return a,b,c\n' % path
        job = self.submit(source, timeout=40)
        self.assertIn('CUSTOM_TIMEOUT', self.executor.wait(job)[2])
        worker = self.executor.worker
        for _ in range(8):
            self.assertIn('CUSTOM_BUSY', self.executor.wait(self.submit())[2])
            self.assertIs(self.executor.worker, worker)
        self.idle()
        with open(path) as handle:
            self.assertEqual(handle.read(), '')
        self.assertTrue(self.executor.wait(self.submit())[0])
        self.assertIs(self.executor.worker, worker)

    def test_late_function_result_is_discarded(self):
        source = 'import time\ndef custom_codeblock(a,b,c):\n    time.sleep(0.15)\n    return "LATE",b,c\n'
        job = self.submit(source, timeout=40)
        result = self.executor.wait(job)
        self.assertFalse(result[0])
        self.idle()
        self.assertEqual(self.executor.poll(job), result)
        self.assertIsNone(result[1])

    def test_close_resolves_waiters_and_prevents_reload_worker_accumulation(self):
        active = self.submit(SLOW)
        self.active()
        queued = self.submit()
        self.executor.close()
        self.assertIn('CUSTOM_CLOSED', self.executor.wait(active)[2])
        self.assertIn('CUSTOM_CLOSED', self.executor.wait(queued)[2])
        replacement = self.ns['CustomExecutor'](self.ui.helpers)
        self.extra.append(replacement)
        self.assertIn('CUSTOM_BUSY', replacement.wait(self.submit(executor=replacement))[2])
        self.executor.worker.join(2)
        self.assertTrue(replacement.wait(self.submit(executor=replacement))[0])

    def test_idle_close_terminates_worker_and_rejects_new_jobs(self):
        self.assertTrue(self.executor.wait(self.submit())[0])
        self.executor.close()
        self.executor.worker.join(2)
        self.assertFalse(self.executor.worker.is_alive())
        self.assertIn('CUSTOM_CLOSED', self.executor.wait(self.submit())[2])

    def test_compile_cache_does_not_cache_namespace_or_skip_top_level(self):
        path = self.file()
        source = ('with open(%r,"a") as trace:\n    trace.write("TOP\\n")\n'
                  'seen = globals().get("seen", 0) + 1\n'
                  'def custom_codeblock(a,b,c):\n    return str(seen),b,c\n') % path
        first = self.executor.wait(self.submit(source))
        compiled = self.executor._cached_code
        second = self.executor.wait(self.submit(source))
        self.assertEqual(first[1][0], '1')
        self.assertEqual(second[1][0], '1')
        self.assertIs(self.executor._cached_code, compiled)
        with open(path) as handle:
            self.assertEqual(handle.read(), 'TOP\nTOP\n')

    def test_python_base_exception_cannot_kill_worker(self):
        job = self.submit('raise SystemExit("CONTROLLED")\n' + PASS)
        self.assertIn('CONTROLLED', self.executor.wait(job)[2])
        self.assertTrue(self.executor.wait(self.submit())[0])

    def test_unicode_editor_source_allows_encoding_cookie_and_explicit_utf8(self):
        code = u'# -*- coding: utf-8 -*-\n' + u'def custom_codeblock(a,b,c):\n    return u"\u20ac".encode("utf-8"),b,c\n'
        result = self.executor.wait(self.submit(code))
        self.assertTrue(result[0], result[2])
        self.assertEqual(result[1][0], u'\xe2\x82\xac')

    def test_exception_text_cannot_kill_worker(self):
        for code, expected in [(u'def custom_codeblock(a,b,c):\n    raise ValueError(u"\u0151")\n', u'\u0151'),
                ('class Broken(Exception):\n    def __str__(self):\n        raise ValueError("BROKEN_STR")\n'
                 'def custom_codeblock(a,b,c):\n    raise Broken()\n', 'Broken')]:
            result = self.executor.wait(self.submit(code))
            self.assertFalse(result[0])
            self.assertIn(expected, result[2])
            self.assertTrue(self.executor.wait(self.submit())[0])

    def test_workflow_freezes_source_timeout_and_enabled_state_for_both_calls(self):
        self.ui.custom_codeblock_status = True
        self.ui.customCodeArea = Field('def custom_codeblock(a,b,c):\n    return "A"+a,b,c\n')
        self.ui.timeoutField = Field('2000')
        self.ui.useCheckPageTemplate = True
        ui = self.ui
        class EditingCallbacks(Callbacks):
            def makeHttpRequest(self, *args):
                ui.customCodeArea.setText('raise ValueError("NEW_CODE_MUST_NOT_RUN")')
                ui.timeoutField.setText('INVALID')
                ui.custom_codeblock_status = False
                return Callbacks.makeHttpRequest(self, *args)
        ui.callbacks = EditingCallbacks()
        result = ui.proxy_flow_process_request(as_bytes('GET /entry?q=ONE&w=TWO HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].READY)
        self.assertIn('one=AONE', as_text(result.request_bytes))
        self.assertIn('one=AONE', as_text(ui.callbacks.calls[0][1]))

    def test_invalid_ui_timeout_is_visible_pre_send_error(self):
        self.ui.custom_codeblock_status = True
        self.ui.customCodeArea = Field(PASS)
        self.ui.timeoutField = Field('bad')
        result = self.ui.proxy_flow_process_request(as_bytes('GET /entry?q=ONE HTTP/1.1\r\nHost: demo\r\n\r\n'), 'demo', 80, False)
        self.assertEqual(result.status, self.ns['ProxyWorkflowResult'].ERROR_BEFORE_SEND)
        self.assertIn('CUSTOM_CONFIG_ERROR', result.error_detail)
        self.assertEqual(self.ui.callbacks.calls, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
