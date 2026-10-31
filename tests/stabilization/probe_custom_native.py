# -*- coding: utf-8 -*-
"""K05 finite native/Jython/Swing checks, optionally with real Burp helpers.

No network. Long/infinite-code cases belong in an externally bounded JVM.
All probe executors are closed and their finite workers joined before returning.
"""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import time
import traceback
import unittest
from StringIO import StringIO

from javax.swing import JTable, JPanel, SwingUtilities
from javax.swing.table import TableRowSorter
from java.lang import System
from org.python.util import PythonInterpreter
from org.python.core import PySystemState, PyStringMap
from burp import IExtensionStateListener

from source_harness import ROOT, Helpers
from probe_template_native import load_source
from test_custom_executor import CustomTests, PASS


def run_checks(helpers=None):
    actual = helpers is not None
    helpers = helpers if actual else Helpers()
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    ns['_probe_threads'] = []
    checks, errors = {}, []
    class NativeCustom(CustomTests):
        @classmethod
        def setUpClass(cls):
            cls.ns = ns
        def setUp(self):
            CustomTests.setUp(self)
            self.ui.helpers = helpers
            self.executor.helpers = helpers
    stream = StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(NativeCustom))
    checks['native_executor_regressions'] = result.wasSuccessful()
    if not result.wasSuccessful():
        errors.append(stream.getvalue())
    checks['extension_state_listener_interface'] = isinstance(ns['BurpExtender'](), IExtensionStateListener)

    # Independent Python interpreters in one JVM must share the gate.
    peers = []
    try:
        for _ in range(2):
            interpreter = PythonInterpreter(PyStringMap(), PySystemState())
            peers.append(interpreter)
            interpreter.set('probe_path', os.path.join(ROOT, 'tests', 'stabilization'))
            interpreter.exec('import sys\nsys.path.insert(0, probe_path)\n'
                             'from source_harness import load_namespace, Helpers\n'
                             'scope = load_namespace()\nexecutor = scope["CustomExecutor"](Helpers())\n')
        first, second = peers
        first.set('code', 'import time\ntime.sleep(0.25)\n' + PASS)
        first.exec('job=executor.submit(code, 2000, ("ONE","TWO","TOKEN"))\n')
        end = time.time() + 2
        while time.time() < end and not bool(first.eval('executor.state()["active"]')):
            time.sleep(0.001)
        first.exec('executor.close()')
        second.set('code', PASS)
        second.exec('blocked=executor.wait(executor.submit(code, 2000, ("ONE","TWO","TOKEN")))')
        checks['cross_interpreter_reload_keeps_old_worker_capacity'] = 'CUSTOM_BUSY' in str(second.get('blocked'))
        first.exec('executor.worker.join(2)')
        second.exec('resumed=executor.wait(executor.submit(code, 2000, ("ONE","TWO","TOKEN")))')
        checks['cross_interpreter_recovery_after_natural_finish'] = bool(second.eval('resumed[0]'))
    except BaseException:
        checks['cross_interpreter_lifecycle'] = False
        errors.append(traceback.format_exc())
    finally:
        for interpreter in peers:
            try:
                interpreter.exec('executor.close()\nif executor.worker is not None: executor.worker.join(2)')
                interpreter.close()
            except BaseException:
                errors.append(traceback.format_exc())

    class Editor(object):
        def getMessage(self):
            return None
        def getComponent(self):
            return JPanel()
    class Callbacks(object):
        def getHelpers(self):
            return helpers
        def createMessageEditor(self, *args):
            return Editor()

    current = []
    def configure():
        cb = Callbacks()
        ui = ns['LoggerUI'](cb, ns['SimpleMessageController'](), None, cb)
        current.append(ui)
        ui.useCustomChk.doClick(0)
        ui.customCodeArea.setText('import time\ntime.sleep(0.40)\n' + PASS)
        ui.timeoutField.setText('1500')
        start = time.time()
        ui.testCodeBtn.doClick(0)
        checks['test_action_returns_before_custom_finishes'] = time.time() - start < 0.25
        state = ui._custom_executor.state()
        checks['test_uses_existing_executor'] = state['active'] or state['pending']

    def ui_call(operation):
        failures = []
        def invoke():
            try:
                operation()
            except BaseException:
                failures.append(traceback.format_exc())
        SwingUtilities.invokeAndWait(invoke)
        if failures:
            raise RuntimeError('\n'.join(failures))

    def wait_ui(predicate, timeout=3):
        end = time.time() + timeout
        while time.time() < end:
            values = []
            ui_call(lambda: values.append(predicate()))
            if values[0]:
                return True
            time.sleep(0.01)
        return False

    try:
        ui_call(configure)
        ui = current[0]
        state = []
        ui_call(lambda: state.append(ui._custom_executor.state()['active']))
        checks['edt_responds_while_custom_runs'] = bool(state and state[0])
        checks['test_success_published_on_edt'] = wait_ui(lambda: ui.customStatusArea.getText().startswith('Test OK!'))
        def timeout_test():
            ui.customCodeArea.setText('import time\ntime.sleep(0.20)\n' + PASS)
            ui.timeoutField.setText('50')
            ui.testCodeBtn.doClick(0)
        ui_call(timeout_test)
        checks['test_top_level_timeout_visible'] = wait_ui(lambda: 'CUSTOM_TIMEOUT' in ui.customStatusArea.getText())
        time.sleep(0.25)
        ui_call(lambda: checks.update(late_test_result_not_published='CUSTOM_TIMEOUT' in ui.customStatusArea.getText()))
        def edit_test():
            ui.timeoutField.setText('1500')
            ui.testCodeBtn.doClick(0)
            ui.customCodeArea.setText(PASS)
        ui_call(edit_test)
        checks['edited_settings_discard_old_test_output'] = wait_ui(lambda: 'discarded' in ui.customStatusArea.getText())
        def close_test():
            ui.customCodeArea.setText('import time\ntime.sleep(0.20)\n' + PASS)
            ui.testCodeBtn.doClick(0)
            extension = ns['BurpExtender']()
            extension.ui = ui
            extension.extensionUnloaded()
            ui.customStatusArea.setText('UNLOADED_SENTINEL')
        ui_call(close_test)
        ui._custom_executor.worker.join(2)
        ui_call(lambda: ui._log('LATE_WORKFLOW_OUTPUT'))
        ui_call(lambda: checks.update(unload_stops_timer=ui._custom_test_timer is None,
                                     unload_cannot_publish_test_output=ui.customStatusArea.getText() == 'UNLOADED_SENTINEL'))
    except BaseException:
        checks['native_swing_test_flow'] = False
        errors.append(traceback.format_exc())
    finally:
        for ui in current:
            ui_call(ui.close_custom_runtime)
            if ui._custom_executor.worker is not None:
                ui._custom_executor.worker.join(2)
    return dict(kind='K05-finite-native-Jython-Swing-no-network', actual_burp_helpers=actual,
                source_sha256=hashlib.sha256(raw).hexdigest(), checks=checks, errors=errors,
                passed=bool(checks) and all(checks.values()) and not errors,
                executor_cases=result.testsRun, executor_log=stream.getvalue(),
                python=sys.version, java_version=str(System.getProperty('java.version')),
                message_editors_are_doubles=True, guaranteed_hard_stop=False)


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
