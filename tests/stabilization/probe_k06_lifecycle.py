# -*- coding: utf-8 -*-
"""E56 K06 subset: repeated EDT publishers and finite custom jobs in one JVM."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import threading
import traceback
from javax.swing import JTable, JPanel, SwingUtilities
from javax.swing.table import TableRowSorter
from java.lang import Thread
from source_harness import ROOT, Helpers
from probe_template_native import load_source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    cycles, errors = [], []
    class Editor(object):
        def getComponent(self):
            return JPanel()
        def getMessage(self):
            return None
    class Callbacks(object):
        def getHelpers(self):
            return Helpers()
        def createMessageEditor(self, *args):
            return Editor()
        def setExtensionName(self, name):
            pass
        def registerExtensionStateListener(self, listener):
            pass
        def addSuiteTab(self, ui):
            pass
        def registerHttpListener(self, listener):
            pass
        def registerProxyListener(self, listener):
            pass
        def printError(self, text):
            errors.append(str(text))
    def edt(operation):
        failures = []
        def run():
            try:
                operation()
            except BaseException:
                failures.append(traceback.format_exc())
        SwingUtilities.invokeAndWait(run)
        if failures:
            raise AssertionError('\n'.join(failures))
    current = None
    try:
        for index in range(8):
            current = ns['BurpExtender']()
            current.registerExtenderCallbacks(Callbacks())
            edt(lambda: None)
            ui = current.ui
            if ui is None:
                raise AssertionError('Missing UI')
            timed = index % 2 == 1
            entered, release = threading.Event(), threading.Event()
            code = ('def custom_codeblock(a,b,c):\n    a.set()\n'
                    '    b.wait(0.35)\n    return "ONE","TWO",None\n')
            executor = ui._custom_executor
            job = executor.submit(code, 200 if timed else 2000, (entered, release, None))
            if not entered.wait(2):
                raise AssertionError('Finite custom job never started')
            if not timed:
                release.set()
            result = executor.wait(job)
            active = len([t for t in Thread.getAllStackTraces().keySet()
                if t.getThreadGroup() is not None and t.getThreadGroup().getName() == ns['CUSTOM_GATE_NAME']])
            current.extensionUnloaded()
            version = ui._capture_runtime().version
            edt(lambda: None)
            edt(lambda: ui._log('LATE K06 LIFECYCLE OUTPUT'))
            if executor.worker is not None:
                executor.worker.join(2)
            row = dict(cycle=index, timed=timed,
                expected_job_outcome=('CUSTOM_TIMEOUT' in result[2]) if timed else result[0],
                publisher_stopped=not ui._runtime_publisher.timer.isRunning(),
                listeners_detached=not ui._runtime_publisher.documents and not ui._runtime_publisher.items,
                coordinator_closed=ui.sessions.closed,
                snapshot_not_republished=ui._capture_runtime().version == version,
                no_replacement_or_accumulation=active == 1,
                finite_worker_finished=not executor.worker.is_alive())
            row['passed'] = all(value for key, value in row.items() if key not in ('cycle','timed'))
            cycles.append(row)
    except BaseException:
        errors.append(traceback.format_exc())
    finally:
        if current is not None:
            current.extensionUnloaded()
            edt(lambda: None)
    report = dict(kind='standalone-K06-repeated-lifecycle-no-network', cycles=cycles,
                  source_sha256=hashlib.sha256(raw).hexdigest(), errors=errors,
                  passed=len(cycles) == 8 and all(row['passed'] for row in cycles) and not errors,
                  scope='Eight private source instances; four finite successes and four timeouts. No infinite code or live Burp setting changes.')
    with open(args.report, 'w') as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
