# -*- coding: utf-8 -*-
"""Standalone wrapper lifecycle/command smoke; no sockets or visible tab."""
from __future__ import print_function
import argparse
import json
import os
import time
import traceback
from javax.swing import JTable, JPanel, SwingUtilities
from javax.swing.table import TableRowSorter
from source_harness import ROOT, Helpers
from burp_k06_instrumented import BurpExtender


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    checks, errors = {}, []
    class Editor(object):
        def __init__(self):
            self.message = None
        def getComponent(self):
            return JPanel()
        def getMessage(self):
            return self.message
        def setMessage(self, message, is_request):
            self.message = message
    class Callbacks(object):
        def getExtensionFilename(self):
            return os.path.join(ROOT, 'tests', 'stabilization', 'burp_k06_instrumented.py')
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
        def printOutput(self, text):
            print(text)
        def printError(self, text):
            errors.append(str(text))
    wrapper = BurpExtender()
    try:
        wrapper.registerExtenderCallbacks(Callbacks())
        SwingUtilities.invokeAndWait(lambda: None)
        checks['main_ui_created_on_edt'] = wrapper.main.ui._creation_on_edt
        def command(action):
            command = dict(instance=wrapper.instance, id=action, action=action)
            with open(wrapper.command_path, 'w') as handle:
                json.dump(command, handle)
            end = time.time() + 3
            while time.time() < end:
                try:
                    with open(wrapper.ack_path) as handle:
                        ack = json.load(handle)
                    if ack.get('instance') == wrapper.instance and ack.get('id') == action:
                        if not ack.get('ok'):
                            raise AssertionError(ack.get('error'))
                        return ack['state']
                except (IOError, ValueError):
                    pass
                time.sleep(0.01)
            raise AssertionError('File command not acknowledged: ' + action)
        state = command('setup')
        checks['setup_via_edt_command'] = all(state[k] for k in ('proxy','use_cp','cookies','csrf_enabled'))
        checks['setup_both_exact_templates'] = ('/k06/action?' in wrapper.main.ui._capture_runtime().get('rt')
            and '/k06/check?' in wrapper.main.ui._capture_runtime().get('cp'))
        checks['clear_cookies_epoch'] = command('clear-cookies')['epoch'] == state['epoch'] + 1
        checks['clear_csrf_epoch'] = command('clear-csrf')['epoch'] == state['epoch'] + 2
        changed = command('change')
        checks['all_settings_change_published'] = not any(changed[k] for k in ('proxy','use_cp','cookies','csrf_enabled'))
        checks['changed_config_has_new_version'] = changed['version'] > state['version']
        closed = command('unload')
        checks['source_unload_closes_runtime'] = closed['closed']
        SwingUtilities.invokeAndWait(lambda: None)
        checks['source_unload_stops_timer'] = not wrapper.main.ui._runtime_publisher.timer.isRunning()
    except BaseException:
        checks['wrapper_smoke'] = False
        errors.append(traceback.format_exc())
    finally:
        if hasattr(wrapper, 'main'):
            wrapper.main.extensionUnloaded()
            wrapper.control_thread.join(2)
            SwingUtilities.invokeAndWait(lambda: None)
            checks['actual_unload_stops_control_thread'] = not wrapper.control_thread.is_alive()
    report = dict(kind='standalone-K06-test-wrapper-no-network', checks=checks, errors=errors,
                  passed=bool(checks) and all(checks.values()) and not errors,
                  source_sha256=getattr(wrapper, 'hash', None))
    with open(args.report, 'w') as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
