# -*- coding: utf-8 -*-
"""Finite code-editor/packaging checks; private instances, never network traffic."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import traceback
from javax.swing import SwingUtilities
from javax import swing
from java.awt.event import ActionEvent
from java.lang import Throwable
from org.python.util import PythonInterpreter
from org.python.core import Py, PySystemState, PyStringMap
from source_harness import ROOT
from probe_template_native import load_source
from probe_logging_native import NativeHelpers
from probe_ui02_native import run_checks as layout_checks


def run_checks(actual_callbacks=None, preview=None):
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    original_state = Py.getSystemState()
    checks, errors, owned, peers = {}, [], [], []
    helpers = actual_callbacks.getHelpers() if actual_callbacks else NativeHelpers()
    dimensions, key_observations, test_observation = {}, [], {}
    def edt(operation):
        failures = []
        def invoke():
            try: operation()
            except (BaseException, Throwable): failures.append(traceback.format_exc())
        if swing.SwingUtilities.isEventDispatchThread(): invoke()
        else: swing.SwingUtilities.invokeAndWait(invoke)
        if failures: raise AssertionError('\n'.join(failures))
    class Editor(object):
        def __init__(self): self.value = helpers.stringToBytes('')
        def getMessage(self): return self.value
        def setMessage(self, value, request): self.value = value
        def getComponent(self): return swing.JPanel()
    class Callbacks(object):
        def getHelpers(self): return helpers
        def createMessageEditor(self, controller, editable):
            return actual_callbacks.createMessageEditor(controller, editable) if actual_callbacks else Editor()
    def create():
        ui = ns['LoggerUI'](Callbacks(), ns['SimpleMessageController']())
        owned.append(ui)
        return ui
    def key(editor, stroke):
        binding = editor.getInputMap().get(swing.KeyStroke.getKeyStroke(stroke))
        action = editor.getActionMap().get(binding)
        if action is None: raise AssertionError('Missing editor key binding: ' + stroke)
        observation = dict(stroke=stroke, binding=unicode(binding), action_class=str(type(action)),
                           action_enabled=bool(action.isEnabled()), editor_enabled=bool(editor.isEnabled()),
                           editor_editable=bool(editor.isEditable()), editor_showing=bool(editor.isShowing()),
                           text_before=unicode(editor.getText()))
        key_observations.append(observation)
        action.actionPerformed(ActionEvent(editor, ActionEvent.ACTION_PERFORMED, 'probe'))
        observation['text_after'] = unicode(editor.getText())
    def wait_ui(predicate):
        deadline = time.time() + 4
        while time.time() < deadline:
            values = []
            edt(lambda: values.append(predicate()))
            if values[0]: return True
            time.sleep(0.02)
        return False
    try:
        checks['relative_jar_loaded'] = 'editor' in ns['CODE_EDITOR_SUPPORT']
        missing = ns['_load_code_editor_support'](os.path.join(ROOT, 'tests', 'missing', 'BoberProxy.py'))
        checks['missing_jar_detected_even_after_class_import'] = missing.get('error') == 'CODE_EDITOR_JAR_MISSING'
        temp = tempfile.mkdtemp(prefix='boberproxy-ui03-')
        lib = os.path.join(temp, 'lib'); os.mkdir(lib)
        corrupt = os.path.join(lib, ns['CODE_EDITOR_JAR'])
        try:
            with open(corrupt, 'wb') as handle: handle.write(b'not a JAR')
            result = ns['_load_code_editor_support'](os.path.join(temp, 'BoberProxy.py'))
            checks['corrupt_jar_detected'] = result.get('error') == 'CODE_EDITOR_LOAD_FAILED'
        finally:
            os.remove(corrupt); os.rmdir(lib); os.rmdir(temp)
        def trial():
            before_map = swing.UIManager.get('TextArea.focusInputMap')
            ui = create()
            checks['enhanced_editor_and_gutter'] = ui._code_editor_enhanced and ui.customCodeScroll.getLineNumbersEnabled()
            checks['python_style'] = ui.customCodeArea.getSyntaxEditingStyle() == 'text/python'
            checks['four_space_tabs_and_autoindent'] = (ui.customCodeArea.getTabsEmulated()
                and ui.customCodeArea.getTabSize() == 4 and ui.customCodeArea.isAutoIndentEnabled())
            checks['no_folding_or_extra_parser'] = not ui.customCodeArea.isCodeFoldingEnabled() and ui.customCodeArea.getParserCount() == 0
            size = ui.customCodeScroll.getPreferredSize()
            dimensions.update(enhanced_width=ui._sidebar_width, editor_width=size.width, editor_height=size.height)
            original = ns['CODE_EDITOR_SUPPORT']
            try:
                ns['CODE_EDITOR_SUPPORT'] = missing
                fallback = create()
            finally: ns['CODE_EDITOR_SUPPORT'] = original
            old = fallback.customCodeScroll.getPreferredSize()
            checks['same_outer_size_as_plain_editor'] = (old == size and fallback._sidebar_width == ui._sidebar_width)
            checks['fallback_visible_and_usable'] = (not fallback._code_editor_enhanced
                and 'CODE_EDITOR_JAR_MISSING' in fallback.customStatusArea.getText())
            ui.useCustomChk.doClick(0)
            code = u'# comment \u00e9 \u20ac\n\ndef custom_codeblock(a, b, c):\n\treturn a, b, c\n'
            ui.customCodeArea.setText(code)
            ui.customCodeArea.discardAllEdits()
            checks['paste_and_snapshot_exact'] = ui.customCodeArea.getText() == code and ui._capture_custom_settings()[1] == code
            version = ui._custom_version
            ui._on_custom_settings_changed()
            checks['unchanged_text_does_not_invalidate_snapshot'] = ui._custom_version == version
            ui.customCodeArea.append('# new')
            ui.customCodeArea.undoLastAction()
            checks['undo_exact'] = ui.customCodeArea.getText() == code
            ui.customCodeArea.redoLastAction()
            checks['redo_exact'] = ui.customCodeArea.getText() == code + '# new'
            ui.customCodeArea.setText('')
            ui.customCodeArea.getKeymap().getDefaultAction().actionPerformed(
                ActionEvent(ui.customCodeArea, ActionEvent.ACTION_PERFORMED, 'x'))
            checks['typed_character_input'] = ui.customCodeArea.getText() == 'x'
            ui.customCodeArea.setText('')
            key(ui.customCodeArea, 'TAB')
            checks['tab_inserts_four_spaces'] = ui.customCodeArea.getText() == '    '
            ui.customCodeArea.setText('    value = 1')
            ui.customCodeArea.setCaretPosition(ui.customCodeArea.getDocument().getLength())
            key(ui.customCodeArea, 'ENTER')
            checks['enter_preserves_indentation'] = ui.customCodeArea.getText() == '    value = 1\n    '
            ui.resetBtn.doClick(0)
            checks['reset_exact'] = ui.customCodeArea.getText() == ui.default_code_text
            ui.timeoutField.setText('2000')
            ui.testCodeBtn.doClick(0)
            test_observation['version_after_submit'] = ui._custom_version
            checks['standard_textarea_keys_unchanged'] = swing.UIManager.get('TextArea.focusInputMap') is before_map
        edt(trial)
        ui = owned[0]
        checks['test_uses_existing_custom_executor'] = wait_ui(lambda: ui.customStatusArea.getText().startswith('Test OK!'))
        edt(lambda: test_observation.update(result_text=unicode(ui.customStatusArea.getText()),
                                            current_version=ui._custom_version,
                                            executor_state=ui._custom_executor.state()))
        edt(lambda: ui.useCustomChk.doClick(0))
        checks['disable_editing_preserves_code'] = not ui.customCodeArea.isEnabled() and ui.customCodeArea.getText() == ui.default_code_text
        # Independent Jython states reproduce extension reload/classloader keymap sharing.
        for _ in range(0 if actual_callbacks else 2):
            peer = PythonInterpreter(PyStringMap(), PySystemState()); peers.append(peer)
            peer.set('jar_path', ns['CODE_EDITOR_SUPPORT']['jar'])
            peer.exec('import sys\nsys.path.append(jar_path)\n'
                      'from org.fife.ui.rsyntaxtextarea import RSyntaxTextArea, SyntaxConstants\n'
                      'from javax.swing import SwingUtilities\n'
                      'from java.awt.event import ActionEvent\n'
                      'editors=[]\n'
                      'def check_keys():\n'
                      '    editor=RSyntaxTextArea(10,28)\n'
                      '    editor.setTabsEmulated(True)\n'
                      '    editor.setTabSize(4)\n'
                      '    binding=editor.getInputMap().get(__import__("javax.swing",fromlist=["KeyStroke"]).KeyStroke.getKeyStroke("TAB"))\n'
                      '    editor.getActionMap().get(binding).actionPerformed(ActionEvent(editor,1001,"probe"))\n'
                      '    editors.append(editor)\n'
                      'SwingUtilities.invokeAndWait(check_keys)\n')
            checks['independent_interpreter_%d' % len(peers)] = bool(peer.eval('editors[0].getText()=="    "'))
    except (BaseException, Throwable): errors.append(traceback.format_exc())
    finally:
        for peer in peers: peer.close()
        if peers:
            Py.setSystemState(original_state)
            edt(lambda: Py.setSystemState(original_state))
        for ui in owned: ui.close_custom_runtime()
        edt(lambda: None)
        for ui in owned:
            for owner in (ui._custom_executor, ui._filter_worker, ui._log_writer, ui._log_io):
                if owner.worker is not None: owner.worker.join(5)
    regression = layout_checks(actual_callbacks, preview=preview, expected_line='BoberProxy loaded (UI03)')
    jar_path = os.path.join(ROOT, 'lib', 'rsyntaxtextarea-3.6.3.jar')
    with open(jar_path, 'rb') as handle: jar_sha256 = hashlib.sha256(handle.read()).hexdigest()
    return dict(kind='UI03-private-code-editor-no-network', checks=checks, errors=errors,
                dimensions=dimensions, key_observations=key_observations, test_observation=test_observation,
                regression=regression, source_sha256=hashlib.sha256(raw).hexdigest(),
                jar_sha256=jar_sha256, jar_version='3.6.3', actual_burp_helpers=bool(actual_callbacks),
                network_requests=0, passed=bool(checks) and all(checks.values()) and not errors and regression['passed'])


def summary(report):
    return 'UI03_EDITOR %s (%d editor cases; 18 layout; 10 cleanup/UI; 24 logging)' % (
        'PASS' if report['passed'] else 'FAIL', len(report['checks']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    parser.add_argument('--preview')
    args = parser.parse_args()
    report = run_checks(preview=args.preview)
    with open(args.report, 'w') as handle: json.dump(report, handle, indent=2)
    print(summary(report))
    if not report['passed']: print(json.dumps(report, indent=2))
    sys.exit(0 if report['passed'] else 1)
