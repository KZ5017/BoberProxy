# -*- coding: utf-8 -*-
"""Disposable standalone JVM only: reproduce shared RSTA action/keymap caches."""
from __future__ import print_function
import argparse
import json
import os
from javax.swing import SwingUtilities, KeyStroke, Action, UIManager
from javax.swing.text import DefaultEditorKit, JTextComponent
from java.awt.event import ActionEvent
from java.net import URLClassLoader
from java.lang import ClassLoader, Throwable
from java.io import File


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    parser.add_argument('--isolate-keys', action='store_true')
    args = parser.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    isolate = None
    if args.isolate_keys:
        from probe_template_native import load_source
        namespace, raw = load_source(os.path.join(root, 'BoberProxy.py'))
        isolate = namespace['_code_editor_local_keys']
    url = File(os.path.join(root, 'lib', 'rsyntaxtextarea-3.6.3.jar')).toURI().toURL()
    loaders, editors, observations, errors = [], [], [], []
    def examine():
        for index in range(2):
            loader = URLClassLoader([url], ClassLoader.getSystemClassLoader())
            loaders.append(loader)
            editor = loader.loadClass('org.fife.ui.rsyntaxtextarea.RSyntaxTextArea').newInstance()
            editors.append(editor)
            editor.setTabsEmulated(True); editor.setTabSize(4)
            action = editor.getActionMap().get(editor.getInputMap().get(KeyStroke.getKeyStroke('TAB')))
            action.actionPerformed(ActionEvent(editor, 1001, 'probe'))
            observation = dict(index=index, text_after_cached_tab=unicode(editor.getText()),
                action_from_editor_loader=action.getClass().getClassLoader() == editor.getClass().getClassLoader())
            editor.setText('')
            own = dict((unicode(a.getValue(Action.NAME)), a) for a in editor.getActions())
            own['insert-tab'].actionPerformed(ActionEvent(editor, 1001, 'probe'))
            observation['text_after_own_tab'] = unicode(editor.getText())
            editor.setText('')
            editor.getKeymap().getDefaultAction().actionPerformed(ActionEvent(editor, 1001, 'x'))
            observation['text_after_cached_typing'] = unicode(editor.getText())
            observation['own_default_action_present'] = DefaultEditorKit.defaultKeyTypedAction in own
            if isolate is not None:
                shared_keymap = JTextComponent.getKeymap('RTextAreaKeymap')
                shared_actions = UIManager.get('RSyntaxTextAreaUI.actionMap')
                isolate(editor)
                editor.setText('')
                fixed = editor.getActionMap().get(editor.getInputMap().get(KeyStroke.getKeyStroke('TAB')))
                fixed.actionPerformed(ActionEvent(editor, 1001, 'probe'))
                observation['isolated_tab'] = unicode(editor.getText())
                editor.setText('')
                editor.getKeymap().getDefaultAction().actionPerformed(ActionEvent(editor, 1001, 'x'))
                observation['isolated_typing'] = unicode(editor.getText())
                observation['shared_maps_unchanged'] = (shared_keymap is JTextComponent.getKeymap('RTextAreaKeymap')
                    and shared_actions is UIManager.get('RSyntaxTextAreaUI.actionMap'))
            observations.append(observation)
    try:
        SwingUtilities.invokeAndWait(examine)
    except (BaseException, Throwable) as error:
        errors.append(str(error))
    finally:
        for loader in loaders: loader.close()
    report = dict(kind='UI03-isolated-classloader-keymap-characterization', observations=observations,
                  isolated_keys=args.isolate_keys,
                  errors=errors, network_requests=0,
                  note='Standalone disposable JVM only; no user Burp UI/defaults are touched.')
    report['passed'] = not errors and len(observations) == 2 and (not args.isolate_keys or all(
        row.get('isolated_tab') == '    ' and row.get('isolated_typing') == 'x'
        and row.get('shared_maps_unchanged') for row in observations))
    with open(args.report, 'w') as handle: json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
