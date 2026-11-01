# -*- coding: utf-8 -*-
"""UI02 status-bar geometry and native-button delegation on private instances."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import traceback
from javax.swing import SwingUtilities, JPanel, JButton, JMenuItem, UIManager
from java.lang import Throwable
from source_harness import ROOT
from probe_template_native import load_source
from probe_logging_native import NativeHelpers
from probe_cleanup_native import run_checks as cleanup_checks


def run_checks(actual_callbacks=None, preview=None, expected_line='BoberProxy loaded (UI02)'):
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    checks, errors, dimensions, owned = {}, [], [], []
    helpers = actual_callbacks.getHelpers() if actual_callbacks else NativeHelpers()
    def edt(operation):
        failures = []
        def invoke():
            try: operation()
            except (BaseException, Throwable): failures.append(traceback.format_exc())
        if SwingUtilities.isEventDispatchThread(): invoke()
        else: SwingUtilities.invokeAndWait(invoke)
        if failures: raise AssertionError('\n'.join(failures))
    class Editor(object):
        def __init__(self): self.value = helpers.stringToBytes('')
        def getMessage(self): return self.value
        def setMessage(self, value, request): self.value = value
        def getComponent(self): return JPanel()
    class Callbacks(object):
        def getHelpers(self): return helpers
        def createMessageEditor(self, controller, editable):
            return actual_callbacks.createMessageEditor(controller, editable) if actual_callbacks else Editor()
    def layout(component):
        component.doLayout()
        if hasattr(component, 'getComponents'):
            for child in component.getComponents(): layout(child)
    def descendant(component, parent):
        while component is not None:
            if component is parent: return True
            component = component.getParent()
        return False
    def trial():
        ui = ns['LoggerUI'](Callbacks(), ns['SimpleMessageController']())
        owned.append(ui)
        root = ui.getUiComponent()
        checks['status_outside_sidebar'] = all(not descendant(label, ui.rightScroll)
            and descendant(label, ui.logPanel) for label in (ui.statusLabel, ui.filterStatusLabel))
        checks['labels_single_row'] = ui.statusLabel.getY() == ui.filterStatusLabel.getY()
        checks['clear_logging_caption'] = ui.statusLabel.getText() == 'Logging enabled'
        checks['checkpage_tab_spacing'] = ui.tabbed.getTitleAt(2) == 'CheckPage Template'
        checks['shortcut_not_a_fourth_tab'] = ui.tabbed.getTabCount() == 3
        checks['shortcut_trailing_property'] = ui.tabbed.getClientProperty('JTabbedPane.trailingComponent') is ui.proxySettingsToolbar
        bar_height = ui.statusBar.getPreferredSize().height
        for width, height in [(1000, 550), (1400, 900), (1850, 700)]:
            root.setSize(width, height)
            layout(root)
            dimensions.append(dict(width=width, height=height, bar_width=ui.statusBar.getWidth(),
                log_width=ui.logScroll.getWidth(), bar_height=ui.statusBar.getHeight(),
                label_y=[ui.statusLabel.getY(), ui.filterStatusLabel.getY()],
                toolbar_height=ui.proxySettingsToolbar.getHeight()))
        checks['bar_fixed_height_full_log_width'] = all(row['bar_height'] == bar_height
            and row['bar_width'] == row['log_width'] for row in dimensions)
        checks['bar_visible_when_sidebar_scrolls'] = dimensions[0]['bar_height'] > 0 and ui.statusBar.getParent() is ui.logPanel
        checks['toolbar_visible_in_flatlaf'] = all(row['toolbar_height'] > 0 for row in dimensions)
        checks['one_row_at_each_size'] = all(row['label_y'][0] == row['label_y'][1] for row in dimensions)
        ui.set_status('Last operation ' * 200)
        ui._capture_error = 'Invalid expression ' * 200
        ui._filter_message()
        layout(root)
        checks['long_status_does_not_grow_bar'] = ui.statusBar.getHeight() == bar_height
        checks['full_messages_in_tooltips'] = (ui.statusLabel.getToolTipText() == ui.statusLabel.getText()
            and ui.filterStatusLabel.getToolTipText() == ui.filterStatusLabel.getText())
        ui._capture_error = None
        ui._filter_message()
        ui.pauseBtn.setSelected(True)
        ui.toggle_pause()
        checks['logging_pause_clear'] = ui.paused and ui.statusLabel.getText() == 'Logging paused'
        ui.pauseBtn.setSelected(False)
        ui.toggle_pause()
        checks['logging_resume_clear'] = not ui.paused and ui.statusLabel.getText() == 'Logging enabled'
        # Only synthetic controls receive clicks; never open real Burp settings here.
        parent, calls = JPanel(), []
        own = JButton('Proxy settings')
        own.setName('BoberProxy.proxySettings')
        menu = JMenuItem('Proxy settings')
        native = JButton('Proxy settings', actionPerformed=lambda event: calls.append(event.getSource()))
        parent.add(own); parent.add(menu); parent.add(native)
        parent.add(JButton(u'Unrelated \u2019 label'))
        found = ui._find_proxy_settings_control(parent)
        checks['finder_excludes_own_and_menu'] = found is native
        original = ui._sync_proxy_settings_shortcut
        ui._sync_proxy_settings_shortcut = lambda: native
        ui._open_proxy_settings()
        checks['one_click_original_event_source'] = len(calls) == 1 and calls[0] is native
        native.setEnabled(False)
        ui._open_proxy_settings()
        checks['disabled_host_button_not_invoked'] = len(calls) == 1 and 'unavailable' in ui.statusLabel.getText()
        ui._sync_proxy_settings_shortcut = lambda: None
        ui._open_proxy_settings()
        checks['missing_button_visible_status'] = len(calls) == 1 and 'Proxy > Proxy settings' in ui.statusLabel.getText()
        ui._sync_proxy_settings_shortcut = original
        ui.set_status('Logging enabled')
        if preview:
            from java.awt.image import BufferedImage
            from javax.imageio import ImageIO
            from java.io import File
            root.setSize(1450, 850); layout(root)
            bitmap = BufferedImage(1450, 850, BufferedImage.TYPE_INT_RGB)
            graphics = bitmap.createGraphics()
            try: root.printAll(graphics)
            finally: graphics.dispose()
            ImageIO.write(bitmap, 'png', File(preview))
    try:
        if not actual_callbacks:
            def theme():
                from com.formdev.flatlaf import FlatLightLaf
                UIManager.setLookAndFeel(FlatLightLaf())
            edt(theme)  # Private standalone JVM only, never the user's Burp.
        edt(trial)
    except (BaseException, Throwable): errors.append(traceback.format_exc())
    finally:
        for ui in owned: ui.close_custom_runtime()
        edt(lambda: None)
        for ui in owned:
            for owner in (ui._filter_worker, ui._log_writer, ui._log_io):
                if owner.worker is not None: owner.worker.join(5)
    regression = cleanup_checks(actual_callbacks, expected_line=expected_line)
    return dict(kind='UI02-private-status-and-shortcut-no-network', checks=checks, errors=errors,
                dimensions=dimensions, regression=regression, source_sha256=hashlib.sha256(raw).hexdigest(),
                actual_burp_helpers=bool(actual_callbacks), network_requests=0,
                passed=bool(checks) and all(checks.values()) and not errors and regression['passed'])


def summary(report):
    return 'UI02_LAYOUT %s (%d layout cases; 10 cleanup/UI checks; 24 logging checks)' % (
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
