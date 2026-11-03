# -*- coding: utf-8 -*-
from __future__ import print_function
import os, sys, json, hashlib, traceback
from javax.swing import SwingUtilities
from javax import swing
from java.awt.event import MouseEvent, InputEvent
from java.lang import System, Throwable
from java.awt.image import BufferedImage
from source_harness import ROOT
from probe_template_native import load_source
from probe_logging_native import NativeHelpers


def run_checks(actual_callbacks=None):
    ns, raw = load_source(os.path.join(ROOT,'BoberProxy.py'))
    helpers = actual_callbacks.getHelpers() if actual_callbacks else NativeHelpers()
    class Editor(object):
        def __init__(self): self.value=helpers.stringToBytes('')
        def getMessage(self): return self.value
        def setMessage(self, value, request): self.value=value
        def getComponent(self): return swing.JPanel()
    class Callbacks(object):
        def getHelpers(self): return helpers
        def createMessageEditor(self, controller, editable):
            return actual_callbacks.createMessageEditor(controller,editable) if actual_callbacks else Editor()
    checks, owned, errors, dimensions, frames = {}, [], [], {}, []
    def layout(component):
        # A non-showing preview has no automatic RepaintManager validation pass.
        def invalidate_tree(node):
            if hasattr(node, 'getComponents'):
                for child in node.getComponents(): invalidate_tree(child)
            node.invalidate()
        def place(node):
            node.doLayout()
            if hasattr(node, 'getComponents'):
                for child in node.getComponents(): place(child)
        invalidate_tree(component)
        place(component)
    def trial():
        try:
            for enhanced in (True, False):
                if not enhanced: ns['CODE_EDITOR_SUPPORT'] = {'error':'CODE_EDITOR_JAR_MISSING'}
                ui = ns['LoggerUI'](Callbacks(), ns['SimpleMessageController']())
                owned.append(ui)
                panel = ui.mainPanel
                frame = swing.JFrame()
                frames.append(frame)
                frame.setContentPane(panel)
                frame.pack()
                frame.setSize(1400, 850)
                frame.validate()
                layout(panel)
                image = BufferedImage(1400,850,BufferedImage.TYPE_INT_RGB)
                graphics = image.createGraphics()
                try: panel.paint(graphics)
                finally: graphics.dispose()
                checks[('enhanced_' if enhanced else 'basic_')+'initial_paint'] = True
                prefix = 'enhanced_' if enhanced else 'basic_'
                grip, scroll = ui.customCodeResizeGrip, ui.customCodeScroll
                initial = scroll.getPreferredSize().height
                width = ui.rightScroll.getWidth()
                start_y = swing.SwingUtilities.convertPoint(ui.testCodeBtn, 0, 0, ui._controls_content).y
                code = ui.customCodeArea.getText()
                def sizes():
                    return dict(content_h=ui._controls_content.getHeight(),content_pref=ui._controls_content.getPreferredSize().height,scroll_h=scroll.getHeight(),scroll_pref=scroll.getPreferredSize().height,container_h=ui.customCodeContainer.getHeight(),container_pref=ui.customCodeContainer.getPreferredSize().height,button_y=swing.SwingUtilities.convertPoint(ui.testCodeBtn,0,0,ui._controls_content).y)
                before_sizes = sizes()
                def event(kind, y, button=MouseEvent.BUTTON1, x=100):
                    mods = InputEvent.BUTTON1_DOWN_MASK if kind != MouseEvent.MOUSE_RELEASED and button == MouseEvent.BUTTON1 else 0
                    grip.dispatchEvent(MouseEvent(grip, kind, System.currentTimeMillis(), mods,
                                                  5, 5, x, y, 1, False,
                                                  button if kind != MouseEvent.MOUSE_DRAGGED else MouseEvent.NOBUTTON))
                def drag(delta):
                    event(MouseEvent.MOUSE_PRESSED, 200)
                    event(MouseEvent.MOUSE_DRAGGED, 200 + delta, x=1000)
                    event(MouseEvent.MOUSE_RELEASED, 200 + delta)
                    frame.validate()
                    layout(panel)
                    graphics = image.createGraphics()
                    try: panel.paint(graphics)
                    finally: graphics.dispose()
                checks[prefix+'editor_type'] = bool(ui._code_editor_enhanced) == enhanced
                drag(80)
                button_y = swing.SwingUtilities.convertPoint(ui.testCodeBtn, 0, 0, ui._controls_content).y
                after_sizes = sizes()
                checks[prefix+'height_grows_80'] = scroll.getPreferredSize().height == initial + 80
                checks[prefix+'buttons_move_80'] = button_y == start_y + 80
                checks[prefix+'width_fixed_despite_horizontal_drag'] = width == ui.rightScroll.getWidth() == ui._sidebar_width
                drag(5000)
                checks[prefix+'maximum_clamped'] = scroll.getPreferredSize().height == ui._code_editor_max_height
                checks[prefix+'sidebar_scrolls'] = ui._controls_content.getPreferredSize().height > ui.rightScroll.getViewport().getExtentSize().height
                drag(-5000)
                checks[prefix+'minimum_clamped'] = scroll.getPreferredSize().height == ui._code_editor_min_height
                before = scroll.getPreferredSize().height
                event(MouseEvent.MOUSE_DRAGGED, 800)
                checks[prefix+'release_stops_resize'] = scroll.getPreferredSize().height == before
                event(MouseEvent.MOUSE_PRESSED, 200, MouseEvent.BUTTON3)
                event(MouseEvent.MOUSE_DRAGGED, 500)
                event(MouseEvent.MOUSE_RELEASED, 500, MouseEvent.BUTTON3)
                checks[prefix+'right_click_ignored'] = scroll.getPreferredSize().height == before
                checks[prefix+'code_unchanged'] = ui.customCodeArea.getText() == code
                checks[prefix+'remains_default_off'] = not ui.useCustomChk.isSelected() and not ui.proxyModeBtn.isSelected()
                line = ui.customCodeArea.getFontMetrics(ui.customCodeArea.getFont()).getHeight()
                chrome = max(0, initial - 10 * line)
                checks[prefix+'maximum_is_29_lines'] = ui._code_editor_max_height == max(initial, 29 * line + chrome)
                initial_code_width = scroll.getWidth()
                divider = ui.controlsSplit
                left_width = ui.leftSplit.getWidth()
                divider.setDividerLocation(divider.getDividerLocation() - 120)
                layout(panel)
                checks[prefix+'sidebar_grows_left_120'] = ui.rightScroll.getWidth() == width + 120 and ui.leftSplit.getWidth() == left_width - 120
                checks[prefix+'editor_uses_extra_width'] = scroll.getWidth() == initial_code_width + 120
                checks[prefix+'sidebar_viewport_tracks_width'] = ui._controls_content.getWidth() == ui.rightScroll.getViewport().getExtentSize().width
                wide = ui.rightScroll.getWidth()
                frame.setSize(1600,850)
                layout(panel)
                checks[prefix+'window_resize_retains_selected_width'] = ui.rightScroll.getWidth() == wide
                divider.setDividerLocation(divider.getMaximumDividerLocation())
                layout(panel)
                checks[prefix+'native_drag_minimum_is_original_width'] = ui.rightScroll.getWidth() == width == ui.rightScroll.getMinimumSize().width
                graphics = image.createGraphics()
                try: panel.paint(graphics)
                finally: graphics.dispose()
                checks[prefix+'width_resize_repaints'] = True
                checks[prefix+'scope_default_disables_injection'] = not ui.proxyModeBtn.isEnabled() and not ui.proxyModeBtn.isSelected()
                checks[prefix+'top_buttons_equal_width'] = abs(ui.scopeBtn.getWidth()-ui.proxyModeBtn.getWidth())<=1
                dialog = ns['TargetScopeDialog'](ui)
                ui._scope_dialog = dialog
                dialog.origin.setText('http://bad/path')
                dialog.apply()
                checks[prefix+'invalid_origin_keeps_unconfigured'] = ui.sessions.selection()[0] is None and not ui.proxyModeBtn.isEnabled()
                dialog.origin.setText('http://127.0.0.1:18810')
                dialog.prefix.setText('/workflow')
                dialog.apply()
                selection = ui.sessions.selection()
                checks[prefix+'valid_apply_enables_but_does_not_activate'] = ui.proxyModeBtn.isEnabled() and not ui.proxyModeBtn.isSelected() and selection[0].prefix=='/workflow'
                ui.proxyModeBtn.setSelected(True)
                ui._on_proxy_toggle()
                checks[prefix+'empty_template_activation_refused'] = not ui.proxyModeBtn.isSelected()
                ui.reqTemplateEditor.setMessage(helpers.stringToBytes('GET /workflow/action?q=p4yl04dm4rk3r HTTP/1.1\r\nHost: 127.0.0.1:18810\r\n\r\n'),True)
                ui.proxyModeBtn.doClick(0)
                checks[prefix+'valid_template_activation'] = ui.proxyModeBtn.isSelected()
                ui.cookieManager.jar['canary']='A'
                ui.csrfManager.set_token('A')
                ui._apply_scope(ns['TargetScopePolicy']('HTTP://127.0.0.1:18810/','/workflow/'))
                checks[prefix+'same_scope_apply_preserves_state_and_toggle'] = ui.proxyModeBtn.isSelected() and ui.cookieManager.jar=={'canary':'A'} and ui.sessions.selection()==selection
                dialog=ns['TargetScopeDialog'](ui);ui._scope_dialog=dialog
                dialog.prefix.setText('/workflow/../bad')
                dialog.apply()
                checks[prefix+'invalid_prefix_preserves_live_scope'] = ui.sessions.selection()==selection and ui.proxyModeBtn.isSelected()
                dialog.dialog.dispose()
                checks[prefix+'cancel_preserves_state'] = ui.csrfManager.get_token()=='A'
                dialog=ns['TargetScopeDialog'](ui);ui._scope_dialog=dialog
                dialog.origin.setText('http://127.0.0.1:18811')
                dialog.apply()
                checks[prefix+'scope_change_resets_state_and_toggle'] = not ui.proxyModeBtn.isSelected() and ui.cookieManager.jar=={} and ui.csrfManager.get_token() is None
                dialog=ns['TargetScopeDialog'](ui);ui._scope_dialog=dialog
                dialog.clear()
                checks[prefix+'scope_clear_disables_injection'] = not ui.proxyModeBtn.isEnabled() and ui.sessions.selection()[0] is None
                image=BufferedImage(panel.getWidth(),panel.getHeight(),BufferedImage.TYPE_INT_RGB)
                graphics=image.createGraphics()
                try: panel.paint(graphics)
                finally: graphics.dispose()
                checks[prefix+'scope_operations_repaint'] = True
                dimensions[prefix] = dict(initial=initial, minimum=ui._code_editor_min_height, maximum=ui._code_editor_max_height, width=width, button_shift=button_y-start_y, before=before_sizes, after=after_sizes)
        except (BaseException, Throwable): errors.append(traceback.format_exc())
        finally:
            for ui in owned: ui.close_custom_runtime()
            for frame in frames: frame.dispose()
    swing.SwingUtilities.invokeAndWait(trial)
    swing.SwingUtilities.invokeAndWait(lambda:None)
    for ui in owned:
        for owner in (ui._custom_executor, ui._filter_worker, ui._log_writer, ui._log_io):
            if owner.worker is not None: owner.worker.join(5)
    report=dict(kind='TG04-private-native-scope-ui-and-resize-no-network',source_sha256=hashlib.sha256(raw).hexdigest(),checks=checks,errors=errors,dimensions=dimensions,network_requests=0,actual_burp=bool(actual_callbacks),passed=bool(checks) and all(checks.values()) and not errors)
    return report

def summary(report):
    return 'TG_SCOPE_UI %s (%d native/UI checks)' % ('PASS' if report['passed'] else 'FAIL',len(report['checks']))

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    report=run_checks()
    with open(args.report,'w') as handle: json.dump(report,handle,indent=2)
    print(summary(report))
    if not report['passed']: print(json.dumps(report,indent=2))
    sys.exit(0 if report['passed'] else 1)
