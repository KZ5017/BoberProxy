# -*- coding: utf-8 -*-
"""UI01 geometry on private source instances; no traffic/main UI changes."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import traceback
from javax.swing import SwingUtilities, UIManager
from javax.swing.plaf import FontUIResource
from java.awt import Font
from java.lang import Throwable
from source_harness import ROOT
from probe_template_native import load_source
from probe_logging_native import NativeHelpers
from probe_cleanup_native import run_checks as cleanup_checks


def run_checks(actual_callbacks=None, preview=None):
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    helpers = actual_callbacks.getHelpers() if actual_callbacks else NativeHelpers()
    trials, errors, current = [], [], []
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
        def setMessage(self, value, is_request):
            if value is None: raise ValueError('Message cannot be null')
            self.value = value
        def getComponent(self):
            from javax.swing import JPanel
            return JPanel()
    class Callbacks(object):
        def getHelpers(self): return helpers
        def createMessageEditor(self, controller, editable):
            return actual_callbacks.createMessageEditor(controller, editable) if actual_callbacks else Editor()
    def layout(component):
        component.doLayout()
        if hasattr(component, 'getComponents'):
            for child in component.getComponents(): layout(child)
    font_defaults = {}
    if not actual_callbacks:
        def fonts():
            for key in UIManager.getDefaults().keys():
                value = UIManager.get(key)
                if isinstance(value, Font): font_defaults[key] = value
        edt(fonts)
    try:
        for scale in ([1.0] if actual_callbacks else [1.0, 1.15, 1.3]):
            def trial():
                if font_defaults:
                    for key, value in font_defaults.items(): UIManager.put(key, FontUIResource(value.deriveFont(float(value.getSize2D()) * scale)))
                ui = ns['LoggerUI'](Callbacks(), ns['SimpleMessageController']())
                current.append(ui)
                root, sidebar = ui.getUiComponent(), ui.rightScroll
                content = ui._controls_content
                checks, dimensions = {}, []
                initial_viewer = []
                natural_height = int(content.getPreferredSize().height)
                width = int(ui._sidebar_width)
                for total in [width + 500, width + 900, width + 1300]:
                    for height in [500, max(900, natural_height + 200)]:
                        root.setSize(total, height)
                        layout(root)
                        if not initial_viewer:
                            initial_viewer.extend([ui.viewerSplit.getLeftComponent().getWidth(),
                                                   ui.viewerSplit.getRightComponent().getWidth()])
                        dimensions.append(dict(root_width=total,root_height=height,sidebar_width=int(sidebar.getWidth()),
                            viewport_width=int(sidebar.getViewport().getExtentSize().width),content_width=int(content.getWidth()),
                            vertical_scrollbar=bool(sidebar.getVerticalScrollBar().isVisible()),
                            horizontal_scrollbar=bool(sidebar.getHorizontalScrollBar().isVisible())))
                checks['fixed_width_on_resize'] = all(d['sidebar_width'] == width for d in dimensions)
                checks['viewport_width_tracking'] = all(d['content_width'] == d['viewport_width'] for d in dimensions)
                checks['outer_horizontal_never_visible'] = all(not d['horizontal_scrollbar'] for d in dimensions)
                checks['vertical_scroll_when_short_only'] = all(d['vertical_scrollbar'] == (d['root_height'] == 500) for d in dimensions)
                pairs = [(ui.clearBtn, ui.clearSelBtn), (ui.filterBtn, ui.pauseBtn),
                         (ui.clearCookiesBtn, ui.showCookiesBtn), (ui.clearCsrfBtn, ui.showCsrfBtn),
                         (ui.testCodeBtn, ui.resetBtn), (ui.useCheckPageChk, ui.autoFollowRTChk)]
                checks['equal_full_width_pairs'] = all(
                    left.getParent() is right.getParent()
                    and abs(left.getWidth() - right.getWidth()) <= 1
                    and left.getY() == right.getY()
                    and abs(left.getWidth() + right.getWidth() + 8 - left.getParent().getWidth()) <= 1
                    for left, right in pairs)
                checks['full_width_primary_buttons'] = all(
                    button.getWidth() == button.getParent().getWidth() - 8
                    for button in (ui.proxyModeBtn, ui.addSitemapBtn))
                request, response = ui.viewerSplit.getLeftComponent(), ui.viewerSplit.getRightComponent()
                checks['viewer_equal_initial_and_resize_weight'] = (abs(initial_viewer[0] - initial_viewer[1]) <= 1
                    and ui.viewerSplit.getResizeWeight() == 0.5)
                pair_sizes = [dict(left=str(a.getText()), right=str(b.getText()),
                    left_width=a.getWidth(), right_width=b.getWidth(), parent_width=a.getParent().getWidth())
                    for a, b in pairs]
                viewer_sizes = dict(request=request.getWidth(), response=response.getWidth(),
                    divider=ui.viewerSplit.getDividerLocation(), total=ui.viewerSplit.getWidth())
                ui.viewerSplit.setDividerLocation(120)
                layout(root)
                checks['viewer_manual_divider_preserved'] = ui.viewerSplit.getDividerLocation() == 120
                required = ['proxyModeBtn','lenTypeCombo','compCombo','sizeField','regexField','addSitemapBtn','clearBtn','clearSelBtn','pauseBtn','filterBtn',
                    'useCheckPageChk','autoFollowRTChk','autoUpdateChk','autoUpdateCsrfChk','clearCookiesBtn','showCookiesBtn','clearCsrfBtn','showCsrfBtn',
                    'resetCsrfRegexBtn','csrfRegexArea','useCustomChk','timeoutField','payloadParamField','payloadParam2Field','customCodeArea','testCodeBtn','resetBtn',
                    'customStatusArea','filterStatusLabel','statusLabel']
                def descendants(component):
                    result = [component]
                    if hasattr(component,'getComponents'):
                        for child in component.getComponents(): result.extend(descendants(child))
                    return result
                members = descendants(content)
                checks['controls_present_once'] = all(sum(component is getattr(ui,name) for component in members) == 1 for name in required)
                def inside_control(component):
                    # Every component's allocation stays within the scrollable width;
                    # the native text viewport handles long content internally.
                    if component is ui.customCodeArea:
                        component = ui.customCodeScroll
                    elif component is ui.csrfRegexArea:
                        component = ui.csrfRegexScroll
                    elif component is ui.regexField:
                        component = ui.responseRegexScroll
                    x, current_component = 0, component
                    while current_component is not content:
                        x += current_component.getX()
                        current_component = current_component.getParent()
                        if current_component is None: return False
                    return x >= 0 and x + component.getWidth() <= content.getWidth()
                checks['controls_not_horizontally_clipped'] = all(inside_control(getattr(ui,name)) for name in required)
                clipped = [name for name in required if not inside_control(getattr(ui,name))]
                buttons = [getattr(ui,n) for n in required if n.endswith('Btn')]
                checks['button_labels_fit'] = all(b.getWidth() >= b.getPreferredSize().width for b in buttons)
                checks['logging_fields_locally_aligned'] = (ui.lenTypeCombo.getParent() is ui.compCombo.getParent()
                    and ui.compCombo.getParent() is ui.sizeField.getParent()
                    and ui.lenTypeCombo.getX() == ui.compCombo.getX() == ui.sizeField.getX())
                initial_code, initial_pattern = ui.customCodeArea.getText(), ui.csrfRegexArea.getText()
                response_height = ui.responseRegexScroll.getHeight()
                checks['regex_one_visible_row'] = ui.regexField.getRows() == ui.csrfRegexArea.getRows() == 1
                checks['empty_response_reserves_scroll_height'] = (response_height >=
                    ui.regexField.getPreferredSize().height
                    + ui.responseRegexScroll.getHorizontalScrollBar().getPreferredSize().height)
                ui.customCodeArea.setText('#' + 'x' * 2000)
                ui.csrfRegexArea.setText('(' + 'x' * 1000 + ')')
                ui.regexField.setText('x' * 1000)
                ui.statusLabel.setText('long status ' * 300)
                ui.filterStatusLabel.setText('long filter status ' * 300)
                layout(root)
                checks['long_content_does_not_resize_sidebar'] = sidebar.getWidth() == width and content.getWidth() == sidebar.getViewport().getExtentSize().width
                checks['long_lines_scroll_inside_editors'] = (ui.customCodeScroll.getHorizontalScrollBar().isVisible()
                    and ui.csrfRegexScroll.getHorizontalScrollBar().isVisible()
                    and ui.responseRegexScroll.getHorizontalScrollBar().isVisible()
                    and not sidebar.getHorizontalScrollBar().isVisible())
                checks['response_overflow_leaves_text_visible'] = (
                    ui.responseRegexScroll.getHeight() == response_height
                    and ui.responseRegexScroll.getViewport().getExtentSize().height >=
                    ui.regexField.getFontMetrics(ui.regexField.getFont()).getHeight())
                ui.customCodeArea.setText(initial_code)
                ui.csrfRegexArea.setText(initial_pattern)
                ui.regexField.setText('')
                ui.customStatusArea.getCaret().setVisible(True)
                checks['output_selectable_without_insertion_cursor'] = (not ui.customStatusArea.isEditable()
                    and ui.customStatusArea.isFocusable() and not ui.customStatusArea.getCaret().isVisible())
                ui.customStatusArea.setText('Copyable output')
                ui.customStatusArea.selectAll()
                checks['output_selection_preserved'] = ui.customStatusArea.getSelectedText() == 'Copyable output'
                checks['neutral_click_handlers_scoped'] = (bool(content.getMouseListeners())
                    and not ui.sizeField.getMouseListeners() == content.getMouseListeners()
                    and content.isFocusable())
                checks['size_captions'] = list(ui.logTableModel.COLUMNS[-2:]) == ['Total size', 'Body size']
                mapped = []
                ui.sizeField.setText('2,4')
                for caption, expected in [('Minimum', [False, True, True]),
                                          ('Maximum', [True, True, False]),
                                          ('Not equal', [True, False, True])]:
                    ui.compCombo.setSelectedItem(caption)
                    for kind, total in [('Total size', True), ('Body size', False)]:
                        ui.lenTypeCombo.setSelectedItem(kind)
                        values = ui._collect_runtime_values()
                        plan = ns['CaptureFilterPlan'](values)
                        mapped.append([plan.accepts(200, n if total else 100,
                            100 if total else n, None, helpers) for n in (1, 2, 5)] == expected)
                checks['renamed_size_filters_preserve_comparisons'] = all(mapped)
                ui.sizeField.setText('')
                ui.lenTypeCombo.setSelectedItem('Total size')
                ui.compCombo.setSelectedItem('Minimum')
                ui._collect_runtime_values()
                ui.statusLabel.setText('Running')
                ui.filterStatusLabel.setText('Filters ready')
                layout(root)
                checks['output_fills_spare_height'] = content.getHeight() == sidebar.getViewport().getExtentSize().height
                if preview and scale == 1.0:
                    from java.awt.image import BufferedImage
                    from javax.imageio import ImageIO
                    from java.io import File
                    root.setSize(width+900,natural_height+40)
                    layout(root)
                    bitmap = BufferedImage(width,sidebar.getHeight(),BufferedImage.TYPE_INT_RGB)
                    graphics = bitmap.createGraphics()
                    try: sidebar.printAll(graphics)
                    finally: graphics.dispose()
                    ImageIO.write(bitmap,'png',File(preview))
                trials.append(dict(scale=scale,font_points=float(ui.testCodeBtn.getFont().getSize2D()),width=width,
                    natural_height=natural_height,test_width=int(ui.testCodeBtn.getWidth()),reset_width=int(ui.resetBtn.getWidth()),
                    checks=checks,dimensions=dimensions,pair_sizes=pair_sizes,viewer_sizes=viewer_sizes,
                    clipped=clipped,passed=all(checks.values())))
            edt(trial)
            ui = current[-1]
            ui.close_custom_runtime()
            edt(lambda:None)
            for owner in (ui._filter_worker,ui._log_writer,ui._log_io):
                if owner.worker is not None: owner.worker.join(5)
            if not trials[-1]['passed']: break
    except (BaseException, Throwable): errors.append(traceback.format_exc())
    finally:
        for ui in current: ui.close_custom_runtime()
        edt(lambda:None)
        if font_defaults:
            edt(lambda:[UIManager.put(key,value) for key,value in font_defaults.items()])
    # Actual native editor/helper and existing archive, selection, export lifecycle.
    try:
        regression = cleanup_checks(actual_callbacks,expected_line='BoberProxy loaded (UI01.6)')
    except (BaseException, Throwable):
        errors.append(traceback.format_exc())
        regression = dict(passed=False, checks={}, errors=['Native regression could not complete.'])
    return dict(kind='UI01-private-native-layout-no-network',source_sha256=hashlib.sha256(raw).hexdigest(),
        trials=trials,errors=errors,regression=regression,actual_burp_helpers=bool(actual_callbacks),network_requests=0,
        passed=bool(trials) and all(t['passed'] for t in trials) and not errors and regression['passed'])


def summary(report):
    return 'UI01_LAYOUT %s (%d layout profiles; 10 cleanup/UI checks; 24 logging checks)' % ('PASS' if report['passed'] else 'FAIL',len(report['trials']))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    parser.add_argument('--preview')
    args=parser.parse_args()
    report=run_checks(preview=args.preview)
    with open(args.report,'w') as handle: json.dump(report,handle,indent=2)
    print(summary(report))
    if not report['passed']: print(json.dumps(report,indent=2))
    sys.exit(0 if report['passed'] else 1)
