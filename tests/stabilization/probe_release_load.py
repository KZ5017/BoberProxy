# -*- coding: utf-8 -*-
"""Disposable standalone Jython/JVM load of an extracted release package.

Uses the installed Burp API classes and private callback/editor doubles; does
not register in the user's Burp or send traffic. Report that distinction.
"""
from __future__ import print_function
import argparse, hashlib, json, os, sys, traceback
from java.awt.image import BufferedImage
from java.lang import System, Throwable
from javax.swing import JFrame, JPanel, SwingUtilities
from probe_logging_native import NativeHelpers
from probe_template_native import load_source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    source = os.path.abspath(os.path.join(args.package, 'BoberProxy.py'))
    namespace, raw = load_source(source)
    helpers, registrations, errors, checks = NativeHelpers(), [], [], {}

    class Editor(object):
        def __init__(self): self.value = helpers.stringToBytes('')
        def getMessage(self): return self.value
        def setMessage(self, value, is_request): self.value = value
        def getComponent(self): return JPanel()

    class Callbacks(object):
        def getHelpers(self): return helpers
        def getExtensionFilename(self): return source
        def setExtensionName(self, value): registrations.append('name:' + value)
        def registerExtensionStateListener(self, value): registrations.append('state')
        def addSuiteTab(self, value): registrations.append('tab')
        def registerHttpListener(self, value): registrations.append('http')
        def registerProxyListener(self, value): registrations.append('proxy')
        def removeProxyListener(self, value): pass
        def removeHttpListener(self, value): pass
        def removeSuiteTab(self, value): pass
        def printError(self, value): errors.append(unicode(value))
        def createMessageEditor(self, controller, editable): return Editor()

    extension = namespace['BurpExtender']()
    ui, frames = None, []
    try:
        extension.registerExtenderCallbacks(Callbacks())
        SwingUtilities.invokeAndWait(lambda: None)
        ui = extension.ui
        if ui is None: raise AssertionError('Private extension startup failed')
        def inspect():
            panel = ui.mainPanel
            frame = JFrame()
            frames.append(frame)
            frame.setContentPane(panel)
            frame.pack()
            frame.setSize(1400, 850)
            frame.validate()
            def layout(component):
                component.doLayout()
                if hasattr(component, 'getComponents'):
                    for child in component.getComponents(): layout(child)
            layout(panel)
            image = BufferedImage(1400, 850, BufferedImage.TYPE_INT_RGB)
            graphics = image.createGraphics()
            try: panel.paint(graphics)
            finally: graphics.dispose()
            checks['full_panel_paints'] = True
            checks['scope_starts_empty_injection_disabled'] = ui.sessions.selection()[0] is None and not ui.proxyModeBtn.isEnabled()
            checks['bundled_editor_active'] = bool(ui._code_editor_enhanced)
        SwingUtilities.invokeAndWait(inspect)
        checks['callbacks_registered'] = registrations == ['name:BoberProxy', 'state', 'tab', 'http', 'proxy']
        checks['jar_loaded_from_extraction'] = os.path.normcase(namespace['CODE_EDITOR_SUPPORT'].get('jar', '')) == os.path.normcase(os.path.abspath(os.path.join(args.package, 'lib', 'rsyntaxtextarea-3.6.3.jar')))
    except (BaseException, Throwable):
        errors.append(traceback.format_exc())
    finally:
        extension.extensionUnloaded()
        SwingUtilities.invokeAndWait(lambda: [frame.dispose() for frame in frames])
        if ui is not None:
            for owner in (ui._custom_executor, ui._filter_worker, ui._log_writer, ui._log_io):
                if owner.worker is not None: owner.worker.join(5)
            checks['private_unload_closed'] = ui._custom_ui_closed
    report = dict(kind='release-extracted-standalone-jython-private-callbacks',
                  actual_burp_application=False, network_requests=0,
                  source_sha256=hashlib.sha256(raw).hexdigest(),
                  java_version=unicode(System.getProperty('java.version')),
                  checks=checks, errors=errors,
                  passed=len(checks) == 6 and all(checks.values()) and not errors)
    with open(args.report, 'w') as handle:
        json.dump(report, handle, indent=2, ensure_ascii=True)
    print('RELEASE_EXTRACTED_SMOKE ' + ('PASS' if report['passed'] else 'FAIL'))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
