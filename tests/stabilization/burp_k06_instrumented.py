# -*- coding: utf-8 -*-
"""Unchanged main source, tagged loopback traffic and file-driven EDT test actions.

The command channel exists ONLY in this test entry point, never BoberProxy.py.
No arbitrary exec, paths or remote destinations. Remove after K06 validation.
"""
import hashlib
import json
import os
import sys
import threading
import traceback
import uuid
from burp import IBurpExtender
from javax.swing import SwingUtilities
from java.lang import Exception as JavaException


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        directory = os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        from source_harness import ROOT
        from probe_template_native import load_source
        namespace, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
        Main = namespace['BurpExtender']
        runtime = os.path.join(directory, 'runtime')
        self.instance = uuid.uuid4().hex
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.trace_path = os.path.join(runtime, 'k06-wire-trace.jsonl')
        self.command_path = os.path.join(runtime, 'k06-command.json')
        self.ack_path = os.path.join(runtime, 'k06-ack.json')
        self.hash = hashlib.sha256(raw).hexdigest()
        wrapper = self

        def in_scope(info):
            if info is None:
                return False
            service = info.getHttpService()
            if service is None or service.getHost() != '127.0.0.1' or service.getPort() not in (18765, 18770):
                return False
            text = namespace['_wire_text'](info.getRequest(), callbacks.getHelpers())
            return '\r\nX-Bober-Test-Run: k06-' in text

        class Instrumented(Main):
            def processProxyMessage(self, request, message):
                if not in_scope(message.getMessageInfo()):
                    return
                wrapper.record('before', request, message)
                try:
                    Main.processProxyMessage(self, request, message)
                finally:
                    wrapper.record('after', request, message)
            def processHttpMessage(self, tool, request, info):
                if in_scope(info):
                    Main.processHttpMessage(self, tool, request, info)
            def extensionUnloaded(self):
                wrapper.stop.set()
                Main.extensionUnloaded(self)

        self.Main = Main
        self.main = Instrumented()
        self.callbacks, self.namespace, self.directory = callbacks, namespace, directory
        Main.registerExtenderCallbacks(self.main, callbacks)
        callbacks.setExtensionName('BoberProxy K06 instrumented validation')
        with open(os.path.join(runtime, 'k06-control-session.json'), 'w') as handle:
            json.dump(dict(instance=self.instance, source_sha256=self.hash), handle)
        thread = threading.Thread(target=self.commands, name='BoberProxy.K06.test-control')
        thread.setDaemon(True)
        self.control_thread = thread
        thread.start()
        callbacks.printOutput('K06_INSTRUMENTED READY (tagged loopback only; controlled EDT actions)')

    def state(self):
        ui = self.main.ui
        if ui is None:
            return dict(ready=False)
        def synthetic(value):
            return value if value is None or str(value).startswith('K06_') else '<other>'
        with ui.sessions.condition:
            owner = ui.sessions.owner
            with ui.cookieManager.lock:
                sid = ui.cookieManager.jar.get('sid')
            config = ui._capture_runtime()
            return dict(ready=True, epoch=ui.sessions.epoch, owner=owner.key if owner else None,
                        phase=owner.phase if owner else None, waiting=len(ui.sessions.waiting),
                        version=config.version, closed=ui._custom_ui_closed,
                        sid=synthetic(sid), csrf=synthetic(ui.csrfManager.get_token()),
                        proxy=config.get('proxy'), use_cp=config.get('use_cp'),
                        cookies=config.get('cookies'), csrf_enabled=config.get('csrf'),
                        publisher_running=not ui._runtime_publisher.closed)

    def record(self, phase, request, message):
        try:
            row = dict(instance=self.instance, source_sha256=self.hash, phase=phase,
                       request=bool(request), reference=int(message.getMessageReference()),
                       action=int(message.getInterceptAction()), state=self.state())
            info = message.getMessageInfo()
            text = self.namespace['_wire_text'](info.getRequest(), self.callbacks.getHelpers())
            row['request_line'] = text.split('\r\n', 1)[0]
            with self.lock:
                with open(self.trace_path, 'a') as handle:
                    handle.write(json.dumps(row, ensure_ascii=True) + '\n')
        except (Exception, JavaException):
            self.callbacks.printError('K06 trace error:\n' + traceback.format_exc())

    def apply(self, command):
        ui = self.main.ui
        if ui is None:
            raise ValueError('Main UI not initialized')
        action = command.get('action')
        if action == 'setup':
            for name, filename in [('reqTemplateEditor', 'k06-request-template.http'),
                                   ('checkPageEditor', 'k06-checkpage-template.http')]:
                with open(os.path.join(self.directory, 'fixtures', filename), 'rb') as handle:
                    getattr(ui, name).setMessage(self.callbacks.getHelpers().stringToBytes(handle.read().decode('latin-1')), True)
            with open(os.path.join(self.directory, 'runtime', 'custom-k06-cases.py'), 'rb') as handle:
                ui.customCodeArea.setText(handle.read().decode('utf-8'))
            ui.timeoutField.setText('2000')
            ui.payloadParamField.setText('q')
            ui.payloadParam2Field.setText('w')
            ui.csrfRegexArea.setText(ui.csrf_default_pattern)
            for name in ('proxyModeBtn', 'useCheckPageChk', 'autoUpdateChk', 'autoUpdateCsrfChk', 'useCustomChk'):
                widget = getattr(ui, name)
                if not widget.isSelected():
                    widget.doClick(0)
            if ui.autoFollowRTChk.isSelected():
                ui.autoFollowRTChk.doClick(0)
        elif action == 'change':
            # Deliberately change all important settings while an RT is held.
            for name in ('proxyModeBtn', 'useCheckPageChk', 'autoUpdateChk', 'autoUpdateCsrfChk', 'useCustomChk'):
                widget = getattr(ui, name)
                if widget.isSelected():
                    widget.doClick(0)
            ui.payloadParamField.setText('changed')
            ui.payloadParam2Field.setText('changed2')
            ui.checkPageEditor.setMessage(self.callbacks.getHelpers().stringToBytes(
                'POST /k06/check-alt?case=p4yl04dm4rk3r HTTP/1.1\r\nHost: 127.0.0.1:18770\r\nX-Bober-Test-Run: k06-wire\r\n\r\ncsrf=c5rfm4rk3r'), True)
            ui.csrfRegexArea.setText(r'other="([^"]*)"')
            ui.timeoutField.setText('1')
            ui.customCodeArea.setText('raise ValueError("K06 changed code must not execute")')
        elif action in ('clear-cookies', 'clear-csrf'):
            (ui.clearCookiesBtn if action == 'clear-cookies' else ui.clearCsrfBtn).doClick(0)
        elif action == 'unload':
            # Keep the test controller alive for the post-unload observation.
            self.Main.extensionUnloaded(self.main)
        elif action != 'state':
            raise ValueError('Unknown K06 test action')
        ui._publish_runtime()
        return self.state()

    def commands(self):
        seen = None
        while not self.stop.wait(0.05):
            try:
                if not os.path.isfile(self.command_path) or os.path.getsize(self.command_path) > 16384:
                    continue
                try:
                    with open(self.command_path, 'r') as handle:
                        command = json.load(handle)
                except (IOError, ValueError):
                    continue  # Atomic replacement/read contention in the fixture.
                if command.get('instance') != self.instance or not command.get('id') or command['id'] == seen:
                    continue
                seen = command['id']
                completed = threading.Event()
                result = dict(instance=self.instance, id=seen, source_sha256=self.hash)
                def invoke():
                    try:
                        result['state'] = self.apply(command)
                        result['ok'] = True
                    except (Exception, JavaException):
                        result['ok'], result['error'] = False, traceback.format_exc()
                    finally:
                        completed.set()
                SwingUtilities.invokeLater(invoke)
                while not completed.wait(0.1):
                    if self.stop.isSet():
                        return
                with open(self.ack_path, 'w') as handle:
                    json.dump(result, handle, ensure_ascii=True)
            except (Exception, JavaException):
                self.callbacks.printError('K06 test controller error:\n' + traceback.format_exc())
                self.stop.set()
