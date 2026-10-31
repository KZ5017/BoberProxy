# -*- coding: utf-8 -*-
"""Inspect public Swing/editor capabilities and tagged local Proxy references.

Never modifies main BoberProxy settings or interception actions. Only its own
synthetic editor is edited. Proxy observation is limited to one tagged loopback.
"""
from burp import IBurpExtender, IProxyListener, ITab, IExtensionStateListener, IMessageEditorController
from javax.swing import SwingUtilities, Timer
from javax.swing.text import JTextComponent
from javax.swing.event import DocumentListener
from java.lang import System
import json
import os
import threading
import traceback


class BurpExtender(IBurpExtender, IProxyListener, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.lock = threading.Lock()
        self.references = set()
        self.path = os.path.join(os.path.dirname(str(callbacks.getExtensionFilename())),
                                 'runtime', 'k06-editor-inspection.json')
        self.report = dict(kind='K06-real-editor-and-reference-inspection',
                           burp_version=list(callbacks.getBurpVersion()),
                           java_version=str(System.getProperty('java.version')),
                           editors=[], proxy_events=[])
        callbacks.setExtensionName('BoberProxy K06 editor/API inspection')

        def inspect():
            try:
                self.report['editors'] = []
                self.report['creation_on_edt'] = bool(SwingUtilities.isEventDispatchThread())
                editor = getattr(self, 'editor', None)
                if editor is None:
                    service = self.helpers.buildHttpService('127.0.0.1', 18765, False)
                    request = self.helpers.stringToBytes('GET /k06-editor-probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
                    class Controller(IMessageEditorController):
                        def getHttpService(self):
                            return service
                        def getRequest(self):
                            return request
                        def getResponse(self):
                            return None
                    self.controller = Controller()
                    editor = callbacks.createMessageEditor(self.controller, True)
                    self.editor = editor
                editor.setMessage(self.helpers.stringToBytes(
                    'GET /k06-editor-probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'), True)
                documents = []
                def walk(component, depth=0):
                    if depth > 20:
                        return
                    row = dict(component=str(type(component)))
                    if isinstance(component, JTextComponent):
                        document = component.getDocument()
                        row.update(document=str(type(document)), editable=bool(component.isEditable()),
                                   length=document.getLength())
                        documents.append((component, document))
                    self.report['editors'].append(row)
                    if hasattr(component, 'getComponents'):
                        for child in component.getComponents():
                            walk(child, depth + 1)
                walk(editor.getComponent())
                events = []
                class Listener(DocumentListener):
                    def insertUpdate(self, event):
                        events.append('insert')
                    def removeUpdate(self, event):
                        events.append('remove')
                    def changedUpdate(self, event):
                        events.append('change')
                changed = False
                for component, document in documents:
                    if not component.isEditable():
                        continue
                    text = document.getText(0, document.getLength())
                    needle = '/k06-editor-probe'
                    if needle not in text:
                        continue
                    listener = Listener()
                    document.addDocumentListener(listener)
                    try:
                        document.insertString(text.index(needle) + len(needle), '-changed', None)
                        changed = '/k06-editor-probe-changed' in self.helpers.bytesToString(editor.getMessage())
                    finally:
                        document.removeDocumentListener(listener)
                    break
                self.report.update(document_count=len(documents), edit_events=events,
                                   document_edit_reaches_message=changed,
                                   modified_flag=bool(editor.isMessageModified()))
            except BaseException:
                self.report['inspection_error'] = traceback.format_exc()
        if SwingUtilities.isEventDispatchThread():
            inspect()
        else:
            SwingUtilities.invokeAndWait(inspect)
        self.save()
        callbacks.registerProxyListener(self)
        callbacks.registerExtensionStateListener(self)
        def add_tab():
            callbacks.addSuiteTab(self)
            def materialized(event):
                if not self.editor.getComponent().isShowing():
                    return
                self.timer.stop()
                inspect()
                self.save()
                callbacks.printOutput('K06_INSPECT MATERIALIZED (documents=%s, edit-reaches-message=%s)' % (
                    self.report.get('document_count'), self.report.get('document_edit_reaches_message')))
            self.timer = Timer(300, materialized)
            self.timer.start()
        if SwingUtilities.isEventDispatchThread():
            add_tab()
        else:
            SwingUtilities.invokeAndWait(add_tab)
        callbacks.printOutput('K06_INSPECT READY (documents=%s, edit-reaches-message=%s)\n%s' % (
            self.report.get('document_count'), self.report.get('document_edit_reaches_message'), self.path))
        if self.report.get('inspection_error'):
            callbacks.printError(self.report['inspection_error'])

    def getTabCaption(self):
        return 'K06 Editor Probe'

    def getUiComponent(self):
        return self.editor.getComponent()

    def extensionUnloaded(self):
        timer = getattr(self, 'timer', None)
        if timer is not None:
            SwingUtilities.invokeLater(timer.stop)

    def save(self):
        with self.lock:
            with open(self.path, 'w') as handle:
                handle.write(json.dumps(self.report, indent=2, ensure_ascii=True) + '\n')

    def processProxyMessage(self, messageIsRequest, intercepted):
        try:
            info = intercepted.getMessageInfo()
            service = info.getHttpService()
            if service.getHost() != '127.0.0.1' or service.getPort() != 18765:
                return
            reference = int(intercepted.getMessageReference())
            if messageIsRequest:
                text = self.helpers.bytesToString(info.getRequest())
                if 'X-Bober-K06-Inspect: reference' not in text:
                    return
                self.references.add(reference)
            elif reference not in self.references:
                return
            with self.lock:
                self.report['proxy_events'].append(dict(request=bool(messageIsRequest), reference=reference,
                                                         action=int(intercepted.getInterceptAction())))
                if len(self.report['proxy_events']) > 10:
                    self.report['proxy_events'] = self.report['proxy_events'][-10:]
            self.save()
            if not messageIsRequest:
                self.references.discard(reference)
        except BaseException:
            self.callbacks.printError(traceback.format_exc())
