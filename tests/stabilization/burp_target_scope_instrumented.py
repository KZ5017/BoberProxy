# -*- coding: utf-8 -*-
"""TG05 unchanged root, tagged loopback observations and fixed EDT profiles.

Private test entry point: never distributed as the normal extension. No automatic
requests, arbitrary code/URL/file commands, or access to external session values.
"""
from burp import IBurpExtender
from javax.swing import SwingUtilities
from java.lang import Throwable, System
from collections import deque
from urlparse import urlsplit, parse_qs
import hashlib, json, os, re, sys, threading, traceback, uuid

ORIGINS = dict(A='http://127.0.0.1:18810', B='http://127.0.0.1:18811', T='https://127.0.0.1:18812')
CUSTOM = '''def custom_codeblock(a, b, c):
    import time
    if a == 'custom-hold': time.sleep(.6)
    return a, b, c
'''


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        directory = os.path.dirname(unicode(callbacks.getExtensionFilename()))
        sys.path.insert(0, directory)
        from source_harness import ROOT
        from probe_template_native import load_source
        self.ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
        self.hash, self.instance = hashlib.sha256(raw).hexdigest(), uuid.uuid4().hex
        self.callbacks, self.stop, self.lock = callbacks, threading.Event(), threading.RLock()
        self.audit, self.custom, self.failures = deque([], 1024), deque([], 512), deque([], 128)
        self.handoff_switch = False
        runtime = os.path.join(directory, 'runtime')
        self.command_path, self.ack_path = [os.path.join(runtime, 'tg-'+part+'.json') for part in ('command', 'ack')]
        self.Main = self.ns['BurpExtender']
        owner = self
        class Observed(self.Main):
            def processProxyMessage(this, request, message):
                tagged = owner.tagged(message.getMessageInfo())
                manual = tagged and '/scope/manual?' in tagged['line']
                if manual:
                    # Same actual IInterceptedProxyMessage before/main/after.
                    message.setInterceptAction(message.ACTION_DO_INTERCEPT)
                before, start = int(message.getInterceptAction()), System.nanoTime()
                try: owner.Main.processProxyMessage(this, request, message)
                finally:
                    if tagged:
                        with owner.lock:
                            owner.audit.append(dict(request=bool(request), before=before,
                                after=int(message.getInterceptAction()), reference=int(message.getMessageReference()),
                                line=tagged['line'], run=tagged['run'], manual=bool(manual),
                                elapsed_ms=(System.nanoTime()-start)/1e6))
            def _report_workflow_error(this, result):
                with owner.lock: owner.failures.append(dict(code=result.error_code, status=result.status))
                owner.Main._report_workflow_error(this, result)
            def extensionUnloaded(this):
                owner.stop.set()
                owner.Main.extensionUnloaded(this)
        class RootCallbacks(object):
            def __getattr__(this, name): return getattr(callbacks, name)
            def getExtensionFilename(this): return os.path.join(ROOT, 'BoberProxy.py')
        if SwingUtilities.isEventDispatchThread(): raise ValueError('Load on the extension loader thread')
        self.main = Observed()
        self.Main.registerExtenderCallbacks(self.main, RootCallbacks())
        SwingUtilities.invokeAndWait(lambda: None)
        if self.main.ui is None: raise ValueError('Root UI did not initialize')
        ui = self.main.ui
        original_custom = ui.run_user_code
        def custom(a, timeout=500, b=None, c=None):
            if b is not None and re.match(r'^tg-[A-Za-z0-9_-]{1,100}$', unicode(b)):
                with owner.lock: owner.custom.append(dict(a=a, b=b, csrf=c))
            return original_custom(a, timeout, b, c)
        ui.run_user_code = custom
        original_authorize = ui.sessions.authorize
        def authorize(context, proof, handoff=None):
            if handoff is not None and owner.handoff_switch:
                owner.handoff_switch = False
                # Deterministic generation replacement after final guard, before
                # production's shared-lock authorization. No fake network call.
                done = threading.Event()
                def change():
                    try: ui._apply_scope(owner.ns['TargetScopePolicy'](ORIGINS['B']))
                    finally: done.set()
                SwingUtilities.invokeLater(change)
                if not done.wait(3): raise ValueError('TG05 EDT switch deadline')
            return original_authorize(context, proof, handoff)
        ui.sessions.authorize = authorize
        callbacks.setExtensionName('BoberProxy Target Scope instrumented validation')
        with open(os.path.join(runtime, 'tg-control-session.json'), 'w') as handle:
            json.dump(dict(instance=self.instance, source_sha256=self.hash), handle)
        self.thread = threading.Thread(target=self.commands, name='BoberProxy.TG05.test-control')
        self.thread.setDaemon(True)
        self.thread.start()
        callbacks.printOutput('TG_SCOPE_WIRE READY (tagged loopback 18810-18812 only; fixed scope profiles)')

    def tagged(self, info):
        if info is None: return None
        service = info.getHttpService()
        if service is None or unicode(service.getHost()) not in ('127.0.0.1', 'localhost') or service.getPort() not in (18810,18811,18812): return None
        text = self.ns['_wire_text'](info.getRequest(), self.callbacks.getHelpers())
        line = text.split('\r\n', 1)[0]
        match = re.search(r'\r\nX-Bober-TG: (tg-[A-Za-z0-9_-]{1,100})\r\n', text)
        run = match.group(1) if match else parse_qs(urlsplit(line.split(' ')[1]).query).get('run', [''])[0]
        return dict(run=run, line=line) if re.match(r'^tg-[A-Za-z0-9_-]{1,100}$', run) else None

    def state(self):
        ui = self.main.ui
        with ui.sessions.condition:
            policy, generation = ui.sessions.selection()
            own = policy is None or policy.host == '127.0.0.1' and (policy.origin[0],policy.origin[2]) in (('http',18810),('http',18811),('https',18812))
            with ui.cookieManager.lock: sid = ui.cookieManager.jar.get('sid') if own else None
            token = ui.csrfManager.get_token() if own else None
            def synthetic(value, prefix):
                return value if value is None or unicode(value).startswith(prefix) else '<non-fixture>'
            config = ui._capture_runtime()
            result = dict(scope=policy.label if policy else None, generation=generation,
                sid=synthetic(sid,'sid.'), csrf=synthetic(token,'csrf.'), records=len(ui.sessions.records),
                owner=ui.sessions.owner is not None, waiting=len(ui.sessions.waiting),
                proxy=config.get('proxy'), follow=config.get('follow'), cp=config.get('use_cp'),
                closed=ui._custom_ui_closed, rows=ui.logTableModel.getRowCount())
        with self.lock:
            result.update(audit=list(self.audit), custom=list(self.custom), failures=list(self.failures))
        return result

    def apply(self, command):
        ui, action = self.main.ui, command.get('action')
        if action in ('profile','scope'):
            kind = command.get('kind', 'A')
            if kind not in ORIGINS and kind != 'none': raise ValueError('Unknown fixed origin')
            prefix = '/scope' if command.get('prefix') else ''
            policy = self.ns['TargetScopePolicy'](ORIGINS[kind], prefix) if kind != 'none' else None
            ui._apply_scope(policy)
            if action == 'profile':
                host = '127.0.0.1:' + dict(A='18810',B='18811',T='18812',none='18810')[kind]
                rt = ('POST /scope/action?case=p4yl04dm4rk3r&run=53c0undm4rk3r HTTP/1.1\r\nHost: '+host+
                      '\r\nX-Bober-TG: 53c0undm4rk3r\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\none=p4yl04dm4rk3r&two=53c0undm4rk3r')
                cp_path = '/outside' if command.get('bad_cp') else '/scope/check'
                cp = ('POST '+cp_path+'?run=53c0undm4rk3r HTTP/1.1\r\nHost: '+host+
                      '\r\nX-Bober-TG: 53c0undm4rk3r\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncsrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r')
                for name, text in (('reqTemplateEditor',rt),('checkPageEditor',cp)):
                    getattr(ui,name).setMessage(self.callbacks.getHelpers().stringToBytes(text),True)
                ui.customCodeArea.setText(CUSTOM)
                ui.timeoutField.setText('2000')
                ui.payloadParamField.setText('q'); ui.payloadParam2Field.setText('w')
                ui.csrfRegexArea.setText(ui.csrf_default_pattern)
                def selected(name, desired):
                    field=getattr(ui,name)
                    if bool(field.isSelected()) != bool(desired): field.doClick(0)
                selected('useCheckPageChk',command.get('cp',True))
                selected('useCustomChk',command.get('custom',True))
                selected('autoUpdateChk',True); selected('autoUpdateCsrfChk',True)
                selected('proxyModeBtn',kind != 'none' and command.get('active',True))
                selected('autoFollowRTChk',command.get('follow',True) and command.get('cp',True))
        elif action == 'clear':
            ui.clearCookiesBtn.doClick(0); ui.clearCsrfBtn.doClick(0)
        elif action == 'bad-cp':
            # Mutate AFTER activation, final/static dispatch guard must still win.
            raw = ui.checkPageEditor.getMessage()
            text=self.ns['_wire_text'](raw,self.callbacks.getHelpers()).replace('POST /scope/check','POST /outside')
            ui.checkPageEditor.setMessage(self.callbacks.getHelpers().stringToBytes(text),True)
        elif action == 'handoff-switch': self.handoff_switch=True
        elif action == 'burp-scope':
            from java.net import URL
            self.callbacks.includeInScope(URL('http://127.0.0.1:18811/scope/tg-independent'))
        elif action != 'state': raise ValueError('Unknown fixed TG05 action')
        ui._publish_runtime()
        return self.state()

    def commands(self):
        seen=None
        while not self.stop.wait(.05):
            try:
                if not os.path.isfile(self.command_path) or os.path.getsize(self.command_path)>4096: continue
                try:
                    with open(self.command_path) as handle: command=json.load(handle)
                except (IOError,ValueError): continue
                if command.get('instance')!=self.instance or not command.get('id') or command['id']==seen: continue
                seen=command['id']; done=threading.Event()
                result=dict(instance=self.instance,id=seen,source_sha256=self.hash)
                def invoke():
                    try: result.update(ok=True,state=self.apply(command))
                    except (Exception,Throwable): result.update(ok=False,error=traceback.format_exc())
                    finally: done.set()
                SwingUtilities.invokeLater(invoke)
                while not done.wait(.1):
                    if self.stop.isSet(): return
                with open(self.ack_path,'w') as handle: json.dump(result,handle,ensure_ascii=True)
            except (Exception,Throwable):
                self.callbacks.printError('TG05 controller error:\n'+traceback.format_exc()); self.stop.set()
