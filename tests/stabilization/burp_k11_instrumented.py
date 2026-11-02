# -*- coding: utf-8 -*-
"""K11 live test entry: unchanged root source, tagged loopback 18790 only.

Fixed file-channel actions, bounded telemetry, no arbitrary code/path commands.
Never run its standalone smoke concurrently with this loaded live entry.
"""
from burp import IBurpExtender
from javax.swing import SwingUtilities, Timer
from javax.swing.event import TableModelListener, TableModelEvent
from java.lang import System, Runtime, Throwable
from java.lang.management import ManagementFactory
from collections import deque, OrderedDict
import hashlib
import json
import os
import sys
import threading
import traceback
import uuid
from urlparse import urlsplit, parse_qs

PORT = 18790
CUSTOM = '''def custom_codeblock(a, b, c):
    import time
    if a.startswith('k11-error-'): raise ValueError('K11 controlled transform failure')
    if a.startswith('k11-bad-'): return a, b
    if a.startswith('k11-cp-error-') and c is not None: raise ValueError('K11 controlled CheckPage failure')
    if a.startswith('k11-slow-') or a.startswith('k11-cp-slow-') and c is not None: time.sleep(.3)
    if a.startswith('k11-busy-'): time.sleep(.6)
    return a, b, c
'''


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self.directory = os.path.dirname(unicode(callbacks.getExtensionFilename()))
        sys.path.insert(0, self.directory)
        from source_harness import ROOT
        from probe_template_native import load_source
        self.ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
        self.hash, self.instance = hashlib.sha256(raw).hexdigest(), uuid.uuid4().hex
        self.callbacks, self.lock, self.stop = callbacks, threading.Lock(), threading.Event()
        self.metrics = {key:deque([],200000) for key in ('http_ms','proxy_ms','appearance_ms','heartbeat_ms')}
        self.pending, self.audit, self.failures = OrderedDict(), deque([],4096), deque([],256)
        self.custom_calls = deque([],4096)
        self.counts = dict(http=0,proxy=0,inserts=0,lag_evicted=0,custom=0,writes=0,reads=0,edt_io=False)
        self.profile, self.measure, self.fail_write, self.fail_read = 'passive', False, False, False
        self.last_heartbeat = System.nanoTime()
        self.initial_budget = self.ns['WORKFLOW_TIMEOUT_MS']
        runtime = os.path.join(self.directory,'runtime')
        if not os.path.isdir(runtime): os.makedirs(runtime)
        prefix = getattr(self,'channel_prefix','k11')
        self.command_path, self.ack_path = [os.path.join(runtime,prefix+'-'+name+'.json') for name in ('command','ack')]
        self.Main = self.ns['BurpExtender']
        owner = self
        class Observed(self.Main):
            def processHttpMessage(this, tool, request, info):
                if not owner.scoped(info): return
                if request: return owner.Main.processHttpMessage(this,tool,request,info)
                path = owner.path(info)
                config = this.ui._capture_runtime()
                if owner.measure and not config.get('paused') and config.get('capture_filter_plan').pattern is None:
                    with owner.lock:
                        owner.pending[path] = System.nanoTime()
                        if len(owner.pending)>4096:
                            owner.pending.popitem(last=False)
                            owner.counts['lag_evicted'] += 1
                began = System.nanoTime()
                try: owner.Main.processHttpMessage(this,tool,request,info)
                finally:
                    with owner.lock:
                        owner.counts['http'] += 1
                        if owner.measure: owner.metrics['http_ms'].append((System.nanoTime()-began)/1e6)
            def processProxyMessage(this, request, message):
                if not owner.scoped(message.getMessageInfo()): return
                before, path = message.getInterceptAction(), owner.path(message.getMessageInfo())
                began = System.nanoTime()
                try: owner.Main.processProxyMessage(this,request,message)
                finally:
                    with owner.lock:
                        owner.counts['proxy'] += 1
                        if owner.measure: owner.metrics['proxy_ms'].append((System.nanoTime()-began)/1e6)
                        owner.audit.append(dict(request=bool(request),before=int(before),after=int(message.getInterceptAction()),path=path))
            def _report_workflow_error(this, result):
                with owner.lock: owner.failures.append(dict(code=result.error_code,status=result.status))
                owner.Main._report_workflow_error(this,result)
            def extensionUnloaded(this):
                owner.stop.set()
                def detach():
                    if hasattr(owner,'heartbeat'): owner.heartbeat.stop()
                    if hasattr(owner,'listener'): this.ui.logTableModel.removeTableModelListener(owner.listener)
                SwingUtilities.invokeLater(detach)
                owner.Main.extensionUnloaded(this)
        self.main = Observed()
        class RootCallbacks(object):
            def __getattr__(this,name): return getattr(callbacks,name)
            def getExtensionFilename(this): return os.path.join(ROOT,'BoberProxy.py')
        if SwingUtilities.isEventDispatchThread(): raise ValueError('Load the K11 entry from the extension loader thread')
        self.Main.registerExtenderCallbacks(self.main,RootCallbacks())
        SwingUtilities.invokeAndWait(lambda:None)
        if self.main.ui is None: raise ValueError('K11 main source did not initialize')
        callbacks.setExtensionName('BoberProxy K11 instrumented validation')
        ui = self.main.ui
        original_put, original_read = self.ns['LogArchive'].put, self.ns['LogArchive'].read
        def put(archive,snapshot,epoch):
            with owner.lock:
                owner.counts['writes'] += 1
                owner.counts['edt_io'] |= SwingUtilities.isEventDispatchThread()
            if owner.fail_write:
                owner.fail_write = False
                raise IOError('K11 controlled own-archive write failure')
            return original_put(archive,snapshot,epoch)
        def read(archive,record,part):
            with owner.lock:
                owner.counts['reads'] += 1
                owner.counts['edt_io'] |= SwingUtilities.isEventDispatchThread()
            if owner.fail_read:
                owner.fail_read = False
                raise IOError('K11 controlled own-archive read failure')
            return original_read(archive,record,part)
        self.ns['LogArchive'].put, self.ns['LogArchive'].read = put, read
        original_custom = ui.run_user_code
        def custom(a, timeout=500, b=None, c=None):
            with owner.lock:
                owner.counts['custom'] += 1
                owner.custom_calls.append(dict(payload1=a,payload2=b,csrf=c))
            return original_custom(a,timeout,b,c)
        ui.run_user_code = custom
        class Listener(TableModelListener):
            def tableChanged(this,event):
                if event.getType()!=TableModelEvent.INSERT: return
                now = System.nanoTime()
                with owner.lock:
                    owner.counts['inserts'] += event.getLastRow()-event.getFirstRow()+1
                    for row in range(event.getFirstRow(),event.getLastRow()+1):
                        entry = ui.logTableModel.displayed[row]
                        start = owner.pending.pop(unicode(entry.path),None)
                        if start is not None: owner.metrics['appearance_ms'].append((now-start)/1e6)
        self.listener = Listener()
        def beat(event):
            now = System.nanoTime()
            with owner.lock:
                if owner.measure: owner.metrics['heartbeat_ms'].append(max(0,(now-owner.last_heartbeat)/1e6-50))
                owner.last_heartbeat = now
        def install():
            ui.logTableModel.addTableModelListener(self.listener)
            self.heartbeat = Timer(50,beat)
            self.heartbeat.start()
        SwingUtilities.invokeAndWait(install)
        with open(os.path.join(runtime,prefix+'-control-session.json'),'w') as handle:
            json.dump(dict(instance=self.instance,source_sha256=self.hash,target_port=PORT,
                           scope_version=2,burp_version=list(callbacks.getBurpVersion())),handle)
        self.thread = threading.Thread(target=self.commands,name='BoberProxy.K11.test-control')
        self.thread.setDaemon(True)
        self.thread.start()
        callbacks.printOutput('K11_INSTRUMENTED READY (tagged loopback 18790 only; bounded telemetry; fixed profiles)')

    def path(self,info):
        return self.ns['_wire_text'](info.getRequest(),self.callbacks.getHelpers()).split(' ',2)[1]

    def scoped(self,info):
        if info is None: return False
        service = info.getHttpService()
        if service is None or service.getHost()!='127.0.0.1' or service.getPort()!=PORT: return False
        text = self.ns['_wire_text'](info.getRequest(),self.callbacks.getHelpers())
        if '\r\nX-Bober-Test-Run: k11-' in text: return True
        # Production's minimal redirect GET intentionally omits custom headers.
        # Keep the tag in its raw URL query within our fixed loopback routes.
        target = urlsplit(text.split(' ',2)[1])
        return target.path.startswith('/k11/') and any(value.startswith('k11-') for value in parse_qs(target.query).get('run',[]))

    def state(self):
        ui = self.main.ui
        config = ui._capture_runtime()
        with self.lock:
            counts, audit, failures = dict(self.counts),list(self.audit),list(self.failures)
        with ui._log_archive.lock:
            archive = dict(records=len(ui._log_archive.records),retired=sum(len(d) for d in ui._log_archive.retired),
                           deleted=len(ui._log_archive.deleted),writers=ui._log_archive.writers,
                           cleanup_error=ui._log_archive.cleanup_error,root=ui._log_archive.root)
        return dict(source_sha256=self.hash,scope_version=2,profile=self.profile,counts=counts,audit=audit[-32:],failures=failures,
                    stored=len(ui.logStore.entries),displayed=ui.logTableModel.getRowCount(),
                    first=ui.logStore.entries[0].index if ui.logStore.entries else None,
                    last=ui.logStore.entries[-1].index if ui.logStore.entries else None,
                    writer=ui._log_writer.state(),filter=ui._filter_worker.state(),archive=archive,
                    raw_bytes=ui._log_budget.used,raw_limit=ui._log_budget.limit,
                    rejected=ui._log_not_accepted,log_error=ui._log_error,
                    display_error=ui._display_error,rebuilding=bool(ui._filter_rebuilding),dirty=ui._filter_dirty,
                    paused=config.get('paused'),proxy=config.get('proxy'),use_cp=config.get('use_cp'),
                    token=ui.csrfManager.get_token(),cookies=ui.cookieManager.jar.copy(),
                    custom_text=unicode(ui.customStatusArea.getText()),status=unicode(ui.statusLabel.getText()),
                    config_version=config.version,workflow_budget_ms=self.ns['WORKFLOW_TIMEOUT_MS'],
                    own_closed=ui._custom_ui_closed,heap_used_bytes=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory(),
                    thread_count=ManagementFactory.getThreadMXBean().getThreadCount())

    def template(self,path):
        return ('POST '+path+'?run=p4yl04dm4rk3r HTTP/1.1\r\nHost: 127.0.0.1:18790\r\n'
                'X-Bober-Test-Run: p4yl04dm4rk3r\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n'
                'csrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r')

    def apply(self,action):
        ui = self.main.ui
        if action=='state': return self.state()
        if ui._custom_ui_closed: raise ValueError('Own instance unloaded')
        def selected(widget,value):
            if bool(widget.isSelected())!=value: widget.doClick(0)
        if action.startswith('profile-'):
            profile = action[8:]
            allowed = ('passive','normal','rt-only','empty-cp','cp-error','custom-error','bad-return','top-timeout',
                       'function-timeout','cp-timeout','invalid-timeout','busy','close','redirect-off','redirect-on',
                       'loop','limit','workflow-timeout','held')
            if profile not in allowed: raise ValueError('Unknown fixed profile')
            self.profile = profile
            selected(ui.proxyModeBtn,profile!='passive')
            selected(ui.useCheckPageChk,profile not in ('passive','rt-only','busy'))
            selected(ui.useCustomChk,profile not in ('passive','rt-only','close','workflow-timeout'))
            selected(ui.autoUpdateChk,profile!='passive')
            selected(ui.autoUpdateCsrfChk,profile!='passive')
            selected(ui.autoFollowRTChk,profile in ('redirect-on','loop','limit'))
            selected(ui.pauseBtn,False)
            self.ns['WORKFLOW_TIMEOUT_MS'] = 100 if profile=='workflow-timeout' else self.initial_budget
            path = {'close':'/accept-then-close','redirect-on':'/k11/redirect/start','redirect-off':'/k11/redirect/start',
                    'loop':'/k11/loop','limit':'/k11/hops/0','workflow-timeout':'/k11/slow-action','held':'/k11/held-action'}.get(profile,'/workflow/action')
            ui.reqTemplateEditor.setMessage(ui.helpers.stringToBytes(self.template(path)),True)
            ui.checkPageEditor.setMessage(ui.helpers.stringToBytes('' if profile=='empty-cp' else self.template('/workflow/check')),True)
            ui.customCodeArea.setText(('import time\ntime.sleep(.3)\n' if profile=='top-timeout' else '')+CUSTOM)
            ui.timeoutField.setText('50' if profile in ('top-timeout','function-timeout','cp-timeout') else 'abc' if profile=='invalid-timeout' else '2000')
            ui.payloadParamField.setText('q'); ui.payloadParam2Field.setText('w')
            ui.csrfRegexArea.setText(ui.csrf_default_pattern)
            ui._on_clear_cookies(); ui._on_clear_csrf()
        elif action=='clear': ui.clear_log()
        elif action=='clear-state': ui._on_clear_cookies(); ui._on_clear_csrf()
        elif action in ('pause','resume'): selected(ui.pauseBtn,action=='pause')
        elif action=='proxy-off': selected(ui.proxyModeBtn,False)
        elif action in ('metrics-reset','metrics-stop'):
            with self.lock:
                self.measure = action=='metrics-reset'
                if self.measure:
                    for values in self.metrics.values(): values.clear()
                    self.pending.clear()
                    for key in self.counts: self.counts[key] = False if key=='edt_io' else 0
                    self.audit.clear(); self.failures.clear(); self.custom_calls.clear()
                    self.last_heartbeat = System.nanoTime()
        elif action=='fail-write': self.fail_write=True
        elif action=='fail-read': self.fail_read=True
        elif action=='select-first':
            if ui.table.getRowCount(): ui.table.setRowSelectionInterval(0,0)
        elif action=='clear-selected': ui.clear_selected()
        elif action=='tiny-budget':
            with ui._log_budget.lock: ui._log_budget.limit=128
        elif action=='normal-budget':
            with ui._log_budget.lock: ui._log_budget.limit=32*1024*1024
            ui.clear_log()
            selected(ui.pauseBtn,False)
        elif action in ('display-bytes','display-none'):
            candidate = {key:dict(active=False,mode='eq',values=[]) for key in ui.display_filters}
            if action=='display-bytes': candidate['Path']=dict(active=True,mode='eq',values=['/bytes'])
            ui._apply_display_filters(candidate)
        elif action=='unload': self.main.extensionUnloaded()
        else: raise ValueError('Unknown K11 action')
        ui._publish_runtime()
        return self.state()

    def commands(self):
        seen = None
        while not self.stop.wait(.025):
            try:
                if not os.path.isfile(self.command_path) or os.path.getsize(self.command_path)>4096: continue
                try:
                    with open(self.command_path) as handle: request=json.load(handle)
                except (IOError,ValueError): continue
                if request.get('instance')!=self.instance or not request.get('id') or request['id']==seen: continue
                seen = request['id']
                result, complete = {},threading.Event()
                def invoke():
                    try: result.update(state=self.apply(request['action']),ok=True)
                    except (BaseException,Throwable): result.update(ok=False,error=traceback.format_exc())
                    finally: complete.set()
                SwingUtilities.invokeLater(invoke)
                while not complete.wait(.1):
                    if self.stop.isSet(): return
                if request['action']=='metrics-stop':
                    with self.lock:
                        result['metrics']={key:list(values) for key,values in self.metrics.items()}
                        result['custom_calls']=list(self.custom_calls)
                result.update(instance=self.instance,id=seen,source_sha256=self.hash)
                temporary = self.ack_path+'.tmp'
                with open(temporary,'w') as handle: json.dump(result,handle)
                # The controller tolerates a partial read on Windows; do not
                # delete another path or retry any HTTP operation.
                with open(temporary,'rb') as source:
                    with open(self.ack_path,'wb') as target: target.write(source.read())
                os.unlink(temporary)
            except (BaseException,Throwable):
                if not self.stop.isSet(): self.callbacks.printError('K11 control error:\n'+traceback.format_exc())
                self.stop.set()
