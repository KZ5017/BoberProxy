# -*- coding: utf-8 -*-
"""Test-only entry: unchanged main source, tagged loopback, fixed EDT profiles.

No arbitrary code/regex/path command, no network control socket. All gate waits
are finite. Remove this entry and reload the root source after verification.
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
from java.lang import Throwable as JavaException


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self,callbacks):
        self.directory=os.path.dirname(str(callbacks.getExtensionFilename()))
        sys.path.insert(0,self.directory)
        from source_harness import ROOT
        from probe_template_native import load_source
        ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
        self.ns,self.callbacks=ns,callbacks
        self.hash,self.instance=hashlib.sha256(raw).hexdigest(),uuid.uuid4().hex
        self.stop,self.entered,self.release=threading.Event(),threading.Event(),threading.Event()
        self.lock,self.patterns,self.numbers=threading.Lock(),{},0
        self.callbacks_seen,self.callbacks_done=0,0
        self.gate_armed,self.hooked=False,False
        self.write_gate,self.view_gate=False,False
        self.fail_write,self.fail_read=False,False
        self.hash_messages=False
        self.captured=[]
        self.storage_stats=dict(reads=0,writes=0,edt_io=False,files=0,reading=0)
        self.exports=[]

        runtime=os.path.join(self.directory,'runtime')
        self.command_path=os.path.join(runtime,'k089-command.json')
        self.ack_path=os.path.join(runtime,'k089-ack.json')
        self.Main=ns['BurpExtender']
        wrapper=self
        actual_pattern,actual_numbers=ns['Pattern'],ns['_filter_numbers']
        class CountPattern(object):
            CASE_INSENSITIVE,DOTALL=actual_pattern.CASE_INSENSITIVE,actual_pattern.DOTALL
            @staticmethod
            def compile(pattern,flags=0):
                with wrapper.lock:
                    key=(pattern,int(flags))
                    wrapper.patterns[key]=wrapper.patterns.get(key,0)+1
                return actual_pattern.compile(pattern,flags)
        def count_numbers(values,field):
            with wrapper.lock:
                wrapper.numbers+=1
            return actual_numbers(values,field)
        ns['Pattern'],ns['_filter_numbers']=CountPattern,count_numbers
        def scoped(info):
            if info is None:
                return False
            service=info.getHttpService()
            if service is None or service.getHost()!='127.0.0.1' or service.getPort()!=18772:
                return False
            text=ns['_wire_text'](info.getRequest(),callbacks.getHelpers())
            return '\r\nX-Bober-Test-Run: k089-' in text
        class Instrumented(self.Main):
            def processHttpMessage(self,tool,request,info):
                if scoped(info):
                    if not request:
                        with wrapper.lock:
                            wrapper.callbacks_seen+=1
                    try:
                        if not request and wrapper.hash_messages:
                            with wrapper.lock:
                                wrapper.captured.append(dict(request_sha=wrapper.digest(info.getRequest()),response_sha=wrapper.digest(info.getResponse())))
                        wrapper.Main.processHttpMessage(self,tool,request,info)
                    finally:
                        if not request:
                            with wrapper.lock:
                                wrapper.callbacks_done+=1
            def processProxyMessage(self,request,message):
                if scoped(message.getMessageInfo()):
                    wrapper.Main.processProxyMessage(self,request,message)
            def extensionUnloaded(self):
                wrapper.stop.set()
                wrapper.release.set()
                wrapper.Main.extensionUnloaded(self)
        self.main=Instrumented()
        self.Main.registerExtenderCallbacks(self.main,callbacks)
        callbacks.setExtensionName('BoberProxy K089 instrumented validation')
        with open(os.path.join(runtime,'k089-control-session.json'),'w') as handle:
            json.dump(dict(instance=self.instance,source_sha256=self.hash,target_port=18772),handle)
        self.thread=threading.Thread(target=self.commands,name='BoberProxy.K089.test-control')
        self.thread.setDaemon(True)
        self.thread.start()
        callbacks.printOutput('K089_INSTRUMENTED READY (tagged loopback 18772 only; fixed logging/storage test actions)')
        original_put,original_read=ns['LogArchive'].put,ns['LogArchive'].read
        original_collect,original_snapshot=ns['LogArchive'].collect,ns['StoredLogMessage'].snapshot
        def put(archive,snapshot,epoch):
            with wrapper.lock:
                wrapper.storage_stats['writes']+=1
                wrapper.storage_stats['edt_io'] |= SwingUtilities.isEventDispatchThread()
            if wrapper.write_gate:
                wrapper.write_gate=False
                wrapper.entered.set()
                if not wrapper.release.wait(5): raise IOError('Finite K089 write gate expired')
            if wrapper.fail_write:
                wrapper.fail_write=False
                raise IOError('K089 controlled disk-full equivalent')
            return original_put(archive,snapshot,epoch)
        def read(archive,record,part):
            with wrapper.lock:
                wrapper.storage_stats['reads']+=1
                wrapper.storage_stats['edt_io'] |= SwingUtilities.isEventDispatchThread()
            return original_read(archive,record,part)
        def collect(archive,count=64):
            result=original_collect(archive,count)
            with wrapper.lock:
                wrapper.storage_stats['files']=len(os.listdir(archive.root)) if archive.root and os.path.isdir(archive.root) else 0
            return result
        def snapshot(message,helpers):
            with wrapper.lock: wrapper.storage_stats['reading']+=1
            try:
                if wrapper.view_gate:
                    wrapper.view_gate=False
                    wrapper.entered.set()
                    if not wrapper.release.wait(5): raise IOError('Finite K089 viewer gate expired')
                if wrapper.fail_read:
                    wrapper.fail_read=False
                    raise IOError('K089 controlled read failure')
                result=original_snapshot(message,helpers)
                result._k089_request_sha=wrapper.digest(result.getRequest())
                result._k089_response_sha=wrapper.digest(result.getResponse())
                return result
            finally:
                with wrapper.lock: wrapper.storage_stats['reading']-=1
        ns['LogArchive'].put,ns['LogArchive'].read=put,read
        ns['LogArchive'].collect,ns['StoredLogMessage'].snapshot=collect,snapshot

    def digest(self,value):
        if value is None: return None
        return hashlib.sha256(self.ns['_wire_text'](value,self.callbacks.getHelpers()).encode('latin-1')).hexdigest()

    def state(self):
        ui=self.main.ui
        if ui is None:
            return dict(ready=False)
        with self.lock:
            patterns=[dict(pattern=p,flags=f,count=n) for (p,f),n in sorted(self.patterns.items())]
            numbers=self.numbers
            seen,done=self.callbacks_seen,self.callbacks_done
            stats=dict(self.storage_stats)
            captured=list(self.captured)
            exports=list(self.exports)

        config=ui._capture_runtime()
        text=self.ns['_filter_text']
        loaded=getattr(ui.controller,'_messageInfo',None)
        viewer=dict(request_sha=getattr(loaded,'_k089_request_sha',None),response_sha=getattr(loaded,'_k089_response_sha',None))
        with ui._log_io.condition:
            io_pending=len(ui._log_io.commands)+len(ui._log_io.results)
        return dict(ready=True,source_sha256=self.hash,writer=ui._log_writer.state(),storage=stats,
            raw_bytes=ui._log_budget.used,log_error=ui._log_error,not_accepted=ui._log_not_accepted,
            paused=config.get('paused'),status=str(ui.statusLabel.getText()),viewer=viewer,
            captured=captured,exports=exports,io_pending=io_pending,stored=[dict(index=e.index,path=text(e.path),
            status=int(e.status) if e.status not in ('',None) else None,
            body_len=int(e.body_len) if e.body_len not in ('',None) else None) for e in ui.logStore.entries],
            displayed=[e.index for e in ui.logTableModel.displayed],
            capture_pattern=ui._capture_filter_plan.pattern_text,numbers=list(ui._capture_filter_plan.numbers),
            capture_error=ui._capture_error,display_error=ui._display_error,
            display=ui.display_filters,rebuilding=bool(ui._filter_rebuilding),dirty=ui._filter_dirty,
            worker=ui._filter_worker.state(),rejected=ui._filter_rejected,
            compile_patterns=patterns,parse_numbers=numbers,
            callbacks_seen=seen,callbacks_done=done,
            gate_entered=self.entered.isSet(),epoch=ui._log_generation,
            proxy=config.get('proxy'),use_cp=config.get('use_cp'),custom=config.get('custom')[0])

    def apply(self,action):
        ui=self.main.ui
        if ui is None or ui._custom_ui_closed:
            raise ValueError('Main UI unavailable')
        if not self.hooked:
            wrapper=self
            actual=ui.callbacks_ref
            class ObservedCallbacks(object):
                def __getattr__(self,name): return getattr(actual,name)
                def addToSiteMap(self,message):
                    actual.addToSiteMap(message)
                    with wrapper.lock: wrapper.exports.append(dict(request_sha=wrapper.digest(message.getRequest()),response_sha=wrapper.digest(message.getResponse())))
            ui.callbacks_ref=ObservedCallbacks()
            original=ui._filter_worker.submit
            def submit(operation,apply,key=None):
                if key=='rebuild' and self.gate_armed:
                    self.gate_armed=False
                    def held():
                        self.entered.set()
                        if not self.release.wait(5):
                            raise ValueError('K089 finite rebuild gate timed out')
                        return operation()
                    return original(held,apply,key)
                return original(operation,apply,key)
            ui._filter_worker.submit=submit
            self.hooked=True
        if action=='clear':
            ui.clear_log()
        elif action.startswith('capture-'):
            profiles={'capture-none':('', '', 'Min Len'),
                      'capture-alpha':('TOKEN_ALPHA','','Min Len'),
                      'capture-lower':('token_alpha','','Min Len'),
                      'capture-invalid':('[','','Min Len'),
                      'capture-min':('','2,6','Min Len'),
                      'capture-max':('','2,6','Max Len'),
                      'capture-noteq':('','0,3','Not eq Len'),
                      'capture-bad-number':('','bad','Not eq Len')}
            regex,size,mode=profiles[action]
            ui.regexField.setText(regex)
            ui.sizeField.setText(size)
            ui.lenTypeCombo.setSelectedItem('Response body len')
            ui.compCombo.setSelectedItem(mode)
            for widget in ui.statusChecks.values():
                widget.setSelected(False)
        elif action.startswith('display-'):
            profiles={'display-none':None,'display-tokens':('ResponseContent','TOKEN_ALPHA\nTOKEN_BETA'),
                      'display-status':('Status','204'),'display-comma':('ResponseContent','a{1,3},b'),
                      'display-invalid':('ResponseContent','[')}
            profile=profiles[action]
            if ui._filter_dialog:
                ui._filter_dialog._on_cancel()
            dialog=self.ns['FilterDialog'](ui)
            dialog.load_from_parent()
            for enabled,mode,field in dialog.controls.values():
                enabled.setSelected(False)
                mode.setSelectedItem('eq')
                field.setText('')
            if profile:
                dialog.controls[profile[0]][0].setSelected(True)
                dialog.controls[profile[0]][2].setText(profile[1])
            dialog._on_apply()
        elif action in ('pause','resume'):
            ui.pauseBtn.setSelected(action=='pause')
            ui.toggle_pause()
        elif action in ('gate-write','gate-view'):
            self.entered.clear()
            self.release.clear()
            self.write_gate=action=='gate-write'
            self.view_gate=action=='gate-view'
        elif action=='tiny-budget':
            with ui._log_budget.lock: ui._log_budget.limit=128
        elif action=='normal-budget':
            with ui._log_budget.lock: ui._log_budget.limit=32*1024*1024
            ui.pauseBtn.setSelected(False)
            ui.toggle_pause()
        elif action=='fail-write': self.fail_write=True
        elif action=='fail-read': self.fail_read=True
        elif action=='hash-messages': self.hash_messages=True
        elif action=='select-first': ui.table.setRowSelectionInterval(0,0)
        elif action=='select-next': ui.table.setRowSelectionInterval(1,1)
        elif action=='select-two':
            ui.table.setRowSelectionInterval(0,0)
            ui.table.addRowSelectionInterval(2,2)
        elif action=='sort-asc': ui.sort_by_index_asc()
        elif action=='clear-selected': ui.clear_selected()
        elif action=='export': ui.add_selected_to_sitemap()
        elif action=='gate':
            self.entered.clear()
            self.release.clear()
            self.gate_armed=True
            ui._refresh_table_display()
        elif action=='release':
            self.release.set()
        elif action!='state':
            raise ValueError('Unknown K089 profile')
        ui._publish_runtime()
        return self.state()

    def commands(self):
        seen=None
        while not self.stop.wait(0.05):
            try:
                if not os.path.isfile(self.command_path) or os.path.getsize(self.command_path)>16384:
                    continue
                try:
                    with open(self.command_path) as handle:
                        request=json.load(handle)
                except (IOError,ValueError):
                    continue
                if request.get('instance')!=self.instance or not request.get('id') or request['id']==seen:
                    continue
                seen=request['id']
                complete=threading.Event()
                response=dict(instance=self.instance,id=seen,source_sha256=self.hash)
                def invoke():
                    try:
                        response['state']=self.apply(request['action'])
                        response['ok']=True
                    except (Exception,JavaException):
                        response.update(ok=False,error=traceback.format_exc())
                    finally:
                        complete.set()
                SwingUtilities.invokeLater(invoke)
                while not complete.wait(0.1):
                    if self.stop.isSet():
                        return
                with open(self.ack_path,'w') as handle:
                    json.dump(response,handle,ensure_ascii=True)
            except (Exception,JavaException):
                if not self.stop.isSet():
                    self.callbacks.printError('K089 controller error:\n'+traceback.format_exc())
                self.stop.set()
