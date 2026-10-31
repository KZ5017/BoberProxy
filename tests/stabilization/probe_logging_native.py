# -*- coding: utf-8 -*-
"""Finite private K08-K09 native/Swing checks. No traffic or live-main settings."""
import argparse
import hashlib
import json
import os
import sys
import threading
import time
import traceback
import unittest
from StringIO import StringIO
from javax.swing import JPanel, SwingUtilities, JTable
from javax.swing.event import TableModelListener, TableModelEvent
from java.lang import System, Class, Throwable
from java.net import URL
from burp import IHttpService
from source_harness import ROOT, Helpers, CapturedOutput, as_text, as_bytes, RequestInfo
from probe_template_native import load_source, java_bytes
from test_log_storage import LogStorageTests
from burp_k089_storage_probe import SyntheticMessage


class NativeHelpers(Helpers):
    """Standalone parser/service fixture; actual Burp run uses real helpers."""
    def stringToBytes(self,value): return java_bytes(value)
    def buildHttpService(self,host,port,protocol):
        class Service(IHttpService):
            def getHost(self): return host
            def getPort(self): return port
            def getProtocol(self): return 'https' if protocol in (True,'https') else 'http'
        return Service()
    def analyzeRequest(self,message):
        data=message.getRequest() if hasattr(message,'getRequest') else message
        class Request(RequestInfo):
            def getMethod(self): return as_text(self.data).split()[0]
            def getUrl(self):
                service=message.getHttpService()
                return URL('%s://%s:%d%s' % (service.getProtocol(),service.getHost(),service.getPort(),as_text(self.data).split()[1]))
        return Request(as_bytes(as_text(data)))
    def analyzeResponse(self,data): return RequestInfo(as_bytes(as_text(data)))


def run_checks(actual_callbacks=None):
    ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
    ns['_probe_threads']=[]
    checks,errors,current,gates={},[],[],[]
    class NativeLogs(LogStorageTests):
        @classmethod
        def setUpClass(cls): cls.ns=ns
    output=StringIO()
    result=unittest.TextTestRunner(stream=output,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeLogs))
    checks['native_storage_contracts']=result.wasSuccessful()
    if not result.wasSuccessful(): errors.append(output.getvalue())
    helpers=actual_callbacks.getHelpers() if actual_callbacks else NativeHelpers()
    counts={'request':0,'response':0}
    class CountingHelpers(object):
        def __getattr__(self,name): return getattr(helpers,name)
        def analyzeRequest(self,*args):
            counts['request']+=1
            return helpers.analyzeRequest(*args)
        def analyzeResponse(self,*args):
            counts['response']+=1
            return helpers.analyzeResponse(*args)
    counted=CountingHelpers()
    def edt(operation):
        failures=[]
        def invoke():
            try: operation()
            except (BaseException,Throwable): failures.append(traceback.format_exc())
        if SwingUtilities.isEventDispatchThread(): invoke()
        else: SwingUtilities.invokeAndWait(invoke)
        if failures: raise AssertionError('\n'.join(failures))
    def wait(predicate):
        end=time.time()+5
        while time.time()<end:
            values=[]
            edt(lambda:values.append(bool(predicate())))
            if values[0]: return True
            time.sleep(0.01)
        return False
    class Editor(object):
        def __init__(self): self.value=None
        def getComponent(self): return JPanel()
        def getMessage(self): return self.value
        def setMessage(self,value,is_request):
            if value is None: raise ValueError('Message cannot be null (real Burp editor contract)')
            self.value=value
    class Callbacks(object):
        def __init__(self): self.site=[]; self.scope=[]; self.registrations=[]
        def getHelpers(self): return counted
        def setExtensionName(self,name): pass
        def createMessageEditor(self,controller,editable):
            return actual_callbacks.createMessageEditor(controller,editable) if actual_callbacks else Editor()
        def printError(self,text): errors.append(str(text))
        def addSuiteTab(self,tab): self.registrations.append('tab')
        def removeSuiteTab(self,tab): pass
        def registerExtensionStateListener(self,listener): pass
        def registerHttpListener(self,listener): self.registrations.append('http')
        def removeHttpListener(self,listener): pass
        def registerProxyListener(self,listener): self.registrations.append('proxy')
        def removeProxyListener(self,listener): pass
        def addToSiteMap(self,message):
            self.site.append(as_text(message.getRequest()))
        def includeInScope(self,url): self.scope.append(str(url))
    extension=None
    try:
        cb=Callbacks()
        extension=ns['BurpExtender']()
        with CapturedOutput(): extension.registerExtenderCallbacks(cb)
        edt(lambda:None)
        ui=extension.ui
        current.append(ui)
        checks['source_startup_on_edt']=ui._creation_on_edt and cb.registrations==['tab','http','proxy']
        baseline=[]
        edt(lambda:baseline.append(len(JTable().getSelectionModel().getListSelectionListeners())))
        checks['one_selection_listener']=len(ui.table.getSelectionModel().getListSelectionListeners())==baseline[0]+1
        checks['one_explicit_sorter']=ui.table.getRowSorter()==ui.rowSorter
        checks['no_initial_files_or_workers']=ui._log_archive.root is None and ui._log_writer.worker is None and ui._log_io.worker is None
        # Own fixture only: stop its timer to make burst notification counting deterministic.
        edt(lambda:ui._filter_timer.stop())
        def message(index):
            request=helpers.stringToBytes('GET /row/%d HTTP/1.1\r\nHost: 127.0.0.1:18765\r\n\r\n' % index)
            response=helpers.stringToBytes('HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nABC')
            return SyntheticMessage(helpers,request,response)
        extension.processHttpMessage(4,True,message(0))
        checks['request_events_skip_analysis']=counts=={'request':0,'response':0}
        edt(lambda:ui.pauseBtn.setSelected(True))
        edt(ui._publish_runtime)
        extension.processHttpMessage(4,False,message(0))
        checks['paused_events_skip_analysis']=counts=={'request':0,'response':0}
        edt(lambda:ui.pauseBtn.setSelected(False))
        edt(ui._publish_runtime)
        for index in range(32): extension.processHttpMessage(4,False,message(index))
        checks['metadata_analyzed_once_per_response']=counts=={'request':32,'response':32}
        end=time.time()+5
        while len(ui._log_writer.results)<32 and time.time()<end: time.sleep(0.01)
        notifications=[]
        class Listener(TableModelListener):
            def tableChanged(self,event):
                if event.getType()==TableModelEvent.INSERT:
                    notifications.append((event.getFirstRow(),event.getLastRow()))
        edt(lambda:ui.logTableModel.addTableModelListener(Listener()))
        edt(ui._filter_tick)
        checks['single_burst_notification']=notifications==[(0,31)]
        def replacement_during_batch():
            store=ns['LogStore']()
            model=ns['LogTableModel'](store)
            events=[]
            model.fireTableRowsInserted=lambda a,b:events.append(('insert',a,b))
            model.fireTableDataChanged=lambda:events.append(('reset',))
            model.begin_batch()
            for unused in range(3):
                model.add_entry_top(store.add('t','h','GET','/',200,1,0,None),True)
            model.displayed=[store.entries[0]]
            model.fireTableDataChanged()
            model.add_entry_top(store.add('t','h','GET','/new',200,1,0,None),True)
            model.end_batch()
            checks['single_burst_notification']=checks['single_burst_notification'] and events==[('insert',0,2),('reset',),('insert',0,0)]
        edt(replacement_during_batch)
        checks['all_rows_newest_first']=len(ui.logStore.entries)==32 and [e.index for e in ui.logTableModel.displayed]==list(range(32,0,-1))
        checks['stored_rows_hold_no_bodies']=all(isinstance(e.messageInfo,ns['StoredLogMessage']) and not hasattr(e.messageInfo,'_log_response') for e in ui.logStore.entries)
        checks['raw_budget_released_after_persist']=ui._log_budget.used==0
        first=ui.logStore.entries[0].messageInfo
        checks['disk_roundtrip_exact']=as_text(first.getRequest()).startswith('GET /row/31 ') and as_text(first.getResponse()).endswith('ABC')
        snapshot=first.snapshot(helpers)
        native_request=Class.forName('burp.IHttpRequestResponse').getMethod('getRequest',[]).invoke(snapshot,[])
        checks['frozen_snapshot_native_interface']=as_text(native_request).startswith('GET /row/31 ')
        def forbidden_edt_read():
            try:
                first.getResponse()
                checks['edt_disk_read_rejected']=False
            except ns['LogStorageError']:
                checks['edt_disk_read_rejected']=True
        edt(forbidden_edt_read)
        edt(lambda:ui._filter_timer.start())
        entered,release=threading.Event(),threading.Event()
        gates.append(release)
        original=first.snapshot
        def held(helpers):
            entered.set()
            release.wait(3)
            return original(helpers)
        first.snapshot=held
        edt(lambda:ui.table.setRowSelectionInterval(0,0))
        checks['viewer_read_is_background']=entered.wait(3)
        edt(lambda:ui.table.setRowSelectionInterval(1,1))
        release.set()
        checks['late_viewer_cannot_replace_new_selection']=wait(lambda:ui.controller.getRequest() is not None and as_text(ui.controller.getRequest()).startswith('GET /row/30 '))
        edt(ui.sort_by_index_asc)
        edt(lambda:ui.table.setRowSelectionInterval(0,0))
        checks['sorted_selection_uses_same_message']=wait(lambda:ui.controller.getRequest() is not None and as_text(ui.controller.getRequest()).startswith('GET /row/0 '))
        edt(ui._load_template_from_viewer)
        checks['template_load_from_disk_is_exact']=wait(lambda:ui.reqTemplateEditor.getMessage() is not None and as_text(ui.reqTemplateEditor.getMessage()).startswith('GET /row/0 '))
        edt(lambda:ui.table.addRowSelectionInterval(3,3))
        edt(ui.add_selected_to_sitemap)
        checks['sitemap_and_scope_preserve_sorted_selection']=wait(lambda:len(cb.site)==2 and len(cb.scope)==2) and all(any('/row/%d ' % n in r for r in cb.site) for n in (0,3))
        selected_paths=[ui.logStore.entries[-1].messageInfo.path,ui.logStore.entries[-4].messageInfo.path]
        edt(ui.clear_selected)
        checks['selected_clear_preserves_other_rows']=wait(lambda:len(ui.logStore.entries)==30 and all(not os.path.exists(path) for path in selected_paths))
        root=ui._log_archive.root
        extension.extensionUnloaded()
        edt(lambda:None)
        for owner in (ui._log_writer,ui._filter_worker,ui._log_io):
            if owner.worker is not None: owner.worker.join(5)
        checks['unload_stops_owned_workers_and_releases_content']=(all(owner.worker is None or not owner.worker.is_alive() for owner in (ui._log_writer,ui._filter_worker,ui._log_io))
                                                                 and ui.controller.getRequest() is None and not ui.logStore.entries)
        checks['unload_deletes_owned_directory']=not os.path.exists(root)
        checks['unload_stops_timer']=ui._filter_timer is None
    except (BaseException,Throwable):
        errors.append(traceback.format_exc())
    finally:
        for gate in gates: gate.set()
        if extension is not None: extension.extensionUnloaded()
        for ui in current:
            for owner in (ui._log_writer,ui._filter_worker,ui._log_io):
                if owner.worker is not None: owner.worker.join(5)
        edt(lambda:None)
    return dict(kind='K08-K09-native-Jython-Swing-private-no-network',source_sha256=hashlib.sha256(raw).hexdigest(),
                checks=checks,errors=errors,passed=bool(checks) and all(checks.values()) and not errors,
                logic_cases=result.testsRun,logic_log=output.getvalue(),actual_burp_helpers=bool(actual_callbacks),
                java_version=str(System.getProperty('java.version')),network_requests=0)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    report=run_checks()
    with open(args.report,'w') as handle: json.dump(report,handle,indent=2)
    print(json.dumps(report,indent=2))
    sys.exit(0 if report['passed'] else 1)
