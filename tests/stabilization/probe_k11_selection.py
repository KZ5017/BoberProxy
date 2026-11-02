# -*- coding: utf-8 -*-
"""E45: private native 100k table sorting/selection/export identity; no network.

Message content is in synthetic native snapshots for this index-mapping probe.
Disk/archive scale is tested separately by probe_k11_load.py.
"""
import argparse
import hashlib
import json
import os
import time
import traceback
import uuid
from javax.swing import JPanel, SwingUtilities
from java.lang import System, Throwable
from source_harness import ROOT, as_text
from probe_template_native import load_source
from probe_k11_load import LoadHelpers
from burp_k089_storage_probe import SyntheticMessage


def run(actual_callbacks=None, real_export=False):
    ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
    helpers=actual_callbacks.getHelpers() if actual_callbacks else LoadHelpers()
    checks,errors,current,site,scope_urls={},[],[],[],[]
    prefix='/k11/row/'+uuid.uuid4().hex[:10]+'/' if actual_callbacks else '/k11/row/'
    timings={}
    def edt(fn):
        failures=[]
        def invoke():
            try: fn()
            except (BaseException,Throwable): failures.append(traceback.format_exc())
        SwingUtilities.invokeAndWait(invoke)
        if failures: raise AssertionError('\n'.join(failures))
    def wait(predicate):
        end=time.time()+8
        while time.time()<end:
            values=[]; edt(lambda:values.append(bool(predicate())))
            if values[0]: return True
            time.sleep(.02)
        return False
    class Editor(object):
        def __init__(self): self.value=helpers.stringToBytes('')
        def getComponent(self): return JPanel()
        def getMessage(self): return self.value
        def setMessage(self,value,request): self.value=value
    class Callbacks(object):
        def getHelpers(self): return helpers
        def createMessageEditor(self,*args): return actual_callbacks.createMessageEditor(*args) if actual_callbacks else Editor()
        def addToSiteMap(self,message):
            if real_export: actual_callbacks.addToSiteMap(message)
            site.append(as_text(message.getRequest()).split(' ')[1])
        def includeInScope(self,url):
            if real_export: actual_callbacks.includeInScope(url)
            scope_urls.append(url)
    try:
        edt(lambda:current.append(ns['LoggerUI'](Callbacks(),ns['SimpleMessageController']())))
        ui=current[0]
        store=ns['LogStore']()
        response=helpers.stringToBytes('HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nX')
        for index in range(100000):
            path=prefix+str(index+1)
            message=SyntheticMessage(helpers,helpers.stringToBytes('GET '+path+' HTTP/1.1\r\nHost: 127.0.0.1:18790\r\n\r\n'),response)
            message.setHttpService(helpers.buildHttpService('127.0.0.1',18790,False))
            store.add('fixture','127.0.0.1','GET',path,200,len(response),1,message)
        def install():
            ui.logStore=store; ui.logTableModel.logStore=store
            ui._set_display_rows(store.entries)
        edt(install)
        checks['hundred_thousand_rows']=ui.logTableModel.getRowCount()==100000
        def sort():
            began=System.nanoTime(); ui.sort_by_index_asc(); timings['sort_100k_ascending_ms']=(System.nanoTime()-began)/1e6
        edt(sort)
        edt(lambda:ui.table.setRowSelectionInterval(0,0))
        checks['ascending_first_viewer_exact']=wait(lambda:ui.controller.getRequest() is not None and prefix+'1 ' in as_text(ui.controller.getRequest()))
        edt(ui._load_template_from_viewer)
        checks['template_from_selected_exact']=wait(lambda:prefix+'1 ' in as_text(ui.reqTemplateEditor.getMessage()))
        edt(lambda:ui.table.addRowSelectionInterval(2,2))
        edt(ui.add_selected_to_sitemap)
        checks['sorted_two_exports_exact']=wait(lambda:len(site)==2 and len(scope_urls)==2) and sorted(site)==[prefix+'1',prefix+'3']
        if real_export:
            checks['real_scope_contains_selected_test_urls']=all(actual_callbacks.isInScope(url) for url in scope_urls)
            def actual_site_map():
                messages=actual_callbacks.getSiteMap('http://127.0.0.1:18790'+prefix)
                return sorted(as_text(message.getRequest()).split(' ')[1] for message in messages)
            end=time.time()+8
            actual_paths=actual_site_map()
            while actual_paths!=[prefix+'1',prefix+'3'] and time.time()<end:
                time.sleep(.02); actual_paths=actual_site_map()
            checks['actual_site_map_exact_two_test_messages']=actual_paths==[prefix+'1',prefix+'3']
        edt(ui.clear_selected)
        checks['selected_clear_preserves_remaining']=ui.logTableModel.getRowCount()==99998 and store.entries[-1].index==2
        edt(ui.reset_sorting_to_model_order)
        edt(lambda:ui.table.setRowSelectionInterval(0,0))
        checks['natural_newest_first_viewer_exact']=wait(lambda:ui.controller.getRequest() is not None and prefix+'100000 ' in as_text(ui.controller.getRequest()))
    except (BaseException,Throwable): errors.append(traceback.format_exc())
    finally:
        for ui in current:
            ui.close_custom_runtime(); edt(lambda:None)
            for owner in (ui._custom_executor,ui._filter_worker,ui._log_writer,ui._log_io):
                if owner.worker is not None: owner.worker.join(5)
        checks['owned_ui_and_workers_closed']=all(ui._custom_ui_closed and all(owner.worker is None or not owner.worker.is_alive() for owner in (ui._custom_executor,ui._filter_worker,ui._log_writer,ui._log_io)) for ui in current)
    return dict(kind='K11-100k-native-table-index-identity-not-archive-or-visible-rendering',source_sha256=hashlib.sha256(raw).hexdigest(),actual_burp_helpers=bool(actual_callbacks),real_export=real_export,added_scope_urls=[unicode(url) for url in scope_urls] if real_export else [],checks=checks,errors=errors,timings=timings,passed=bool(checks) and all(checks.values()) and not errors)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report',required=True);args=parser.parse_args()
    if os.path.exists(args.report): raise ValueError('Report exists')
    result=run()
    with open(args.report,'w') as handle:json.dump(result,handle,indent=2)
    print(json.dumps(result,indent=2))
    import sys
    sys.exit(0 if result['passed'] else 1)
