# -*- coding: utf-8 -*-
"""Real Java Pattern and finite Swing/private-dialog checks; no network."""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import time
import traceback
import unittest
import threading
from StringIO import StringIO
from javax.swing import JTable, JPanel, SwingUtilities
from javax.swing.table import TableRowSorter
from burp import IMessageEditorController
from java.lang import System
from source_harness import ROOT, Helpers, Response
from probe_template_native import load_source
from test_filters import FilterTests


def run_checks(actual_callbacks=None):
    helpers=actual_callbacks.getHelpers() if actual_callbacks else Helpers()
    ns,raw=load_source(os.path.join(ROOT,'BoberProxy.py'))
    ns['_probe_threads']=[]
    checks,errors,current,dialogs={ },[],[],[]
    class NativeFilters(FilterTests):
        @classmethod
        def setUpClass(cls):
            cls.ns=ns
    output=StringIO()
    result=unittest.TextTestRunner(stream=output,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeFilters))
    checks['native_filter_regressions']=result.wasSuccessful()
    if not result.wasSuccessful():
        errors.append(output.getvalue())
    def edt(operation):
        failed=[]
        def invoke():
            try:
                operation()
            except BaseException:
                failed.append(traceback.format_exc())
        if SwingUtilities.isEventDispatchThread():
            invoke()
        else:
            SwingUtilities.invokeAndWait(invoke)
        if failed:
            raise AssertionError('\n'.join(failed))
    def wait_for(predicate):
        end=time.time()+5
        while time.time()<end:
            values=[]
            edt(lambda:values.append(bool(predicate())))
            if values[0]:
                return True
            time.sleep(0.01)
        return False
    class Controller(IMessageEditorController):
        def getHttpService(self):
            return helpers.buildHttpService('127.0.0.1',18765,False)
        def getRequest(self):
            return helpers.stringToBytes('GET /k07-editor-only HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        def getResponse(self):
            return None
    class Editor(object):
        def getComponent(self):
            return JPanel()
        def getMessage(self):
            return None
    class Callbacks(object):
        def getHelpers(self):
            return helpers
        def createMessageEditor(self,controller,editable):
            return actual_callbacks.createMessageEditor(Controller(),editable) if actual_callbacks else Editor()
    try:
        def create():
            cb=Callbacks()
            current.append(ns['LoggerUI'](cb,ns['SimpleMessageController'](),None,cb))
        edt(create)
        ui=current[0]
        checks['filter_timer_on_edt_ui']=ui._creation_on_edt and ui._filter_timer.isRunning()
        regex=ns['Pattern']
        checks['capture_java_flags_unchanged']=not regex.compile('abc',0).matcher('ABC').find()
        flags=regex.CASE_INSENSITIVE | regex.DOTALL
        checks['display_java_flags_unchanged']=bool(regex.compile('abc.*xyz',flags).matcher('ABC\nxyz').find())
        checks['no_implicit_unicode_case_flag']=not regex.compile(u'\u00e4',flags).matcher(u'\u00c4').find()
        def populate():
            message=Response(helpers.stringToBytes('HTTP/1.1 200 OK\r\nX-Tag: mark\r\n\r\nAbC\na,b aa'))
            length=len(message.getResponse())
            ui.logStore.entries=[ns['LogEntry'](i,'t','demo','GET','/row',200,length,10,message) for i in range(10000,0,-1)]
            ui.logStore._counter=10000
            dialog=ns['FilterDialog'](ui)
            dialogs.append(dialog)
            dialog.load_from_parent()
            enabled,mode,field=dialog.controls['ResponseContent']
            enabled.setSelected(True)
            field.setText('a{1,3}\na,b')
            dialog._on_apply()
        edt(populate)
        checks['two_lines_preserve_embedded_commas']=wait_for(lambda: ui.display_filters['ResponseContent']['values']==['a{1,3}','a,b'])
        checks['ten_thousand_matches_applied']=wait_for(lambda:len(ui.logTableModel.displayed)==10000 and not ui._filter_rebuilding)
        checks['display_filter_keeps_store']=len(ui.logStore.entries)==10000
        valid=ui._display_filter_plan
        def invalid():
            dialog=ns['FilterDialog'](ui)
            dialogs.append(dialog)
            dialog.load_from_parent()
            dialog.controls['ResponseContent'][2].setText('[')
            dialog._on_apply()
        edt(invalid)
        checks['invalid_dialog_visible_and_previous_plan_retained']=wait_for(lambda:
            'Filter error' in dialogs[-1].errorLabel.getText() and ui._display_filter_plan is valid and not dialogs[-1].closed)
        edt(lambda:ui.sizeField.setText('bad'))
        checks['invalid_capture_numeric_visible']=wait_for(lambda:ui._capture_error is not None and 'Len value' in ui.filterStatusLabel.getText())
        checks['invalid_capture_plan_not_published']=ui._capture_filter_plan.numbers==()
        edt(lambda:ui.sizeField.setText(''))
        checks['capture_correction_clears_error']=wait_for(lambda:ui._capture_error is None)

        # Reset back to the already-active defaults must still clear a rejected
        # draft and supersede its intent, rather than keeping an error forever.
        edt(lambda:dialogs[-1]._on_reset())
        def invalid_from_defaults():
            dialog=ns['FilterDialog'](ui)
            dialogs.append(dialog)
            dialog.load_from_parent()
            dialog.controls['ResponseContent'][0].setSelected(True)
            dialog.controls['ResponseContent'][2].setText('[')
            dialog._on_apply()
        edt(invalid_from_defaults)
        if not wait_for(lambda:ui._display_error is not None):
            raise AssertionError('Invalid default-state draft did not finish')
        edt(lambda:dialogs[-1]._on_reset())
        checks['reset_same_defaults_clears_invalid_draft']=wait_for(lambda:ui._display_error is None and not ui._display_filter_plan.fields)
        def reactivate():
            dialog=dialogs[-1]
            dialog.controls['ResponseContent'][0].setSelected(True)
            dialog.controls['ResponseContent'][2].setText('a{1,3}\na,b')
            dialog._on_apply()
        edt(reactivate)
        if not wait_for(lambda:ui._display_filter_plan.has_regex and not ui._filter_rebuilding):
            raise AssertionError('Display filter did not reactivate')

        # Preserve arbitrary existing list values until edited, including a
        # literal newline in a legacy regex; this is independent of rendering.
        def roundtrip():
            ui.display_filters['ResponseContent']['values']=['a,b','a{1,3}','x\ny']
            dialog=ns['FilterDialog'](ui)
            dialogs.append(dialog)
            dialog.load_from_parent()
            checks['legacy_list_roundtrip_lossless']=dialog.candidate()['ResponseContent']['values']==['a,b','a{1,3}','x\ny']
            ui.display_filters['ResponseContent']['values']=['a{1,3}','a,b']
        edt(roundtrip)

        # Controlled finite matcher wait demonstrates EDT liveness and Clear,
        # without running catastrophic/unbounded Java regex inside live Burp.
        entered,release=threading.Event(),threading.Event()
        base_message=ui.logStore.entries[0].messageInfo
        class HeldMessage(object):
            def getResponse(self):
                entered.set()
                if not release.wait(3):
                    raise AssertionError('Finite native search gate not released')
                return base_message.getResponse()
        def held_search():
            ui._display_error='K07 controlled invalid draft'
            ui.logStore.entries[0].messageInfo=HeldMessage()
            ui._refresh_table_display()
        edt(held_search)
        checks['search_executes_off_edt']=entered.wait(2)
        try:
            edt(lambda:ui.payloadParamField.setText('EDT_ALIVE'))
            checks['edt_responds_during_search']=wait_for(lambda:ui._capture_runtime().get('payload1')=='EDT_ALIVE')
            checks['progress_visible_during_search']=wait_for(lambda:'Filtering' in ui.filterStatusLabel.getText())
            edt(ui.clear_log)
            checks['clear_immediate_during_search']=not ui.logStore.entries and not ui.logTableModel.displayed
        finally:
            release.set()
        checks['late_result_does_not_restore_clear']=wait_for(lambda:not ui._filter_worker.state()['active'] and not ui._filter_worker.state()['results'])
        checks['store_still_empty_after_old_result']=not ui.logStore.entries and not ui.logTableModel.displayed
        edt(ui.close_custom_runtime)
        edt(lambda:None)
        ui._filter_worker.worker.join(2)
        checks['unload_stops_filter_timer']=ui._filter_timer is None
        checks['unload_disposes_filter_dialog']=ui._filter_dialog is None and dialogs[-1].closed
        checks['unload_closes_filter_worker']=ui._filter_worker.closed and not ui._filter_worker.worker.is_alive()
    except BaseException:
        checks['native_ui_flow']=False
        errors.append(traceback.format_exc())
    finally:
        for dialog in dialogs:
            edt(dialog._on_cancel)
        for ui in current:
            edt(ui.close_custom_runtime)
            if ui._filter_worker.worker:
                ui._filter_worker.worker.join(3)
        edt(lambda:None)
    return dict(kind='K07-native-Java-regex-and-finite-Swing-no-network',
                source_sha256=hashlib.sha256(raw).hexdigest(),checks=checks,errors=errors,
                passed=bool(checks) and all(checks.values()) and not errors,
                logic_cases=result.testsRun,logic_log=output.getvalue(),
                actual_burp_helpers=bool(actual_callbacks),native_message_editors=bool(actual_callbacks),
                java_version=str(System.getProperty('java.version')),python=sys.version)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--report',required=True)
    args=parser.parse_args()
    report=run_checks()
    with open(args.report,'w') as handle:
        json.dump(report,handle,indent=2)
    print(json.dumps(report,indent=2))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    sys.exit(main())
