# -*- coding: utf-8 -*-
"""K07 plans and controlled scheduling; native probes use actual Java Pattern."""
import threading
import time
from source_harness import Field, Response, as_bytes
from test_source_logic import SourceCase
from filter_cases import ROWS, DISPLAY, CAPTURE, display


class FilterTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.ui.logStore = self.ns['LogStore']()
        self.ui.logTableModel = self.ns['LogTableModel'](self.ui.logStore)
        self.ui.display_filters = {}
        self.ui.set_status = lambda message: None
        self.ui.filterStatusLabel = Field('')
        self.releases = []
        for index,host,method,path,status,body,length in ROWS:
            msg = Response(as_bytes('HTTP/1.1 %d Fixture\r\nX-Tag: mark\r\n\r\n%s' % (status,body)))
            self.ui.logStore.add('t',host,method,path,status,len(msg.data),length,msg)

    def tearDown(self):
        for release in self.releases:
            release.set()
        SourceCase.tearDown(self)

    def wait(self, predicate, timeout=3):
        end=time.time()+timeout
        while not predicate() and time.time()<end:
            self.ui._filter_tick()
            time.sleep(0.002)
        self.ui._filter_tick()
        self.assertTrue(predicate(),'Controlled filter ordering point not reached')

    def display_plan(self, config):
        self.ui.display_filters=config
        plan=self.ns['DisplayFilterPlan'](config)
        self.ui._filter_generation+=1
        plan.version=self.ui._filter_generation
        self.ui._display_filter_plan=plan
        return plan

    def gate_rebuild(self):
        plan=self.display_plan(display('ResponseContent',['abc']))
        entered,release=threading.Event(),threading.Event()
        self.releases.append(release)
        message=self.ui.logStore.entries[-1].messageInfo
        original=message.getResponse
        def block():
            entered.set()
            if not release.wait(2):
                raise AssertionError('Finite display gate was not released')
            return original()
        message.getResponse=block
        self.ui._refresh_table_display()
        self.assertTrue(entered.wait(2),'Worker did not begin response search')
        return plan,release

    def append(self,path,plan,match):
        message=Response(as_bytes('HTTP/1.1 200 OK\r\n\r\nABC'))
        self.ui.append_log_row(4,'new','GET',path,200,len(message.data),message,False,
                              filter_result=(plan,match))

    def test_display_characterized_matches(self):
        entries=sorted(self.ui.logStore.entries,key=lambda entry:entry.index)
        for name,config,expected in DISPLAY:
            plan=self.ns['DisplayFilterPlan'](config)
            self.assertEqual([e.index for e in entries if plan.matches(e,self.ui.helpers)],expected,name)

    def test_capture_characterized_matches(self):
        entries=sorted(self.ui.logStore.entries,key=lambda entry:entry.index)
        for name,config,expected in CAPTURE:
            plan=self.ns['CaptureFilterPlan'](config)
            actual=[]
            for entry in entries:
                response=entry.messageInfo.getResponse()
                body=self.ui.helpers.analyzeResponse(response).getBodyOffset()
                if not config.get('paused') and plan.accepts(entry.status,len(response),len(response)-body,response,self.ui.helpers):
                    actual.append(entry.index)
            self.assertEqual(actual,expected,name)

    def test_compilation_is_not_repeated_per_row(self):
        original=self.ns['Pattern']
        count=[]
        class Counting(object):
            CASE_INSENSITIVE,DOTALL=original.CASE_INSENSITIVE,original.DOTALL
            @staticmethod
            def compile(pattern,flags=0):
                count.append((pattern,flags))
                return original.compile(pattern,flags)
        self.ns['Pattern']=Counting
        try:
            plan=self.ns['DisplayFilterPlan'](display('ResponseContent',['abc']))
            entry=self.ui.logStore.entries[1]
            for unused in range(10000):
                self.assertTrue(plan.matches(entry,self.ui.helpers))
            self.assertEqual(len(count),1)
        finally:
            self.ns['Pattern']=original

    def test_invalid_display_is_atomic_and_keeps_previous_filter(self):
        old=display('Host',['alpha'])
        self.display_plan(old)
        self.ui._apply_display_filters(dict(display('Host',['beta']),**display('ResponseContent',['['])))
        self.wait(lambda:self.ui._display_error is not None)
        self.assertEqual(self.ui.display_filters,old)
        self.assertIn('ResponseContent',self.ui._display_error)
        self.assertIn('Filter error',self.ui.filterStatusLabel.getText())

    def test_other_settings_reuse_unchanged_compiled_patterns(self):
        first=self.ns['CaptureFilterPlan']({'log_regex':'abc'})
        second=self.ns['CaptureFilterPlan']({'log_regex':'abc','size':'3'},first)
        self.assertIs(first.pattern,second.pattern)
        first_display=self.ns['DisplayFilterPlan'](display('ResponseContent',['abc']))
        second_display=self.ns['DisplayFilterPlan'](dict(display('Host',['alpha']),**display('ResponseContent',['abc'])),first_display)
        self.assertIs(list(first_display.patterns.values())[0],list(second_display.patterns.values())[0])

    def test_legacy_empty_regex_item_has_no_response_decode(self):
        entry=self.ui.logStore.entries[0]
        entry.messageInfo.getResponse=lambda:(_ for _ in ()).throw(AssertionError('Unneeded response decode'))
        for mode,expected in [('eq',False),('not eq',True)]:
            plan=self.ns['DisplayFilterPlan'](display('ResponseContent',[''],mode))
            self.assertEqual(plan.matches(entry,self.ui.helpers),expected)

    def test_clear_selected_invalidates_search_but_not_new_admission(self):
        plan,release=self.gate_rebuild()
        self.ui.logTableModel.displayed=list(self.ui.logStore.entries)
        class Table(object):
            def getSelectedRows(self):
                return [1]  # Entry4 in newest-first order.
            def convertRowIndexToModel(self,row):
                return row
        self.ui.table=Table()
        epoch=self.ui._log_generation
        self.ui.clear_selected()
        self.assertEqual(self.ui._log_generation,epoch)
        self.append('/new-after-selected',plan,True)
        release.set()
        self.wait(lambda:not self.ui._filter_rebuilding and not self.ui._filter_dirty)
        self.assertEqual([e.index for e in self.ui.logTableModel.displayed],[6,1])
        self.assertNotIn(4,[e.index for e in self.ui.logStore.entries])

    def test_invalid_numeric_retains_last_valid_capture(self):
        self.ui.sizeField=Field('3')
        self.ui._publish_runtime()
        self.wait(lambda:self.ui._capture_filter_plan.numbers==(3,))
        valid=self.ui._capture_filter_plan
        self.ui.sizeField.setText('3,bad')
        self.ui._publish_runtime()
        self.wait(lambda:self.ui._capture_error is not None)
        self.assertIs(self.ui._capture_filter_plan,valid)
        self.assertIn('Size value',self.ui._capture_error)

    def test_invalid_capture_regex_retains_last_valid_plan(self):
        self.ui.regexField=Field('ABC')
        self.ui._publish_runtime()
        self.wait(lambda:self.ui._capture_filter_plan.pattern is not None)
        valid=self.ui._capture_filter_plan
        self.ui.regexField.setText('[')
        self.ui._publish_runtime()
        self.wait(lambda:self.ui._capture_error is not None)
        self.assertIs(self.ui._capture_filter_plan,valid)

    def test_no_display_filter_erases_stored_entries(self):
        self.ui._apply_display_filters(display('Host',['nobody']))
        self.wait(lambda:not self.ui._filter_rebuilding and self.ui.display_filters.get('Host',{}).get('active'))
        self.assertEqual(self.ui.logTableModel.displayed,[])
        self.assertEqual(len(self.ui.logStore.entries),5)
        self.ui._apply_display_filters({})
        self.assertEqual([e.index for e in self.ui.logTableModel.displayed],[5,4,3,2,1])

    def test_clear_during_rebuild_never_restores_old_rows(self):
        plan,release=self.gate_rebuild()
        self.ui.clear_log()
        self.append('/after-clear',plan,True)
        release.set()
        self.wait(lambda:not self.ui._filter_worker.state()['active'])
        self.assertEqual([e.path for e in self.ui.logStore.entries],['/after-clear'])
        self.assertEqual([e.path for e in self.ui.logTableModel.displayed],['/after-clear'])

    def test_new_filter_wins_over_late_old_search(self):
        plan,release=self.gate_rebuild()
        self.ui._apply_display_filters({})
        self.assertEqual(len(self.ui.logTableModel.displayed),5)
        release.set()
        self.wait(lambda:not self.ui._filter_worker.state()['active'])
        self.assertEqual([e.index for e in self.ui.logTableModel.displayed],[5,4,3,2,1])

    def test_new_rows_merge_into_stable_rebuild_snapshot(self):
        plan,release=self.gate_rebuild()
        self.append('/new-match',plan,True)
        self.append('/new-hidden',plan,False)
        release.set()
        self.wait(lambda:not self.ui._filter_rebuilding)
        self.assertEqual([e.index for e in self.ui.logTableModel.displayed],[6,4,1])
        self.assertEqual(len(self.ui.logStore.entries),7)

    def test_unknown_new_row_is_rechecked_instead_of_lost(self):
        plan,release=self.gate_rebuild()
        self.append('/new-pending',plan,None)
        release.set()
        self.wait(lambda:not self.ui._filter_rebuilding and not self.ui._filter_dirty)
        self.assertEqual([e.index for e in self.ui.logTableModel.displayed],[6,4,1])

    def test_close_ignores_pending_search_result(self):
        plan,release=self.gate_rebuild()
        before=list(self.ui.logTableModel.displayed)
        self.ui.close_custom_runtime()
        release.set()
        self.ui._filter_worker.worker.join(2)
        self.ui._filter_tick()
        self.assertEqual(self.ui.logTableModel.displayed,before)
        self.assertIsNone(self.ui._filter_worker.poll())

    def test_worker_capacity_and_coalesced_controls_are_bounded(self):
        worker=self.ui._filter_worker
        worker.capacity=2
        entered,release=threading.Event(),threading.Event()
        self.releases.append(release)
        def hold():
            entered.set()
            release.wait(2)
        self.assertTrue(worker.submit(hold,lambda *a:None))
        self.assertTrue(entered.wait(2))
        for unused in range(2):
            self.assertTrue(worker.submit(lambda:True,lambda *a:None))
        self.assertFalse(worker.submit(lambda:True,lambda *a:None))
        for unused in range(100):
            for key in ('capture','display','rebuild'):
                self.assertTrue(worker.submit(lambda:True,lambda *a:None,key))
        self.assertEqual(worker.state()['rows'],2)
        self.assertEqual(worker.state()['controls'],3)
        worker.close()
        self.assertEqual(worker.state()['rows'],0)
        release.set()

    def test_busy_display_retains_already_admitted_entry(self):
        self.ui.logStore.clear()
        self.ui._display_filter_plan=self.ns['DisplayFilterPlan'](display('ResponseContent',['abc']))
        worker=self.ui._filter_worker
        worker.submit=lambda *a,**k:False
        message=Response(as_bytes('HTTP/1.1 200 OK\r\n\r\nABC'))
        self.ui._queue_filter_log((4,'h','GET','/retained',200,len(message.data),message,False,3),self.ui._capture_runtime())
        self.wait(lambda:len(self.ui.logStore.entries)==1)
        self.assertEqual([e.path for e in self.ui.logStore.entries],['/retained'])
        self.assertTrue(self.ui._filter_dirty)

    def test_busy_capture_is_visible_and_does_not_accept_unknown_match(self):
        self.ui.logStore.clear()
        self.ui._capture_filter_plan=self.ns['CaptureFilterPlan']({'log_regex':'ABC'})
        self.ui._filter_worker.submit_log=lambda *a,**k:False
        message=Response(as_bytes('HTTP/1.1 200 OK\r\n\r\nABC'))
        config=self.ns['RuntimeConfig']({'capture_filter_plan':self.ui._capture_filter_plan},0)
        self.ui._queue_filter_log((4,'h','GET','/busy',200,len(message.data),message,False,3),config)
        self.assertEqual(self.ui.logStore.entries,[])
        self.assertEqual(self.ui._filter_rejected,1)
        self.ui._filter_tick()
        self.assertIn('1 log responses not accepted',self.ui.filterStatusLabel.getText())

    def test_metadata_rejection_does_not_queue_regex_work(self):
        self.ui.logStore.clear()
        plan=self.ns['CaptureFilterPlan']({'statuses':(5,), 'log_regex':'ABC'})
        config=self.ns['RuntimeConfig']({'capture_filter_plan':plan},0)
        def forbidden(*args,**kwargs):
            raise AssertionError('Rejected metadata still queued a regex')
        self.ui._filter_worker.submit=forbidden
        message=Response(as_bytes('HTTP/1.1 200 OK\r\n\r\nABC'))
        self.ui._queue_filter_log((4,'h','GET','/rejected',200,len(message.data),message,False,3),config)
        self.assertEqual(self.ui.logStore.entries,[])
        self.assertEqual(self.ui._filter_rejected,0)

    def test_clearing_regex_with_valid_size_does_not_wait_for_busy_worker(self):
        self.ui.sizeField,self.ui.regexField=Field('3'),Field('ABC')
        self.ui._capture_filter_plan=self.ns['CaptureFilterPlan']({'size':'3','log_regex':'ABC'})
        self.ui._publish_runtime()
        entered,release=threading.Event(),threading.Event()
        self.releases.append(release)
        def hold():
            entered.set()
            release.wait(2)
        self.assertTrue(self.ui._filter_worker.submit(hold,lambda *a:None))
        self.assertTrue(entered.wait(2))
        self.ui.regexField.setText('')
        self.ui._publish_runtime()
        self.assertIsNone(self.ui._capture_filter_plan.pattern)
        self.assertEqual(self.ui._capture_filter_plan.numbers,(3,))
        self.assertTrue(self.ui._filter_worker.state()['active'])
        self.assertEqual(self.ui._filter_worker.state()['controls'],0)
        release.set()

    def test_clear_while_callback_analyzes_does_not_resurrect_event(self):
        self.ui.logStore.clear()
        original=self.ui.helpers.analyzeResponse
        def clear_during_analysis(response):
            self.ui.clear_log()
            return original(response)
        self.ui.helpers.analyzeResponse=clear_during_analysis
        extension=self.ns['BurpExtender']()
        extension.ui,extension.helpers=self.ui,self.ui.helpers
        message=Response(as_bytes('HTTP/1.1 200 OK\r\n\r\nABC'))
        extension.processHttpMessage(4,False,message)
        self.assertEqual(self.ui.logStore.entries,[])

    def test_reset_to_current_filter_clears_invalid_draft_error(self):
        self.ui._display_error='Invalid draft'
        self.ui._apply_display_filters({})
        self.assertIsNone(self.ui._display_error)
        self.assertEqual(len(self.ui.logTableModel.displayed),5)

    def test_reset_to_current_filter_cancels_pending_new_validation(self):
        entered,release=threading.Event(),threading.Event()
        self.releases.append(release)
        def hold():
            entered.set()
            release.wait(2)
        self.assertTrue(self.ui._filter_worker.submit(hold,lambda *a:None))
        self.assertTrue(entered.wait(2))
        self.ui._apply_display_filters(display('Host',['alpha']))
        self.ui._apply_display_filters({})
        release.set()
        self.wait(lambda:not any(self.ui._filter_worker.state()[k] for k in ('active','controls','results','rows')))
        self.assertEqual(self.ui.display_filters,{})
        self.assertEqual(len(self.ui.logTableModel.displayed),5)
