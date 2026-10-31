# -*- coding: utf-8 -*-
"""Final model event-stream and unload ownership review; no live Burp needed."""
from source_harness import Response
from test_source_logic import SourceCase


class LogFinalReview(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.ui.logStore=self.ns['LogStore']()
        self.ui.logTableModel=self.ns['LogTableModel'](self.ui.logStore)

    def test_replacing_rows_during_batch_never_emits_a_false_insert_interval(self):
        store,model=self.ui.logStore,self.ui.logTableModel
        events=[]
        model.fireTableRowsInserted=lambda a,b:events.append(('insert',a,b))
        model.fireTableDataChanged=lambda:events.append(('reset',))
        model.begin_batch()
        for unused in range(3):
            entry=store.add('t','host','GET','/',200,10,0,None)
            model.add_entry_top(entry,True)
        model.displayed=[store.entries[0]]
        model.fireTableDataChanged()
        entry=store.add('t','host','GET','/new',200,10,0,None)
        model.add_entry_top(entry,True)
        model.end_batch()
        self.assertEqual(events,[('insert',0,2),('reset',),('insert',0,0)])
        self.assertEqual(model.getRowCount(),2)

    def test_unload_explicitly_releases_viewer_content_and_log_metadata(self):
        class Holder(object):
            def __init__(self): self.value=b'owned viewer bytes'
            def setMessageInfo(self,value): self.value=value
            def setMessage(self,value,is_request):
                if value is None: raise ValueError('Native editor rejects null')
                self.value=value
        self.ui.controller=Holder()
        self.ui.reqViewer=Holder()
        self.ui.respViewer=Holder()
        self.ui.logStore.add('t','host','GET','/',200,10,0,Response(b'content'))
        self.ui.close_custom_runtime()
        utilities=self.ns['swing'].SwingUtilities
        if hasattr(utilities,'invokeAndWait') and not utilities.isEventDispatchThread():
            utilities.invokeAndWait(lambda:None)
        self.assertIsNone(self.ui.controller.value)
        self.assertEqual(len(self.ui.reqViewer.value),0)
        self.assertEqual(len(self.ui.respViewer.value),0)
        self.assertEqual(len(self.ui.logStore.entries),0)
