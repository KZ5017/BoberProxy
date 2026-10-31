# -*- coding: utf-8 -*-
"""K08-K09 durable-content, capacity and generation contracts; finite failures only."""
import os
import threading
import time
from source_harness import Response, as_bytes
from test_source_logic import SourceCase


class LogStorageTests(SourceCase):
    def setUp(self):
        SourceCase.setUp(self)
        self.ui.logStore = self.ns['LogStore']()
        self.ui.logTableModel = self.ns['LogTableModel'](self.ui.logStore)
        self.ui.display_filters = {}
        self.ui.set_status = lambda text: None
        self.gates = []

    def tearDown(self):
        for gate in self.gates: gate.set()
        archive = self.ui._log_archive
        SourceCase.tearDown(self)
        # Tests that call the archive directly have no running I/O worker.
        for unused in range(20):
            if not archive.collect(): break
        self.assertFalse(archive.records or archive.retired or archive.deleted)
        self.assertIsNone(archive.root)

    def wait(self, predicate, timeout=3):
        end = time.time()+timeout
        while time.time()<end:
            self.ui._filter_tick()
            if predicate(): return
            time.sleep(0.002)
        self.fail('Finite log checkpoint not reached')

    def background(self, operation):
        out, errors = [], []
        def run():
            try: out.append(operation())
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        if errors: raise errors[0]
        return out[0]

    def message(self, body=b'ABC', request=b'GET /original HTTP/1.1\r\nHost: fixture\r\n\r\n'):
        msg = Response(as_bytes('HTTP/1.1 200 OK\r\n\r\n')+body)
        msg.getRequest = lambda: request
        return msg

    def queue(self, msg=None, path='/original', config=None):
        msg = msg or self.message()
        self.ui._queue_filter_log((4,'fixture','GET',path,200,len(msg.getResponse()),msg,False,
                                   len(msg.getResponse().split(as_bytes('\r\n\r\n'),1)[1])),
                                  config or self.ui._capture_runtime())

    def stored(self, request, response):
        snapshot = self.ns['FrozenLogMessage'](self.ui.helpers,Response(response),request,response)
        return self.background(lambda:self.ui._log_archive.put(snapshot,self.ui._log_archive.epoch))

    def test_archive_exact_binary_and_null_versus_empty(self):
        binary = bytes(bytearray(range(256)))
        record = self.stored(binary,binary[::-1])
        self.assertEqual(self.background(record.getRequest),binary)
        self.assertEqual(self.background(record.getResponse),binary[::-1])
        empty = self.stored(b'',None)
        self.assertEqual(self.background(empty.getRequest),b'')
        self.assertIsNone(self.background(empty.getResponse))
        self.assertFalse(hasattr(record,'_log_response'))

    def test_archive_refuses_edt_io(self):
        record = self.stored(b'R',b'S')
        # Portable EDT double identifies the test main thread; native suite uses real EDT.
        if self.ns['swing'].SwingUtilities.isEventDispatchThread():
            with self.assertRaises(self.ns['LogStorageError']): record.getResponse()
            with self.assertRaises(self.ns['LogStorageError']):
                self.ui._log_archive.put(self.ns['FrozenLogMessage'](self.ui.helpers,Response(b'S'),b'R',b'S'),0)

    def test_clear_and_selected_release_only_owned_files(self):
        first,second = self.stored(b'R1',b'S1'),self.stored(b'R2',b'S2')
        root = self.ui._log_archive.root
        self.ui._log_archive.release(first)
        self.background(self.ui._log_archive.collect)
        self.assertFalse(os.path.exists(first.path))
        self.assertEqual(self.background(second.getRequest),b'R2')
        self.ui._log_archive.clear()
        with self.assertRaises(self.ns['LogStorageError']): self.background(second.getResponse)
        self.background(self.ui._log_archive.collect)
        self.assertEqual(os.listdir(root),[])

    def test_truncated_file_is_visible_read_failure(self):
        record = self.stored(b'R',b'complete')
        with open(record.path,'wb') as handle: handle.write(b'bad')
        with self.assertRaises(self.ns['LogStorageError']): self.background(record.getResponse)

    def test_snapshot_freezes_mutable_source_before_return(self):
        original = bytearray(b'HTTP/1.1 200 OK\r\n\r\nABC')
        msg = self.message()
        msg.getResponse = lambda:original
        self.queue(msg)
        original[-3:] = b'BAD'
        self.wait(lambda:len(self.ui.logStore.entries)==1)
        stored = self.ui.logStore.entries[0].messageInfo
        self.assertTrue(self.background(stored.getResponse).endswith(b'ABC'))

    def test_byte_limit_rejects_before_snapshot_and_pauses_visibly(self):
        self.ui._log_budget.limit = 1
        msg = self.message()
        self.queue(msg)
        self.assertEqual(self.ui._log_not_accepted,1)
        self.assertIn('LOG_BUSY',self.ui._log_error)
        self.assertEqual(self.ui._log_budget.used,0)
        self.assertIsNone(self.ui._log_archive.root)
        self.assertEqual(len(self.ui.logStore.entries),0)

    def test_shared_raw_budget_and_close_release_reservations(self):
        budget = self.ui._log_budget
        budget.limit = 8
        entered,release = threading.Event(),threading.Event()
        self.gates.append(release)
        def operation():
            entered.set()
            release.wait(2)
        writer = self.ui._log_writer
        self.assertTrue(writer.submit_log(lambda:operation,lambda *a:None,6))
        self.assertTrue(entered.wait(2))
        self.assertFalse(self.ui._filter_worker.submit_log(lambda:operation,lambda *a:None,3))
        self.assertEqual(budget.used,6)
        writer.close()
        self.assertEqual(budget.used,6)  # Running bytes stay charged until completion.
        release.set()
        writer.worker.join(2)
        self.assertEqual(budget.used,0)

    def test_concurrent_rejection_accounting_has_no_lost_increment(self):
        self.ui._log_error='controlled failure'
        config=self.ui._capture_runtime()
        msg=self.message()
        data=(4,'fixture','GET','/counter',200,len(msg.getResponse()),msg,False,3)
        start=threading.Event()
        def reject():
            start.wait()
            for unused in range(100): self.ui._queue_filter_log(data,config)
        threads=[threading.Thread(target=reject) for unused in range(20)]
        for thread in threads: thread.start()
        start.set()
        for thread in threads: thread.join(3)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(self.ui._log_not_accepted,2000)
        self.assertEqual(self.ui._log_budget.used,0)

    def test_preparation_order_cannot_overtake_first_snapshot(self):
        entered,release = threading.Event(),threading.Event()
        self.gates.append(release)
        observed=[]
        def prepare_first():
            entered.set()
            release.wait(2)
            return lambda:observed.append('first')
        worker=self.ui._log_writer
        thread=threading.Thread(target=lambda:worker.submit_log(prepare_first,lambda *a:None,1))
        thread.start()
        self.assertTrue(entered.wait(2))
        self.assertTrue(worker.submit_log(lambda:lambda:observed.append('second'),lambda *a:None,1))
        self.assertEqual(observed,[])
        release.set()
        thread.join(2)
        self.wait(lambda:observed==['first','second'])

    def test_pending_accepted_rows_finish_after_pause(self):
        self.queue()
        self.ui.paused=True
        self.wait(lambda:len(self.ui.logStore.entries)==1)
        self.assertEqual(self.ui.logStore.entries[0].index,1)

    def test_clear_while_write_in_progress_cannot_restore_row_or_file(self):
        archive=self.ui._log_archive
        entered,release=threading.Event(),threading.Event()
        self.gates.append(release)
        original=archive._put
        def hold(snapshot,epoch):
            entered.set()
            release.wait(2)
            return original(snapshot,epoch)
        archive._put=hold
        self.queue()
        self.assertTrue(entered.wait(2))
        self.ui.clear_log()
        release.set()
        self.wait(lambda:not self.ui._log_writer.state()['active'])
        self.assertEqual(len(self.ui.logStore.entries),0)
        self.assertEqual(archive.records,{})
        self.assertIsNone(self.ui._log_error)

    def test_storage_write_failure_pauses_new_admission_without_erasing_old(self):
        self.queue()
        self.wait(lambda:len(self.ui.logStore.entries)==1)
        def fail(*args): raise IOError('controlled disk-full equivalent')
        self.ui._log_archive.put=fail
        self.queue(path='/disk-full')
        self.wait(lambda:self.ui._log_error is not None)
        self.assertIn('STORAGE_WRITE_FAILED',self.ui._log_error)
        self.assertEqual(len(self.ui.logStore.entries),1)
        before=self.ui._log_not_accepted
        self.queue(path='/paused')
        self.assertEqual(self.ui._log_not_accepted,before+1)

    def test_one_batch_notification_covers_a_burst(self):
        model=self.ui.logTableModel
        notifications=[]
        model.fireTableRowsInserted=lambda first,last:notifications.append((first,last))
        for unused in range(30): self.queue()
        end=time.time()+3
        while len(self.ui._log_writer.results)<30 and time.time()<end: time.sleep(0.002)
        self.assertEqual(len(self.ui._log_writer.results),30)
        self.ui._filter_tick()
        self.assertEqual(len(self.ui.logStore.entries),30)
        self.assertEqual(notifications,[(0,29)])
        self.assertEqual([e.index for e in model.displayed],list(range(30,0,-1)))

    def test_unload_after_persist_before_publish_cleans_owned_files(self):
        self.queue()
        end=time.time()+3
        while not self.ui._log_archive.records and time.time()<end: time.sleep(0.002)
        root=self.ui._log_archive.root
        self.assertIsNotNone(root)
        self.ui.close_custom_runtime()
        self.ui._log_writer.worker.join(2)
        self.ui._log_io.worker.join(2)
        self.assertFalse(os.path.exists(root))
        self.assertEqual(len(self.ui.logStore.entries),0)

    def test_model_index_lookup_and_multiple_removal_are_stable(self):
        store=self.ui.logStore
        for n in range(1000): store.add('t','host','GET','/'+str(n),200,10,0,None)
        self.ui.logTableModel.rebuild()
        selected={store.entries[3],store.entries[97]}
        stable=[entry.index for entry in selected]
        store.entries=[entry for entry in store.entries if entry not in selected]
        self.ui.logTableModel.rebuild()
        self.assertEqual(len(store.entries),998)
        self.assertFalse(selected.intersection(store.entries))
        self.assertEqual([entry.index for entry in selected],stable)
        self.assertEqual(store.entries[0].index,1000)
