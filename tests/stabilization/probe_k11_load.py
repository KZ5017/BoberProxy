# -*- coding: utf-8 -*-
"""Disposable-JVM full callback/archive/table benchmark, never a Burp entry.

Producer backpressure is explicit instrumentation (64 outstanding events), not
a claim of unpaced wire throughput. Native helpers/editors are standalone doubles.
"""
from __future__ import print_function
import argparse
import hashlib
import json
import os
import sys
import time
import traceback
from java.lang import Runtime, System, Thread, Throwable
from java.lang.management import ManagementFactory
from javax.swing import SwingUtilities
from javax import swing
from javax.swing.event import TableModelListener, TableModelEvent
from java.net import URL
from burp import IHttpService
from source_harness import ROOT, as_text, as_bytes, RequestInfo
from probe_template_native import load_source
from probe_logging_native import NativeHelpers
from burp_k089_storage_probe import SyntheticMessage


class FixedService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host, self._port = host, port
        self._protocol = 'https' if protocol in (True, 'https') else 'http'
    def getHost(self): return self._host
    def getPort(self): return self._port
    def getProtocol(self): return self._protocol


class FixedRequestInfo(RequestInfo):
    def __init__(self, message):
        RequestInfo.__init__(self, as_bytes(as_text(message.getRequest())))
        self.service = message.getHttpService()
    def getMethod(self): return as_text(self.data).split()[0]
    def getUrl(self):
        return URL('%s://%s:%d%s' % (self.service.getProtocol(), self.service.getHost(),
                                   self.service.getPort(), as_text(self.data).split()[1]))


class LoadHelpers(NativeHelpers):
    """One immutable service fixture; never define Java proxy types per event."""
    def __init__(self): self.services = {}
    def buildHttpService(self, host, port, protocol):
        key = (host, port, protocol)
        if key not in self.services: self.services[key] = FixedService(host,port,protocol)
        return self.services[key]
    def analyzeRequest(self, message): return FixedRequestInfo(message)


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered)-1, int((len(ordered)-1)*fraction))] if ordered else None


def distribution(values):
    return dict(count=len(values), median=percentile(values, .5),
                p95=percentile(values, .95), p99=percentile(values, .99),
                maximum=max(values) if values else None)


def run(args):
    ns, raw = load_source(os.path.join(ROOT, 'BoberProxy.py'))
    helpers = LoadHelpers()
    runtime = Runtime.getRuntime()
    reports, errors, owned = [], [], []
    base = os.path.realpath(args.root)
    def edt(operation):
        failures = []
        def invoke():
            try: operation()
            except (BaseException, Throwable): failures.append(traceback.format_exc())
        if swing.SwingUtilities.isEventDispatchThread(): invoke()
        else: swing.SwingUtilities.invokeAndWait(invoke)
        if failures: raise AssertionError('\n'.join(failures))
    class Editor(object):
        def __init__(self): self.value = helpers.stringToBytes('')
        def getMessage(self): return self.value
        def setMessage(self, value, request): self.value = value
        def getComponent(self): return swing.JPanel()
    class Callbacks(object):
        def getHelpers(self): return helpers
        def createMessageEditor(self, controller, editable): return Editor()
    def heap():
        for unused in range(3):
            System.gc()  # Dedicated JVM only; never called in the user's Burp.
            time.sleep(.1)
        return runtime.totalMemory()-runtime.freeMemory()
    def cpu():
        try: return ManagementFactory.getOperatingSystemMXBean().getProcessCpuTime()
        except (BaseException, Throwable): return None
    def state(ui):
        writer, search = ui._log_writer.state(), ui._filter_worker.state()
        return dict(outstanding=sum(writer[k] for k in ('rows','results','active')),
                    raw_bytes=ui._log_budget.used, writer=writer, search=search,
                    rejected=ui._log_not_accepted, error=ui._log_error)
    def clear(ui):
        initial_rows = len(ui._log_archive.records)
        # The production collector intentionally handles 64 records per pass
        # and waits 50 ms between idle passes. A fixed 60 s harness deadline is
        # shorter than even its theoretical 100k-record cleanup time.
        allowance = max(60, initial_rows / 64.0 * .05 * 3 + 30)
        began = time.time()
        edt(ui.clear_log)
        end = time.time()+allowance
        while time.time()<end:
            if not ui._log_archive.retired and not ui._log_archive.deleted and not ui._log_archive.records:
                break
            time.sleep(.01)
        assert not ui._log_archive.retired and not ui._log_archive.deleted and not ui._log_archive.records
        assert ui._log_budget.used == 0
        return dict(content_records=initial_rows, seconds=time.time()-began,
                    harness_allowance_seconds=allowance)
    try:
        def create():
            ui = ns['LoggerUI'](Callbacks(), ns['SimpleMessageController']())
            owned.append(ui)
        edt(create)
        ui = owned[0]
        archive_path = os.path.join(base, 'archive')
        os.mkdir(archive_path)
        ui._log_archive.root = archive_path
        extender = object.__new__(ns['BurpExtender'])
        extender.ui, extender.helpers = ui, helpers
        tracked, latencies, heartbeat = {}, [], []
        last_tick = [ns['_monotonic_ms']()]
        def beat(event):
            now = ns['_monotonic_ms']()
            heartbeat.append(max(0, now-last_tick[0]-50))
            last_tick[0] = now
        timer = swing.Timer(50, beat)
        class Listener(TableModelListener):
            def tableChanged(self, event):
                if event.getType() != TableModelEvent.INSERT: return
                now = ns['_monotonic_ms']()
                for row in range(event.getFirstRow(), event.getLastRow()+1):
                    entry = ui.logTableModel.displayed[row]
                    started = tracked.pop(entry.path, None)
                    if started is not None: latencies.append(now-started)
        listener = Listener()
        edt(lambda: ui.logTableModel.addTableModelListener(listener))
        def populate(count, size, label):
            del latencies[:]
            del heartbeat[:]
            tracked.clear()
            callback_first, callback_last = [], []
            peak_raw, peak_outstanding = 0, 0
            response = helpers.stringToBytes('HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % size + 'X'*size)
            last_tick[0] = ns['_monotonic_ms']()
            edt(timer.start)
            began = time.time()
            cpu_before = cpu()
            for index in range(count):
                end = time.time()+30
                while state(ui)['outstanding'] >= 64:
                    if ui._log_error or time.time() >= end: raise AssertionError('Load pipeline stalled: '+repr(state(ui)))
                    time.sleep(.002)
                path = '/k11/%s/%d' % (label, index)
                request = helpers.stringToBytes('GET '+path+' HTTP/1.1\r\nHost: 127.0.0.1:18765\r\n\r\n')
                message = SyntheticMessage(helpers, request, response)
                tick = ns['_monotonic_ms']()
                tracked[path] = tick
                extender.processHttpMessage(4, False, message)
                elapsed = ns['_monotonic_ms']()-tick
                if index < 1000: callback_first.append(elapsed)
                if index >= count-1000: callback_last.append(elapsed)
                current = state(ui)
                peak_raw = max(peak_raw, current['raw_bytes'])
                peak_outstanding = max(peak_outstanding, current['outstanding'])
                if current['error'] or current['rejected']: raise AssertionError('Unexpected admission rejection: '+repr(current))
            producer_end = time.time()
            end = time.time()+60
            while tracked and time.time()<end: time.sleep(.01)
            elapsed = time.time()-began
            cpu_after = cpu()
            edt(timer.stop)
            assert not tracked, 'Not all submitted events reached the model'
            assert len(latencies)==count and len(ui.logStore.entries)==count
            assert ui.logTableModel.getRowCount()==count
            assert ui.logStore.entries[0].index==count and ui.logStore.entries[-1].index==1
            assert len(set(entry.path for entry in ui.logStore.entries))==count
            assert ui._log_budget.used==0 and not ui._log_not_accepted
            for position in (0, count//2, count-1):
                entry = ui.logStore.entries[position]
                request_text = as_text(entry.messageInfo.getRequest())
                assert request_text.split(' ')[1] == entry.path
                assert as_text(entry.messageInfo.getResponse()) == as_text(response)
            result = dict(label=label, rows=count, body_bytes=size, seconds=elapsed,
                          producer_seconds=producer_end-began, drain_seconds=time.time()-producer_end,
                          process_cpu_seconds=(cpu_after-cpu_before)/1e9 if cpu_before is not None and cpu_after is not None else None,
                          callback_first_ms=distribution(callback_first), callback_last_ms=distribution(callback_last),
                          heartbeat_lag_ms=distribution(heartbeat), appearance_lag_ms=distribution(latencies),
                          peak_raw_bytes=peak_raw, peak_outstanding=peak_outstanding,
                          accepted=count, stored=len(ui._log_archive.records), displayed=ui.logTableModel.getRowCount(),
                          disk_bytes=sum(os.path.getsize(record.path) for record in ui._log_archive.records.values()),
                          roundtrip_samples=3, heap_after_requested_gc_bytes=heap(),
                          loaded_class_count=ManagementFactory.getClassLoadingMXBean().getLoadedClassCount(),
                          current_threads=ManagementFactory.getThreadMXBean().getThreadCount())
            print(label + ': ' + json.dumps({k:result[k] for k in ('rows','seconds','heap_after_requested_gc_bytes')}))
            sys.stdout.flush()
            reports.append(result)
            result['clear'] = clear(ui)
            return result
        populate(100, 1024, 'warmup')
        for count in ([100, 1000] if args.smoke else [1000,10000,100000]):
            populate(count, 1024, 'rows-%d' % count)
        memory_rows = 100 if args.smoke else 10000
        before = heap()
        small = populate(memory_rows, 4096, 'memory-small')
        large = populate(memory_rows, 65536, 'memory-large')
        extra_bodies = memory_rows*(65536-4096)
        growth = large['heap_after_requested_gc_bytes']-small['heap_after_requested_gc_bytes']
        memory = dict(rows=memory_rows, pre_population_heap_bytes=before,
                      small_retained_heap_bytes=small['heap_after_requested_gc_bytes'],
                      large_retained_heap_bytes=large['heap_after_requested_gc_bytes'],
                      heap_difference_bytes=growth, body_difference_bytes=extra_bodies,
                      retained_fraction=float(max(0,growth))/extra_bodies,
                      ninety_percent_extra_body_not_retained=growth <= extra_bodies*.1,
                      heap_after_clear_requested_gc_bytes=heap())
    except (BaseException, Throwable):
        errors.append(traceback.format_exc())
    finally:
        if 'timer' in locals(): edt(timer.stop)
        for ui in owned:
            pending_records = len(ui._log_archive.records) + sum(len(group) for group in ui._log_archive.retired) + len(ui._log_archive.deleted)
            ui.close_custom_runtime()
            edt(lambda: None)
            for worker in (ui._custom_executor,ui._filter_worker,ui._log_writer,ui._log_io):
                if worker.worker is not None:
                    worker.worker.join(max(30, pending_records / 64.0 * .05 * 3 + 30))
        cleaned = not os.path.exists(os.path.join(base, 'archive'))
    checks = dict(all_expected_stages=len(reports)==(5 if args.smoke else 6),
                  no_errors=not errors, owned_archive_reclaimed=cleaned)
    # A 100-row smoke validates the harness, not the specified 10k-row memory
    # acceptance. Keep its noisy fraction as an observation, never relabel it.
    if args.smoke:
        checks['memory_observation_recorded_not_full_acceptance'] = locals().get('memory') is not None
    else:
        checks['memory_gate'] = locals().get('memory',{}).get('ninety_percent_extra_body_not_retained',False)
    if not args.smoke and not errors:
        by_rows = {r['rows']:r for r in reports if r['label'].startswith('rows-')}
        checks['ten_to_hundred_thousand_time_ratio_at_most_25'] = by_rows[100000]['seconds']/by_rows[10000]['seconds'] <= 25
    return dict(kind='K11-full-native-callback-archive-table-dedicated-JVM',
                source_sha256=hashlib.sha256(raw).hexdigest(), smoke=args.smoke,
                java_version=unicode(System.getProperty('java.version')), python=sys.version,
                max_heap_bytes=runtime.maxMemory(), network_requests=0,
                actual_burp_helpers=False, table_visible=False,
                producer_outstanding_limit=64, requested_gc_only_in_disposable_jvm=True,
                helper_service_interned=True,
                stages=reports, memory=locals().get('memory'), errors=errors, checks=checks,
                passed=all(checks.values()), k11_closed=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--smoke', action='store_true')
    args = parser.parse_args()
    if os.path.exists(args.report): raise ValueError('Report already exists')
    result = run(args)
    with open(args.report,'w') as handle: json.dump(result,handle,indent=2)
    print(json.dumps(dict(passed=result['passed'], checks=result['checks'], errors=result['errors']),indent=2))
    sys.exit(0 if result['passed'] else 1)
