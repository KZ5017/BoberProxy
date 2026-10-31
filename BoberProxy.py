# -*- coding: latin-1 -*-
# Extender.py - BoberProxy (updated: tabs, template controls, custom codeblock)
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController, IProxyListener, IExtensionStateListener, IHttpRequestResponse

from javax import swing
from javax.swing import SortOrder, RowSorter, JTable, ListSelectionModel
from javax.swing.table import TableRowSorter, AbstractTableModel

from java.awt import (
    GridBagLayout, GridBagConstraints, Insets, Font, FlowLayout,
    Color, Dimension, BorderLayout
)
from java.awt.event import MouseAdapter
from java.util.regex import Pattern
from java.lang import Integer, Exception as JavaException, Throwable as JavaThrowable

import threading, time, traceback, re

CUSTOM_GATE_NAME = "BoberProxy.custom.v1"
CUSTOM_START_LOCK = threading.Lock()

# URL parsing - choose one, depending on which one works in your environment
# Python 2 (old Jython versions):
from urlparse import urljoin, urlparse
# Python 3 (Jython and newer versions):
#from urllib.parse import urljoin, urlparse


TEMPLATE_PAYLOAD_MARKER_1 = "p4yl04dm4rk3r"
TEMPLATE_PAYLOAD_MARKER_2 = "53c0undm4rk3r"
TEMPLATE_CSRF_MARKER = "c5rfm4rk3r"
TEMPLATE_MARKER_HINT = "Markers: %s, %s, %s " % (
    TEMPLATE_PAYLOAD_MARKER_1,
    TEMPLATE_PAYLOAD_MARKER_2,
    TEMPLATE_CSRF_MARKER,
)
DISPLAY_FILTER_FIELDS = (
    "Host",
    "Method",
    "Path",
    "Status",
    "BodyLen",
    "ResponseContent",
)

class TemplateBuildError(Exception):
    """A failed transformation must not produce a partially rebuilt request."""
    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        self.code = code
        self.detail = detail


def _wire_text(value, helpers=None):
    """Map supported HTTP byte containers to Latin-1 text, without data loss.

    Unicode/Java String use byte-valued code points (0..255), as Burp's
    bytesToString/stringToBytes pair does. Encode real Unicode to UTF-8
    explicitly in custom code when UTF-8 wire bytes are wanted.
    """
    if isinstance(value, (bytes, bytearray)):
        return value.decode("latin-1")
    try:
        text_type = unicode
    except NameError:
        text_type = str
    if isinstance(value, text_type):
        value.encode("latin-1")  # validate; never use replacement characters
        return value
    try:
        java_type = value.getClass().getName()
    except (AttributeError, TypeError):
        java_type = None
    if java_type == "java.lang.String":
        result = text_type(value)
        result.encode("latin-1")
        return result
    if (java_type == "[B" or getattr(value, "typecode", None) == "b") and helpers is not None:
        return _wire_text(helpers.bytesToString(value))
    if java_type == "[B" or getattr(value, "typecode", None) == "b":
        return bytearray((int(part) & 255 for part in value)).decode("latin-1")
    raise TypeError("Expected byte string, bytearray, byte-valued Unicode, Java String or byte[]")


def _custom_value(value, helpers=None):
    # None has historically meant an empty value. False/0 are invalid types.
    return "" if value is None else _wire_text(value, helpers)


def _extract_raw_payloads(request_text, name1, name2):
    """Keep the historical query/form, nonempty and equal-name priorities."""
    payload1, payload2 = "", ""
    first_line = request_text.split("\r\n", 1)[0]
    parts = first_line.split()
    target = parts[1] if len(parts) >= 2 else "/"
    sources = []
    if "?" in target:
        sources.append(target.split("?", 1)[1])
    separated = request_text.split("\r\n\r\n", 1)
    body = separated[1] if len(separated) > 1 else ""
    # Preserve the existing content-type detection; adding parsers is out of scope.
    if body and "=" in body and "application/x-www-form-urlencoded" in request_text.lower():
        sources.append(body)
    for source in sources:
        for pair in source.split("&"):
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            if name == name1 and not payload1:
                payload1 = value
            elif name == name2 and not payload2:
                payload2 = value
    return payload1, payload2


WORKFLOW_TIMEOUT_MS = 30000


def _monotonic_ms():
    import time as timer
    if hasattr(timer, "monotonic"):
        return timer.monotonic() * 1000.0
    from java.lang import System
    return System.nanoTime() / 1000000.0


class RedirectResult(object):
    """Keep terminal redirect errors separate from a usable final response."""
    def __init__(self, response_bytes, hops=0, error_code=None, error_type=None):
        self.response_bytes = response_bytes
        self.hops = hops
        self.error_code = error_code
        self.error_type = error_type


def _redirect_host_header(host, port, https):
    host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    authority = "[" + host + "]" if ":" in host else host
    if int(port) != (443 if https else 80):
        authority += ":%d" % int(port)
    return authority


def _redirect_base(request_text, host, port, https):
    parts = request_text.split("\r\n", 1)[0].split()
    if len(parts) != 3:
        raise ValueError("Invalid redirect base request")
    target = parts[1]
    if not target.startswith("/"):
        parsed = urlparse(target)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError("Unsupported redirect base target")
        target = (parsed.path or "/") + (";" + parsed.params if parsed.params else "")
        if parsed.query:
            target += "?" + parsed.query
    # The transport service, not the template's Host/absolute authority, owns
    # the base origin. The path/query still come from the actual request.
    scheme = "https" if https else "http"
    base = scheme + "://" + _redirect_host_header(host, port, https) + target
    return base, parts[0].upper()


def _redirect_destination(base, location):
    if not location or any(ord(c) <= 32 or ord(c) == 127 for c in location) or "\\" in location:
        raise ValueError("Invalid redirect Location")
    relative = urlparse(location)
    if relative.scheme and relative.scheme.lower() not in ("http", "https"):
        raise ValueError("Unsupported redirect scheme")
    if (relative.scheme or location.startswith("//")) and not relative.netloc:
        raise ValueError("Missing redirect authority")
    if not location.startswith(("/", "?", "#")) and not relative.scheme and ":" in location.split("/", 1)[0]:
        raise ValueError("Invalid relative redirect")
    # An explicit empty query clears the old query; Python 2/3 urljoin
    # otherwise treats a bare question mark as an absent query.
    absolute = (base.split("#", 1)[0].split("?", 1)[0] + location if location.startswith("?")
                else urljoin(base, location))
    parsed = urlparse(absolute)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname or "@" in parsed.netloc or parsed.netloc.endswith(":"):
        raise ValueError("Invalid redirect authority")
    https = scheme == "https"
    # Jython's Python-2 parser can report None for an out-of-range explicit
    # port. Read the authority suffix so this cannot silently become port 80.
    authority = parsed.netloc
    if authority.startswith("["):
        end = authority.find("]")
        suffix = authority[end + 1:]
        if end < 0 or (suffix and not suffix.startswith(":")):
            raise ValueError("Invalid IPv6 redirect authority")
        explicit_port = suffix[1:] if suffix else None
    else:
        if authority.count(":") > 1:
            raise ValueError("IPv6 redirect authority needs brackets")
        explicit_port = authority.rsplit(":", 1)[1] if ":" in authority else None
    if explicit_port is not None:
        if not explicit_port or any(c not in "0123456789" for c in explicit_port):
            raise ValueError("Invalid redirect port")
        port = int(explicit_port)
    else:
        port = 443 if https else 80
    if not 1 <= int(port) <= 65535:
        raise ValueError("Invalid redirect port")
    target = (parsed.path or "/") + (";" + parsed.params if parsed.params else "")
    if parsed.query:
        target += "?" + parsed.query
    host = parsed.hostname
    return host, int(port), https, target


class HttpSendResult(object):
    """A completed synchronous API call; attempted does not prove delivery."""
    def __init__(self, attempted=False, response_bytes=None, error_code=None, error_type=None):
        self.attempted = attempted
        self.response_bytes = response_bytes
        self.error_code = error_code
        self.error_type = error_type


class HttpRequestSender(object):
    """Choose an API before sending and normalize its response without retries."""
    def __init__(self, callbacks, helpers):
        self.callbacks = callbacks
        self.helpers = helpers
        self.api_kind = None
        self.detection_error = None
        try:
            signatures = []
            for method in callbacks.getClass().getMethods():
                if method.getName() == "makeHttpRequest":
                    signatures.append(tuple(str(p.getName()) for p in method.getParameterTypes()))
            if ("burp.IHttpService", "[B") in signatures:
                self.api_kind = "service"
            elif ("java.lang.String", "int", "boolean", "[B") in signatures:
                self.api_kind = "legacy"
        except (Exception, JavaException) as error:
            self.detection_error = type(error).__name__

    def _is_response_bytes(self, value):
        if isinstance(value, (bytes, bytearray)):
            return True
        if getattr(value, "typecode", None) == "b":
            return True
        try:
            return value.getClass().getName() == "[B"
        except (Exception, JavaException):
            return False

    def send(self, host, port, https, request_bytes):
        if self.api_kind is None:
            return HttpSendResult(error_code="HTTP_API_UNAVAILABLE", error_type=self.detection_error)
        attempted = False
        try:
            if self.api_kind == "service":
                service = self.helpers.buildHttpService(host, int(port), "https" if https else "http")
                attempted = True
                response_object = self.callbacks.makeHttpRequest(service, request_bytes)
                response = response_object.getResponse() if response_object is not None else None
            else:
                target_port = int(port)
                attempted = True
                response = self.callbacks.makeHttpRequest(host, target_port, bool(https), request_bytes)
            if response is None:
                return HttpSendResult(attempted=True, error_code="HTTP_NO_RESPONSE")
            if not self._is_response_bytes(response):
                return HttpSendResult(attempted=True, error_code="HTTP_INVALID_RESPONSE")
            if len(response) == 0:
                return HttpSendResult(attempted=True, error_code="HTTP_NO_RESPONSE")
            return HttpSendResult(attempted=True, response_bytes=response)
        except (Exception, JavaException) as error:
            return HttpSendResult(attempted=attempted, error_code="HTTP_SEND_FAILED",
                                  error_type=type(error).__name__)


class ProxyWorkflowResult(object):
    """Separate an unchanged request from failures before or after a send."""
    NO_MATCH = "no_match"
    READY = "ready"
    ERROR_BEFORE_SEND = "error_before_send"
    ERROR_AFTER_SEND = "error_after_send"

    def __init__(self, status, request_bytes=None, workflow_id=None, error_code=None, error_type=None, error_detail=None):
        self.status = status
        self.request_bytes = request_bytes
        self.workflow_id = workflow_id
        self.error_code = error_code
        self.error_type = error_type
        self.error_detail = error_detail


class LogEntry(object):
    def __init__(self, index, ts, host, method, path,
                 status, total_len, body_len, messageInfo):

        self.index = index
        self.ts = ts
        self.host = host
        self.method = method
        self.path = path
        self.status = status
        self.total_len = total_len
        self.body_len = body_len
        self.messageInfo = messageInfo


class NewestRows(object):
    """Append-only physical order, newest-first indexed view."""
    def __init__(self, values=()):
        self.items = list(reversed(list(values)))
    def __len__(self): return len(self.items)
    def __iter__(self): return reversed(self.items)
    def __getitem__(self, key):
        if isinstance(key, slice): return list(self)[key]
        if key < 0: key += len(self.items)
        if key < 0 or key >= len(self.items): raise IndexError(key)
        return self.items[len(self.items)-1-key]
    def __eq__(self, other): return list(self) == list(other)
    def add(self, value): self.items.append(value)
    def remove(self, value): self.items.remove(value)


class LogStore(object):
    def __init__(self):
        self._entries, self._counter = NewestRows(), 0
    def _get_entries(self): return self._entries
    def _set_entries(self, value): self._entries = NewestRows(value)
    entries = property(_get_entries, _set_entries)
    def add(self, ts, host, method, path, status, total_len, body_len, messageInfo):
        self._counter += 1
        entry = LogEntry(self._counter, ts, host, method, path, status, total_len, body_len, messageInfo)
        self._entries.add(entry)
        return entry
    def clear(self):
        self._entries, self._counter = NewestRows(), 0


class LogTableModel(AbstractTableModel):
    COLUMNS = ["#", "Time", "Host", "Method", "Path", "Status", "Total Len", "Body Len"]
    def __init__(self, logStore):
        AbstractTableModel.__init__(self)
        self.logStore, self._displayed = logStore, NewestRows()
        self._batch_start = None
    def _get_displayed(self): return self._displayed
    def _set_displayed(self, value):
        batching = self._batch_start is not None
        if batching: self.end_batch()
        self._displayed = NewestRows(value)
        if batching: self.begin_batch()
    displayed = property(_get_displayed, _set_displayed)
    def getRowCount(self): return len(self._displayed)
    def getColumnCount(self): return len(self.COLUMNS)
    def getColumnName(self, col): return self.COLUMNS[col]
    def getValueAt(self, row, col):
        try:
            entry = self._displayed[row]
            if col == 0: return Integer(entry.index)
            if col == 1: return entry.ts
            if col == 2: return entry.host
            if col == 3: return entry.method
            if col == 4: return entry.path
            value = (entry.status, entry.total_len, entry.body_len)[col-5]
            return None if col == 7 and value in ("", None) else Integer(value or 0)
        except (Exception, JavaException):
            return ""
    def getColumnClass(self, col): return Integer if col in (0,5,6,7) else str
    def isCellEditable(self, row, col): return False
    def rebuild(self, filter_fn=None):
        self.displayed = [e for e in self.logStore.entries if not filter_fn or filter_fn(e)]
        self.fireTableDataChanged()
    def begin_batch(self): self._batch_start = len(self._displayed)
    def end_batch(self):
        start, self._batch_start = self._batch_start, None
        if start is not None and len(self._displayed) > start:
            self.fireTableRowsInserted(0, len(self._displayed)-start-1)
    def add_entry_top(self, entry, show):
        if show:
            self._displayed.add(entry)
            if self._batch_start is None: self.fireTableRowsInserted(0,0)
    def clear(self):
        self._displayed = NewestRows()
        self.fireTableDataChanged()


class LogStorageError(Exception):
    pass


def _log_bytes(value):
    if value is None: return None
    return _wire_text(value).encode("latin-1")


def _log_copy(value):
    if value is None or isinstance(value, bytes): return value
    if isinstance(value, bytearray): return bytes(value)
    from java.util import Arrays
    return Arrays.copyOf(value, len(value))


class FrozenLogMessage(IHttpRequestResponse):
    """Owned native-interface snapshot. Never use JavaBean backing names."""
    def __init__(self, helpers, message, request=None, response=None):
        self._log_helpers = helpers
        service = message.getHttpService() if hasattr(message,"getHttpService") else None
        self._log_service = (helpers.buildHttpService(service.getHost(),service.getPort(),service.getProtocol())
                             if service is not None else None)
        self._log_request, self._log_response = _log_copy(request), _log_copy(response)
        self._log_comment = message.getComment() if hasattr(message,"getComment") else None
        self._log_highlight = message.getHighlight() if hasattr(message,"getHighlight") else None
    def getHttpService(self): return self._log_service
    def setHttpService(self,value): self._log_service = value
    def getRequest(self): return self._log_request
    def setRequest(self,value): self._log_request = value
    def getResponse(self): return self._log_response
    def setResponse(self,value): self._log_response = value
    def getComment(self): return self._log_comment
    def setComment(self,value): self._log_comment = value
    def getHighlight(self): return self._log_highlight
    def setHighlight(self,value): self._log_highlight = value
    def getHost(self): return self._log_service.getHost()
    def getPort(self): return self._log_service.getPort()
    def getProtocol(self): return self._log_service.getProtocol()
    def setHost(self,value): self._log_service = self._log_helpers.buildHttpService(value,self.getPort(),self.getProtocol())
    def setPort(self,value): self._log_service = self._log_helpers.buildHttpService(self.getHost(),value,self.getProtocol())
    def setProtocol(self,value): self._log_service = self._log_helpers.buildHttpService(self.getHost(),self.getPort(),value)
    def getUrl(self): return self._log_helpers.analyzeRequest(self).getUrl()
    def getStatusCode(self):
        return self._log_helpers.analyzeResponse(self._log_response).getStatusCode() if self._log_response is not None else 0


class StoredLogMessage(object):
    def __init__(self, archive, epoch, path, snapshot, lengths):
        self.archive, self.epoch, self.path = archive, epoch, path
        self.service = snapshot.getHttpService()
        self.comment, self.highlight = snapshot.getComment(), snapshot.getHighlight()
        self.lengths, self.readers, self.removed = lengths, 0, False
    def getRequest(self): return self.archive.read(self, 0)
    def getResponse(self): return self.archive.read(self, 1)
    def getHttpService(self): return self.service
    def getComment(self): return self.comment
    def getHighlight(self): return self.highlight
    def snapshot(self, helpers):
        return FrozenLogMessage(helpers, self, self.getRequest(), self.getResponse())


class LogArchive(object):
    """One owned file per message; no retained body cache or open file handle."""
    def __init__(self):
        from collections import deque
        self.lock = threading.Lock()
        self.root, self.epoch, self.serial = None, 0, 0
        self.records, self.retired, self.deleted = {}, deque(), deque()
        self.closed, self.cleanup_error = False, None
        self.writers = 0
        self.write_lock = threading.Lock()
    def put(self, snapshot, epoch):
        if swing.SwingUtilities.isEventDispatchThread(): raise LogStorageError("STORAGE_EDT_WRITE")
        with self.lock: self.writers += 1
        try:
            with self.write_lock: return self._put(snapshot,epoch)
        finally:
            with self.lock: self.writers -= 1
    def _put(self, snapshot, epoch):
        import os, tempfile, struct
        with self.lock:
            if self.closed or epoch != self.epoch: raise LogStorageError("STORAGE_STALE")
        # Only the filter worker writes. Directory creation and all I/O are off EDT.
        if self.root is None: self.root = tempfile.mkdtemp(prefix="BoberProxy-log-")
        with self.lock:
            self.serial += 1
            path = os.path.join(self.root, "%d.httpbin" % self.serial)
        request, response = _log_bytes(snapshot.getRequest()), _log_bytes(snapshot.getResponse())
        lengths = (len(request) if request is not None else -1, len(response) if response is not None else -1)
        record = StoredLogMessage(self,epoch,path,snapshot,lengths)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
            with os.fdopen(descriptor,"wb") as handle:
                handle.write(struct.pack("!qq",*lengths))
                if request is not None: handle.write(request)
                if response is not None: handle.write(response)
                handle.flush()
            with self.lock:
                if self.closed or epoch != self.epoch:
                    record.removed = True
                    self.deleted.append(record)
                    raise LogStorageError("STORAGE_STALE")
                self.records[path] = record
            return record
        except (Exception, JavaThrowable):
            with self.lock:
                if not record.removed:
                    record.removed = True
                    self.deleted.append(record)
            raise
    def read(self, record, part):
        import struct
        if swing.SwingUtilities.isEventDispatchThread(): raise LogStorageError("STORAGE_EDT_READ")
        with self.lock:
            if self.closed or record.removed or record.epoch != self.epoch: raise LogStorageError("STORAGE_STALE")
            record.readers += 1
        try:
            with open(record.path,"rb") as handle:
                header = handle.read(16)
                if len(header) != 16 or tuple(struct.unpack("!qq",header)) != record.lengths:
                    raise LogStorageError("STORAGE_CORRUPT_HEADER")
                length = record.lengths[part]
                if length < 0: return None
                handle.seek(16 + (max(0,record.lengths[0]) if part else 0))
                value = handle.read(length)
                if len(value) != length: raise LogStorageError("STORAGE_SHORT_READ")
                return value
        finally:
            with self.lock: record.readers -= 1
    def release(self, record):
        with self.lock:
            if not record.removed:
                record.removed = True
                self.records.pop(record.path,None)
                self.deleted.append(record)
    def clear(self, close=False):
        with self.lock:
            self.epoch += 1
            if self.records: self.retired.append(self.records)
            self.records = {}
            self.closed = self.closed or close
    def collect(self, count=64):
        import os
        for unused in range(count):
            with self.lock:
                if self.deleted: record = self.deleted.popleft()
                elif self.retired:
                    old = self.retired[0]
                    unused_path, record = old.popitem()
                    if not old: self.retired.popleft()
                    record.removed = True
                else: break
                if record.readers:
                    self.deleted.append(record)
                    continue
            try:
                if os.path.exists(record.path): os.unlink(record.path)
            except (Exception, JavaThrowable):
                with self.lock: self.deleted.append(record)
                self.cleanup_error = "STORAGE_CLEANUP_FAILED"
                break
        with self.lock: pending = bool(self.deleted or self.retired or self.records or self.writers)
        if not pending and self.closed and self.root is not None:
            try:
                os.rmdir(self.root)
                self.root = None
            except (Exception, JavaThrowable): self.cleanup_error = "STORAGE_DIRECTORY_CLEANUP_FAILED"
        return pending


class LogIoWorker(object):
    """One background reader/exporter/collector; one latest selection + one export."""
    def __init__(self, archive):
        from collections import OrderedDict, deque
        self.archive, self.condition = archive, threading.Condition()
        self.commands, self.results = OrderedDict(), deque()
        self.worker, self.closed = None, False
    def start(self):
        with self.condition:
            if self.closed: return False
            if self.worker is None: self.worker = _start_custom_worker(self._work,"BoberProxy.logio.v1")
            return self.worker is not None and self.worker.is_alive()
    def submit(self, key, operation, apply):
        if not self.start(): return False
        with self.condition:
            if self.closed or key == "export" and key in self.commands: return False
            if key not in ("viewer","export"): raise ValueError("Unknown log I/O task")
            self.commands[key] = (operation,apply)
            self.condition.notifyAll()
            return True
    def poll(self):
        with self.condition:
            if not self.results: return None
            result = self.results.popleft()
            self.condition.notifyAll()
            return result
    def _work(self):
        try:
            failures = 0
            while True:
                pending = self.archive.collect()
                with self.condition:
                    if self.closed:
                        if not pending: return
                        failures = failures+1 if self.archive.cleanup_error else 0
                        if failures >= 3: return
                    job = None
                    if self.commands and len(self.results) < 2 and not self.closed:
                        key = next(iter(self.commands))
                        job = self.commands.pop(key)
                    if job is None:
                        self.condition.wait(0.05)
                        continue
                operation, apply = job
                value, error = None, None
                try: value = operation()
                except (BaseException, JavaThrowable) as caught: error = caught
                operation = job = None
                with self.condition:
                    if not self.closed: self.results.append((apply,value,error))
                value = error = apply = None
        finally:
            with self.condition:
                self.closed = True
                self.commands.clear()
                self.results.clear()
    def close(self):
        self.archive.clear(close=True)
        with self.condition:
            self.closed = True
            self.commands.clear()
            self.results.clear()
            self.condition.notifyAll()


class CsrfManager(object):
    """One compatibility-session token; compile only when the pattern changes."""

    def __init__(self):
        self.lock = threading.Lock()
        self.token = None
        self._pattern_text = None
        self._compiled_pattern = None
        self._pattern_error = None
        self._generation = 0
        self._pattern_version = 0
        self._status = "REGEX_UNSET"
        self._detail = None

    def _decode(self, data):
        return _wire_text(data)

    def set_pattern(self, pattern):
        pattern = pattern.strip() if pattern is not None else ""
        with self.lock:
            if pattern == self._pattern_text:
                return self._pattern_error is None
            self._pattern_text = pattern
            self._pattern_version += 1
            self._compiled_pattern = None
            self._pattern_error = None
            self._detail = None
            if not pattern:
                self._status = "REGEX_UNSET"
                return True
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                if compiled.groups < 1:
                    self._pattern_error = "REGEX_NO_CAPTURE"
                    self._detail = "The CSRF regex needs a capturing group."
                else:
                    self._compiled_pattern = compiled
            except (ValueError, OverflowError, re.error) as error:
                self._pattern_error = "REGEX_INVALID"
                self._detail = str(error)
            self._status = self._pattern_error or "REGEX_READY"
            return self._pattern_error is None

    def get_pattern(self):
        with self.lock:
            return self._pattern_text

    pattern_to_use = property(get_pattern, set_pattern)

    def get_status(self):
        with self.lock:
            return self._status, self._detail

    def update_from_response(self, response_bytes):
        """Return (matched, token). No match or invalid regex retains the token.

        Searching does not hold the state lock. A Clear or pattern edit during
        this extraction invalidates its result; workflow-wide ordering is K06.
        """
        with self.lock:
            compiled = self._compiled_pattern
            generation, version = self._generation, self._pattern_version
            if compiled is None:
                self._status = self._pattern_error or "REGEX_UNSET"
                return False, None
        try:
            match = compiled.search(self._decode(response_bytes))
            token = match.group(1) if match is not None else None
            status, detail = ("UPDATED" if token is not None else "NO_MATCH"), None
        except (TypeError, ValueError, UnicodeError) as error:
            token, status, detail = None, "DECODE_ERROR", str(error)
        with self.lock:
            if generation != self._generation or version != self._pattern_version:
                return False, None
            self._status, self._detail = status, detail
            if token is not None:
                self.token = token
                return True, token
        return False, None

    def get_token(self):
        with self.lock:
            return self.token

    def set_token(self, value):
        with self.lock:
            self.token = value

    def clear(self):
        with self.lock:
            self.token = None
            self._generation += 1
            self._status, self._detail = "CLEARED", None

    def dump(self):
        with self.lock:
            if self.token is None:
                return "<no csrf token>"
            return self.token if self.token != "" else "<empty csrf token>"


class CookieManager(object):
    """Global compatibility jar, expiry metadata and template tombstones.

    Domain/Path/Secure are intentionally not selection boundaries in this mode.
    Individual operations are locked; complete workflows are coordinated in K06.
    """

    def __init__(self):
        self.jar = {}
        self.expires = {}
        self.deleted = set()
        self.lock = threading.Lock()
        self._generation = 0

    def _decode(self, data):
        return _wire_text(data)

    def _now(self):
        return time.time()

    @staticmethod
    def _expires_date(value):
        # Cookie-date token order and 2-digit years: RFC 6265 section 5.1.1.
        # No local timezone, permissive calendar normalization or comma split.
        import calendar
        import datetime
        hour = minute = second = day = month = year = None
        months = ("jan", "feb", "mar", "apr", "may", "jun",
                  "jul", "aug", "sep", "oct", "nov", "dec")
        for token in re.split(r"[\x09\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+", value):
            if hour is None:
                match = re.match(r"^(\d{1,2}):(\d{1,2}):(\d{1,2})(?:[^0-9].*)?$", token)
                if match:
                    hour, minute, second = [int(part) for part in match.groups()]
                    continue
            if day is None and re.match(r"^[0-9]{1,2}(?:[^0-9].*)?$", token):
                day = int(re.match(r"^[0-9]+", token).group(0))
                continue
            if month is None and token[:3].lower() in months:
                month = months.index(token[:3].lower()) + 1
                continue
            if year is None and re.match(r"^[0-9]{2,4}(?:[^0-9].*)?$", token):
                year = int(re.match(r"^[0-9]+", token).group(0))
        if None in (hour, minute, second, day, month, year):
            return None
        if 70 <= year <= 99:
            year += 1900
        elif 0 <= year <= 69:
            year += 2000
        if year < 1601:
            return None
        try:
            date = datetime.datetime(year, month, day, hour, minute, second)
            return float(calendar.timegm(date.timetuple()))
        except (ValueError, OverflowError):
            return None

    def _expiry_from_attributes(self, attributes, now):
        max_age, expires = None, None
        for attribute in attributes:
            name, separator, value = attribute.partition("=")
            if not separator:
                continue
            name, value = name.strip().lower(), value.strip()
            if name == "max-age" and re.match(r"^-?[0-9]+$", value):
                # Cap without converting an arbitrarily long untrusted integer.
                digits = value.lstrip("-").lstrip("0") or "0"
                if value.startswith("-") or digits == "0":
                    max_age = 0
                else:
                    max_age = 253402300799 if len(digits) > 12 else int(digits)
            elif name == "expires":
                parsed = self._expires_date(value)
                if parsed is not None:
                    expires = parsed
        if max_age is not None:
            return 0.0 if max_age <= 0 else min(now + max_age, 253402300799.0)
        return expires

    def _expire_locked(self, now):
        for name, expiry in list(self.expires.items()):
            if expiry <= now:
                self.jar.pop(name, None)
                self.expires.pop(name, None)
                self.deleted.add(name)

    def update_from_response(self, response_bytes_or_text):
        """Parse actual Set-Cookie fields in order; return change tuples."""
        with self.lock:
            generation = self._generation
        txt = self._decode(response_bytes_or_text)
        now = self._now()
        parsed = []
        for line in txt.split("\r\n\r\n", 1)[0].split("\r\n")[1:]:
            header_name, separator, value = line.partition(":")
            if not separator or header_name.strip().lower() != "set-cookie":
                continue
            parts = value.strip().split(";")
            name, separator, value = parts[0].partition("=")
            name, value = name.strip(), value.strip()
            if not separator or not name:
                continue
            # Invalid names/control bytes must not create request-header data.
            if any(ord(char) <= 32 or ord(char) >= 127 or char in '()<>@,;:\\"/[]?={}' for char in name):
                continue
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                continue
            parsed.append((name, value, self._expiry_from_attributes(parts[1:], now)))
        changes = []
        with self.lock:
            if generation != self._generation:
                return changes
            self._expire_locked(now)
            for name, value, expiry in parsed:
                old = self.jar.get(name)
                if expiry is not None and expiry <= now:
                    self.jar.pop(name, None)
                    self.expires.pop(name, None)
                    self.deleted.add(name)
                    changes.append(("deleted", name, old, None))
                else:
                    self.jar[name] = value
                    self.deleted.discard(name)
                    if expiry is None:
                        self.expires.pop(name, None)
                    else:
                        self.expires[name] = expiry
                    changes.append(("added" if old is None else "updated", name, old, value))
        return changes

    def inject_into_request(self, request_text):
        txt = self._decode(request_text)
        parts = txt.split("\r\n\r\n", 1)
        header_lines = parts[0].split("\r\n")
        body = parts[1] if len(parts) > 1 else ""
        existing, new_header_lines = {}, []
        for line in header_lines:
            name, separator, value = line.partition(":")
            if separator and name.strip().lower() == "cookie":
                for pair in value.split(";"):
                    if "=" in pair:
                        key, val = pair.split("=", 1)
                        existing[key.strip()] = val.strip()
            else:
                new_header_lines.append(line)
        with self.lock:
            self._expire_locked(self._now())
            merged = dict(existing)
            for name in self.deleted:
                merged.pop(name, None)
            merged.update(self.jar)
        if merged:
            cookie_header = "Cookie: " + "; ".join("%s=%s" % (key, val) for key, val in merged.items())
            insert_at = 1 if len(new_header_lines) > 1 else len(new_header_lines)
            for index, line in enumerate(new_header_lines):
                if line.lower().startswith("host:"):
                    insert_at = index + 1
                    break
            new_header_lines.insert(insert_at, cookie_header)
        return "\r\n".join(new_header_lines) + "\r\n\r\n" + body

    def clear(self):
        with self.lock:
            self.jar = {}
            self.expires = {}
            self.deleted = set()
            self._generation += 1

    def dump(self):
        with self.lock:
            self._expire_locked(self._now())
            if not self.jar:
                return "<no cookies>"
            return "; ".join("%s=%s" % (key, val) for key, val in self.jar.items())


class RuntimeConfig(object):
    """Published values are owned by this snapshot, never widget references."""
    def __init__(self, values, version):
        self._values = values
        self.version = version

    def get(self, name, default=None):
        return self._values.get(name, default)


def _session_cookie_copy(manager):
    result = CookieManager()
    with manager.lock:
        manager._expire_locked(manager._now())
        result.jar = dict(manager.jar)
        result.expires = dict(manager.expires)
        result.deleted = set(manager.deleted)
    return result


def _session_pattern_state(manager):
    with manager.lock:
        return (manager._pattern_text, manager._compiled_pattern,
                manager._pattern_error, manager._detail)


def _session_csrf_copy(manager, pattern_state):
    result = CsrfManager()
    with manager.lock:
        result.token = manager.token
    if pattern_state is None:
        pattern_state = _session_pattern_state(manager)
    (result._pattern_text, result._compiled_pattern,
     result._pattern_error, result._detail) = pattern_state
    result._status = result._pattern_error or ("REGEX_READY" if result._compiled_pattern else "REGEX_UNSET")
    return result


class SessionContext(object):
    def __init__(self, key, config, epoch, matched):
        self.key, self.epoch, self.matched = key, epoch, matched
        self.config = config if matched else None
        self.cookies_enabled = config.get("cookies", False)
        self.csrf_enabled = config.get("csrf", False)
        self.pattern_state = config.get("csrf_pattern")
        self.created = _monotonic_ms()
        self.deadline = None
        self.phase = "waiting" if matched else "passive"
        self.cancelled = False
        self.cookies = self.csrf = None
        self.any_sent = False


class SessionCoordinator(object):
    """Serialize managed exchanges through the Proxy's final response.

    An ownership lease is not a held network lock. Other callbacks can collect
    passive state or Clear while the owner waits on Burp. Clear starts an epoch,
    cancels the previous lease and rejects every old-epoch publication. It cannot
    unsend bytes already handed to Proxy or stop a blocking internal API call.
    """
    def __init__(self, cookies, csrf):
        from collections import OrderedDict
        self.condition = threading.Condition()
        self.cookies, self.csrf = cookies, csrf
        self.epoch, self.sequence = 0, 0
        self.owner = None
        self.waiting = []
        self.records = OrderedDict()
        self.closed = False
        self.cookie_sequences = {}
        self.token_sequence = 0
        self.untracked_responses = 0
        self.max_records = 4096
        self.max_waiters = 32
        self.record_ttl_ms = 120000

    def _prune_locked(self):
        now = _monotonic_ms()
        for key, context in list(self.records.items()):
            if context is self.owner or context in self.waiting:
                continue
            if now - context.created >= self.record_ttl_ms:
                self.records.pop(key, None)

    def register(self, key, config, matched):
        with self.condition:
            if self.closed:
                return None, "SESSION_CLOSED"
            if key is not None and key in self.records:
                return self.records[key], "EXISTING"
            self._prune_locked()
            if key is not None and len(self.records) >= self.max_records:
                return None, "SESSION_TRACKING_FULL"
            context = SessionContext(key, config, self.epoch, matched)
            if key is not None:
                self.records[key] = context
            return context, None

    def begin(self, context, deadline):
        with self.condition:
            if self.closed:
                return "SESSION_CLOSED"
            if len(self.waiting) >= self.max_waiters:
                return "SESSION_BUSY"
            self.waiting.append(context)
            try:
                while self.owner is not None or self.waiting[0] is not context:
                    if self.closed:
                        return "SESSION_CLOSED"
                    now = _monotonic_ms()
                    if self.owner is not None and now >= self.owner.deadline:
                        # Unknown delivery is not proof that the old CP stopped.
                        # Keep its slot until response, explicit Clear or unload.
                        return "SESSION_RESPONSE_PENDING"
                    remaining = deadline - now
                    if remaining <= 0:
                        return "SESSION_BUSY"
                    if self.owner is not None:
                        remaining = min(remaining, self.owner.deadline - now)
                    self.condition.wait(max(0.001, remaining / 1000.0))
                if self.closed:
                    return "SESSION_CLOSED"
                if _monotonic_ms() >= deadline:
                    return "SESSION_BUSY"
                context.epoch = self.epoch
                context.deadline = deadline
                context.cookies = _session_cookie_copy(self.cookies)
                context.csrf = _session_csrf_copy(self.csrf, context.pattern_state)
                context.phase = "active"
                self.owner = context
                return None
            finally:
                self.waiting.remove(context)
                self.condition.notifyAll()

    def valid(self, context):
        with self.condition:
            return not self.closed and not context.cancelled and context.epoch == self.epoch

    def commit(self, context):
        with self.condition:
            if self.closed or context.cancelled or context.epoch != self.epoch or self.owner is not context:
                return False
            context.phase = "handoff"
            return True

    def finish(self, context, original_response=False):
        with self.condition:
            if self.owner is context:
                self.owner = None
                self.condition.notifyAll()
            if original_response:
                context.phase = "passive"
                context.config = None
                context.cookies = context.csrf = None
            elif context.key is not None:
                self.records.pop(context.key, None)

    def clear(self, kind):
        with self.condition:
            if kind == "cookies":
                self.cookies.clear()
            else:
                self.csrf.clear()
            self.epoch += 1
            self.cookie_sequences = {}
            self.token_sequence = 0
            if self.owner is not None:
                self.owner.cancelled = True
                self.owner = None
            self.condition.notifyAll()

    def close(self):
        with self.condition:
            self.closed = True
            if self.owner is not None:
                self.owner.cancelled = True
            self.owner = None
            self.records.clear()
            self.condition.notifyAll()

    def update(self, context, response):
        # No regex or response parsing occurs while holding the ownership lock.
        with self.condition:
            if self.closed or context.cancelled or context.epoch != self.epoch:
                return "SESSION_STALE_RESPONSE", None
            if not context.cookies_enabled and not context.csrf_enabled:
                return None, None
            self.sequence += 1
            sequence = self.sequence
            cookies = context.cookies
            csrf = context.csrf
            if cookies is None:
                cookies = _session_cookie_copy(self.cookies)
            if csrf is None:
                csrf = _session_csrf_copy(self.csrf, context.pattern_state)
        changes = cookies.update_from_response(response) if context.cookies_enabled else []
        ok, token = csrf.update_from_response(response) if context.csrf_enabled else (False, None)
        delta = []
        with cookies.lock:
            names = set(change[1] for change in changes)
            for name in names:
                delta.append((name, cookies.jar.get(name), cookies.expires.get(name), name in cookies.deleted))
        with self.condition:
            if self.closed or context.cancelled or context.epoch != self.epoch:
                return "SESSION_STALE_RESPONSE", None
            with self.cookies.lock:
                for name, value, expiry, deleted in delta:
                    if sequence < self.cookie_sequences.get(name, 0):
                        continue
                    self.cookie_sequences[name] = sequence
                    if deleted or expiry is not None and expiry <= self.cookies._now():
                        self.cookies.jar.pop(name, None)
                        self.cookies.expires.pop(name, None)
                        self.cookies.deleted.add(name)
                    else:
                        self.cookies.jar[name] = value
                        self.cookies.deleted.discard(name)
                        if expiry is None:
                            self.cookies.expires.pop(name, None)
                        else:
                            self.cookies.expires[name] = expiry
            if ok and sequence >= self.token_sequence:
                self.token_sequence = sequence
                with self.csrf.lock:
                    self.csrf.token = token
                    self.csrf._status, self.csrf._detail = "UPDATED", None
        return csrf.get_status() if context.csrf_enabled else (None, None)

    def response(self, key, response):
        with self.condition:
            context = self.records.pop(key, None)
            if context is None:
                self.untracked_responses += 1
                return "SESSION_RESPONSE_UNTRACKED", None
        try:
            return self.update(context, response) if response is not None else (None, None)
        finally:
            self.finish(context)



class SimpleMessageController(IMessageEditorController):
    def __init__(self):
        self._messageInfo = None
    def setMessageInfo(self, messageInfo):
        self._messageInfo = messageInfo
    def getHttpService(self):
        try:
            return self._messageInfo.getHttpService() if self._messageInfo else None
        except:
            return None
    def getRequest(self):
        try:
            return self._messageInfo.getRequest() if self._messageInfo else None
        except:
            return None
    def getResponse(self):
        try:
            return self._messageInfo.getResponse() if self._messageInfo else None
        except:
            return None

# MODULE-LEVEL helper: exec code in given namespace
def _exec_in_namespace(code, namespace):
    # run user code in the provided dict namespace
    exec(code, namespace)


def _custom_timeout(value):
    """Validate without truncating floats or silently accepting bad UI input."""
    try:
        integer_types = (int, long)
    except NameError:
        integer_types = (int,)
    if isinstance(value, bool):
        raise ValueError("timeout must be an integer from 1 to 30000 ms")
    if isinstance(value, integer_types):
        result = value
    else:
        try:
            text = value.strip()
        except AttributeError:
            raise ValueError("timeout must be an integer from 1 to 30000 ms")
        if not re.match(r"^[+]?[0-9]+$", text):
            raise ValueError("timeout must be an integer from 1 to 30000 ms")
        digits = text.lstrip("+").lstrip("0") or "0"
        if len(digits) > 5:
            raise ValueError("timeout must be an integer from 1 to 30000 ms")
        result = int(digits)
    if not 1 <= result <= 30000:
        raise ValueError("timeout must be an integer from 1 to 30000 ms")
    return result


def _custom_failure(code, detail):
    return False, None, code + ": " + detail


def _custom_error_detail(error):
    # Diagnostics may contain genuine Unicode, independently of wire values.
    try:
        text_type = unicode
    except NameError:
        text_type = str
    try:
        message = text_type(error)
    except (BaseException, JavaException):
        message = text_type(type(error).__name__) + " (exception text unavailable)"
    try:
        trace = traceback.format_exc()
        if not isinstance(trace, text_type):
            trace = trace.decode("utf-8", "replace")
        return message + "\n" + trace
    except (BaseException, JavaException):
        return message


class CustomWorkerHandle(object):
    def __init__(self, thread, java=False):
        self.thread, self.java = thread, java

    def is_alive(self):
        return self.thread.isAlive() if self.java else self.thread.is_alive()

    def join(self, seconds):
        self.thread.join(max(1, int(seconds * 1000)) if self.java else seconds)


def _start_custom_worker(target, gate_name=None):
    """Claim one process-wide worker, including other Jython interpreters.

    A bootstrap Java class monitor makes check/start atomic across interpreters.
    A dedicated ThreadGroup remains identifiable if custom code renames its
    thread. This is lifecycle coordination, not a sandbox for arbitrary code.
    """
    gate_name = gate_name or CUSTOM_GATE_NAME
    try:
        from java.lang import Thread, ThreadGroup, Runnable, Class
        from synchronize import apply_synchronized
    except ImportError:
        # CPython logic harness only; the production runtime uses the JVM gate.
        import threading as native_threads
        with CUSTOM_START_LOCK:
            if any(t.name == gate_name and t.is_alive() for t in native_threads.enumerate()):
                return None
            thread = threading.Thread(target=target, name=gate_name)
            thread.setDaemon(True)
            thread.start()
            return CustomWorkerHandle(thread)

    class Worker(Runnable):
        def run(self):
            target()

    def claim():
        for thread in Thread.getAllStackTraces().keySet():
            group = thread.getThreadGroup()
            if thread.isAlive() and group is not None and group.getName() == gate_name:
                return None
        group = ThreadGroup(gate_name)
        thread = Thread(group, Worker(), gate_name)
        thread.setDaemon(True)
        thread.start()
        return CustomWorkerHandle(thread, java=True)
    return apply_synchronized(Class.forName("java.lang.ThreadGroup"), claim, ())


class CustomJob(object):
    def __init__(self, code, args, deadline):
        self.code, self.args, self.deadline = code, args, deadline
        self.done, self.timed_out, self.result = False, False, None


class CustomExecutor(object):
    """One worker + one pending job; never interrupt or replace running code."""
    def __init__(self, helpers):
        self.helpers = helpers
        self.condition = threading.Condition()
        self.worker = None
        self.pending = self.active = None
        self.closed = False
        self._cached_text = self._cached_code = None

    def _finish_locked(self, job, result):
        if not job.done:
            job.result, job.done = result, True
            self.condition.notifyAll()

    def _poll_locked(self, job):
        if not job.done and _monotonic_ms() >= job.deadline:
            job.timed_out = True
            self._finish_locked(job, _custom_failure("CUSTOM_TIMEOUT", "timeout"))
            if self.pending is job:
                self.pending = None
                job.code, job.args = None, ()
        return job.result if job.done else None

    def submit(self, code, timeout_ms, args):
        # Deadline precedes worker acquisition, queueing and compilation.
        started = _monotonic_ms()
        try:
            timeout_ms = _custom_timeout(timeout_ms)
        except (TypeError, ValueError) as error:
            job = CustomJob(None, (), started)
            job.done, job.result = True, _custom_failure("CUSTOM_CONFIG_ERROR", str(error))
            return job
        job = CustomJob(code, args, started + timeout_ms)
        with self.condition:
            if self.closed:
                self._finish_locked(job, _custom_failure("CUSTOM_CLOSED", "extension unloaded"))
                return job
            if self.active is not None:
                self._poll_locked(self.active)
            if self.pending is not None:
                self._poll_locked(self.pending)
            if self.pending is not None or (self.active is not None and self.active.timed_out):
                self._finish_locked(job, _custom_failure("CUSTOM_BUSY", "custom worker is occupied"))
                return job
            if self.worker is None:
                try:
                    self.worker = _start_custom_worker(self._work)
                except (Exception, JavaException) as error:
                    self._finish_locked(job, _custom_failure("CUSTOM_RUNTIME_ERROR", str(error)))
                    return job
                if self.worker is None:
                    self._finish_locked(job, _custom_failure("CUSTOM_BUSY", "a previous extension worker is still running"))
                    return job
            if not self.worker.is_alive():
                self._finish_locked(job, _custom_failure("CUSTOM_CLOSED", "custom worker terminated"))
                return job
            self.pending = job
            self.condition.notifyAll()
        return job

    def poll(self, job):
        with self.condition:
            return self._poll_locked(job)

    def wait(self, job):
        with self.condition:
            while self._poll_locked(job) is None:
                self.condition.wait(max(0.001, (job.deadline - _monotonic_ms()) / 1000.0))
            return job.result

    def _cancelled(self, job):
        with self.condition:
            return self.closed or self._poll_locked(job) is not None

    def _execute(self, job):
        try:
            if job.code != self._cached_text:
                source = job.code
                try:
                    text_type = unicode
                except NameError:
                    text_type = str
                if isinstance(source, text_type):
                    # Swing already supplied decoded text; Python 2 rejects a
                    # byte-encoding cookie in Unicode source. Keep line numbers.
                    lines = source.splitlines(True)
                    for index in range(min(2, len(lines))):
                        if re.match(r"^[ \t\f]*#", lines[index]):
                            lines[index] = re.sub(r"coding[:=][ \t]*[-\w.]+", "encoding supplied by editor", lines[index])
                    source = "".join(lines)
                compiled = compile(source, "<BoberProxy custom>", "exec")
                self._cached_text, self._cached_code = job.code, compiled
            if self._cancelled(job):
                return _custom_failure("CUSTOM_TIMEOUT", "timeout")
            namespace = {}
            _exec_in_namespace(self._cached_code, namespace)
        except (BaseException, JavaException) as error:
            return _custom_failure("CUSTOM_ERROR", "Compilation error: " + _custom_error_detail(error))
        if self._cancelled(job):
            return _custom_failure("CUSTOM_TIMEOUT", "timeout")
        fn = namespace.get("custom_codeblock")
        if not callable(fn):
            return _custom_failure("CUSTOM_ERROR", "custom_codeblock not defined as callable in user code")
        try:
            out = fn(*job.args)
            if not isinstance(out, (list, tuple)):
                return _custom_failure("CUSTOM_ERROR", "custom_codeblock must return a tuple/list of 3 elements: (payload1, payload2, csrf_token)")
            if len(out) != 3:
                return _custom_failure("CUSTOM_ERROR", "custom_codeblock must return exactly 3 elements in order: payload1, payload2, csrf_token")
            try:
                return True, (_custom_value(out[0], self.helpers), _custom_value(out[1], self.helpers),
                              None if out[2] is None else _custom_value(out[2], self.helpers)), None
            except (Exception, JavaException) as error:
                return _custom_failure("CUSTOM_ERROR", "Invalid custom return value: " + _custom_error_detail(error))
        except (BaseException, JavaException) as error:
            return _custom_failure("CUSTOM_ERROR", _custom_error_detail(error))

    def _work(self):
        try:
            while True:
                with self.condition:
                    while self.pending is None and not self.closed:
                        self.condition.wait()
                    if self.closed:
                        return
                    job, self.pending = self.pending, None
                    if self._poll_locked(job) is not None:
                        job.code, job.args = None, ()
                        continue
                    self.active = job
                result = self._execute(job)
                with self.condition:
                    if not self.closed and self._poll_locked(job) is None:
                        self._finish_locked(job, result)
                    self.active = None
                    job.code, job.args = None, ()
                    job = result = None
                    self.condition.notifyAll()
        finally:
            self.close()
            self._cached_text = self._cached_code = None

    def close(self):
        # No join/interrupt on the EDT or inside network callbacks.
        with self.condition:
            self.closed = True
            if self.pending is not None:
                self._finish_locked(self.pending, _custom_failure("CUSTOM_CLOSED", "extension unloaded"))
                self.pending.code, self.pending.args = None, ()
                self.pending = None
            if self.active is not None:
                self._finish_locked(self.active, _custom_failure("CUSTOM_CLOSED", "extension unloaded"))
            self.condition.notifyAll()

    def state(self):
        with self.condition:
            return dict(closed=self.closed, active=self.active is not None,
                        pending=self.pending is not None,
                        worker_alive=self.worker is not None and self.worker.is_alive())



# --- Filter dialog / UI ------------------------------------------
class FilterInputError(Exception):
    def __init__(self, field, detail):
        Exception.__init__(self, field + ": " + detail)
        self.field, self.detail = field, detail


def _filter_text(value):
    try:
        return unicode(value)
    except NameError:
        return str(value)


def _filter_numbers(values, field):
    result = []
    for value in values:
        try:
            result.append(int(value))
        except (ValueError, TypeError, OverflowError):
            raise FilterInputError(field, "Invalid integer: " + _filter_text(value)[:160])
    return tuple(result)


def _filter_diagnostic(error):
    text = _filter_text(error)
    return text[:480] + ("..." if len(text) > 480 else "")


def _filter_pattern(value, flags, field):
    try:
        return Pattern.compile(value, flags)
    except (Exception, JavaThrowable) as error:
        raise FilterInputError(field, _filter_text(error))


class CaptureFilterPlan(object):
    def __init__(self, values, previous=None):
        self.statuses = tuple(values.get("statuses", ()))
        text = values.get("size", "")
        self.size_text = text
        self.numbers = (previous.numbers if previous is not None and previous.size_text == text
                        else _filter_numbers([s.strip() for s in text.split(",") if s.strip()], "Len value") if text else ())
        if text and not self.numbers:
            raise FilterInputError("Len value", "Enter at least one integer")
        self.len_type = values.get("len_type", "Total len")
        self.comparator = values.get("size_comp", "Min Len")
        self.pattern_text = values.get("log_regex", "")
        self.pattern = (previous.pattern if previous is not None and previous.pattern_text == self.pattern_text
                        else _filter_pattern(self.pattern_text, 0, "Response regex") if self.pattern_text else None)
        if previous is not None and self.numbers is previous.numbers:
            self.minimum, self.maximum, self.number_set = previous.minimum, previous.maximum, previous.number_set
        else:
            self.minimum = min(self.numbers) if self.numbers else None
            self.maximum = max(self.numbers) if self.numbers else None
            self.number_set = frozenset(self.numbers)

    def accepts(self, status, total_len, body_len, response, helpers, search=True):
        if self.statuses and not any(status is not None and n*100 <= status < (n+1)*100 for n in self.statuses):
            return False
        if self.numbers:
            actual = total_len if self.len_type == "Total len" else body_len
            if actual in (None, ""):
                actual = total_len
            if self.comparator == "Min Len" and actual < self.minimum:
                return False
            if self.comparator == "Max Len" and actual > self.maximum:
                return False
            if self.comparator == "Not eq Len" and actual in self.number_set:
                return False
        return not search or self.pattern is None or bool(self.pattern.matcher(helpers.bytesToString(response) if response else "").find())


class DisplayFilterPlan(object):
    def __init__(self, config, previous=None):
        self.patterns = {}
        self.fields, self.has_regex, self.version = [], False, 0
        for name in DISPLAY_FILTER_FIELDS:
            values = config.get(name, {})
            if not values.get("active"):
                continue
            tokens = tuple(values.get("values", ()))
            mode = values.get("mode", "eq")
            if mode not in ("eq", "not eq"):
                raise FilterInputError(name, "Unknown comparison mode")
            compiled = tokens
            if name == "BodyLen":
                compiled = frozenset(_filter_numbers(tokens, name))
            elif name == "ResponseContent":
                patterns = []
                for value in tokens:
                    if not value:
                        continue
                    key = (value, Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
                    if key not in self.patterns:
                        self.patterns[key] = (previous.patterns[key] if previous is not None and key in previous.patterns
                                              else _filter_pattern(value, key[1], name))
                    patterns.append(self.patterns[key])
                compiled = tuple(patterns)
                self.has_regex = bool(compiled)
            self.fields.append((name, mode, bool(tokens), compiled))
        self.fields = tuple(self.fields)

    def matches(self, entry, helpers):
        hay = None
        for name, mode, populated, values in self.fields:
            if not populated:
                return False  # Legacy: empty active filter rejects even not eq.
            if name == "BodyLen":
                try:
                    matched = entry.body_len not in (None, "") and int(entry.body_len) in values
                except (ValueError, TypeError, OverflowError):
                    matched = False
            elif name == "ResponseContent":
                if not values:
                    if mode == "eq":
                        return False
                    continue
                if hay is None:
                    response = entry.messageInfo.getResponse() if entry.messageInfo else None
                    hay = helpers.bytesToString(response) if response else ""
                matched = any(pattern.matcher(hay).find() for pattern in values)
            else:
                value = {"Host":entry.host, "Method":entry.method, "Path":entry.path,
                         "Status":_filter_text(entry.status or "")}.get(name, "") or ""
                value = _filter_text(value).strip()
                matched = any(token and (token in value if name == "Path" else token == value) for token in values)
            if (mode == "eq" and not matched) or (mode == "not eq" and matched):
                return False
        return True


class FilterJob(object):
    def __init__(self, operation, apply, key):
        self.operation, self.apply, self.key = operation, apply, key
        self.result, self.error, self.started = None, None, None


class RawLogBudget(object):
    def __init__(self, limit=32*1024*1024):
        self.lock, self.limit, self.used = threading.Lock(), limit, 0
    def reserve(self,cost):
        with self.lock:
            if cost < 0 or self.used+cost > self.limit: return False
            self.used += cost
            return True
    def release(self,cost):
        with self.lock: self.used -= cost


class FilterWorker(object):
    """One JVM-wide worker, 128 row jobs, three coalesced controls/results.

    A Java regex can ignore interruption. No replacement while old work lives,
    no blocking queue admission, and no hard-timeout claim.
    """
    def __init__(self):
        from collections import deque, OrderedDict
        self.condition = threading.Condition()
        self.rows, self.controls, self.results = deque(), OrderedDict(), deque()
        self.capacity = 128
        self.gate_name = "BoberProxy.filters.v1"
        self.worker = self.active = None
        self.closed = False
        self.retry_at = 0
        self.row_bytes = 0
        self.budget = None
        self.byte_capacity = 32 * 1024 * 1024

    def submit(self, operation, apply, key=None):
        with self.condition:
            if self.closed:
                return False
            if self.worker is None:
                if _monotonic_ms() < self.retry_at:
                    return False
                self.worker = _start_custom_worker(self._work, self.gate_name)
                if self.worker is None:
                    self.retry_at = _monotonic_ms() + 1000
                    return False
            if not self.worker.is_alive():
                return False
            if key is None:
                if len(self.rows) >= self.capacity:
                    return False
                self.rows.append(FilterJob(operation, apply, key))
            else:
                if key not in ("capture", "display", "rebuild"):
                    raise ValueError("Unknown filter control")
                self.controls[key] = FilterJob(operation, apply, key)
            self.condition.notifyAll()
            return True

    def submit_log(self, prepare, apply, cost):
        with self.condition:
            if self.closed or cost > self.byte_capacity or self.row_bytes + cost > self.byte_capacity or len(self.rows) >= self.capacity:
                return False
            if self.worker is None:
                self.worker = _start_custom_worker(self._work,self.gate_name)
            if self.worker is None or not self.worker.is_alive(): return False
            if self.budget is not None and not self.budget.reserve(cost): return False
            job = FilterJob(None,apply,None)
            job.cost = cost
            self.row_bytes += cost
            self.rows.append(job)
        try:
            operation = prepare()
        except (BaseException, JavaThrowable):
            with self.condition:
                if job in self.rows:
                    self.rows.remove(job)
                    self._release_log_cost(job)
                self.condition.notifyAll()
            raise
        with self.condition:
            if self.closed: return False
            job.operation = operation
            self.condition.notifyAll()
            return True

    def _work(self):
        try:
            while True:
                with self.condition:
                    while not self.closed and (not self.rows and not self.controls or len(self.results) >= self.capacity or self.rows and self.rows[0].operation is None and not self.controls):
                        self.condition.wait()
                    if self.closed:
                        return
                    if self.controls:
                        key = next(iter(self.controls))
                        job = self.controls.pop(key)
                    else:
                        job = self.rows.popleft()
                    self.active, job.started = job, _monotonic_ms()
                try:
                    job.result = job.operation()
                except (BaseException, JavaThrowable) as error:
                    job.error = LogStorageError(type(error).__name__) if getattr(job,"cost",0) else error
                job.operation = None
                with self.condition:
                    self.active = None
                    self._release_log_cost(job)
                    if not self.closed:
                        self.results.append(job)
                    self.condition.notifyAll()
        finally:
            with self.condition:
                self.closed = True
                self.condition.notifyAll()

    def poll(self):
        with self.condition:
            if not self.results:
                return None
            job = self.results.popleft()
            self.condition.notifyAll()
            return job

    def state(self):
        with self.condition:
            return dict(closed=self.closed, rows=len(self.rows), controls=len(self.controls), raw_bytes=self.row_bytes,
                        results=len(self.results), active=self.active is not None,
                        running_ms=_monotonic_ms()-self.active.started if self.active else 0)

    def _release_log_cost(self,job):
        cost = getattr(job,"cost",0)
        self.row_bytes -= cost
        if self.budget is not None: self.budget.release(cost)
        job.cost = 0

    def close(self):
        with self.condition:
            self.closed = True
            for job in self.rows: self._release_log_cost(job)
            self.rows.clear()
            self.controls.clear()
            self.results.clear()
            self.condition.notifyAll()


class RuntimePublisher(object):
    """Coalesce EDT edits; use public editor getters on the EDT only.

    Native message-editor views materialize lazily. Public Swing document
    listeners provide prompt updates when present; a 100 ms EDT poll covers
    other editor backends/programmatic edits without callback invokeAndWait.
    """
    def __init__(self, ui):
        from javax.swing.event import DocumentListener
        from java.awt.event import ItemListener
        self.ui, self.closed, self.scheduled = ui, False, False
        self.documents = []
        self.items = []
        publisher = self
        class Documents(DocumentListener):
            def insertUpdate(self, event):
                publisher.schedule()
            def removeUpdate(self, event):
                publisher.schedule()
            def changedUpdate(self, event):
                publisher.schedule()
        class Items(ItemListener):
            def itemStateChanged(self, event):
                publisher.schedule()
        self.document_listener, self.item_listener = Documents(), Items()
        for name in ("proxyModeBtn", "useCheckPageChk", "autoFollowRTChk", "useCustomChk",
                     "autoUpdateChk", "autoUpdateCsrfChk", "pauseBtn", "lenTypeCombo", "compCombo"):
            widget = getattr(ui, name, None)
            if widget is not None:
                widget.addItemListener(self.item_listener)
                self.items.append(widget)
        for widget in getattr(ui, "statusChecks", {}).values():
            widget.addItemListener(self.item_listener)
            self.items.append(widget)
        self.ticks = 0
        self.observe_documents()
        ui._publish_runtime()
        self.timer = swing.Timer(100, lambda event: self.tick())
        self.timer.start()

    def observe_documents(self):
        from javax.swing.text import JTextComponent
        documents = []
        def walk(component):
            if isinstance(component, JTextComponent):
                document = component.getDocument()
                if document not in documents:
                    documents.append(document)
            if hasattr(component, "getComponents"):
                for child in component.getComponents():
                    walk(child)
        for name in ("customCodeArea", "timeoutField", "csrfRegexArea", "payloadParamField",
                     "payloadParam2Field", "sizeField", "regexField"):
            widget = getattr(self.ui, name, None)
            if widget is not None:
                walk(widget)
        for name in ("reqTemplateEditor", "checkPageEditor"):
            editor = getattr(self.ui, name, None)
            if editor is not None:
                walk(editor.getComponent())
        for document in self.documents:
            if document not in documents:
                document.removeDocumentListener(self.document_listener)
        for document in documents:
            if document not in self.documents:
                document.addDocumentListener(self.document_listener)
        self.documents = documents

    def schedule(self):
        if self.closed or self.scheduled:
            return
        self.scheduled = True
        def publish():
            self.scheduled = False
            if not self.closed:
                self.ui._publish_runtime()
        swing.SwingUtilities.invokeLater(publish)

    def tick(self):
        if self.closed:
            return
        self.ticks += 1
        if self.ticks % 10 == 0:
            self.observe_documents()
        self.ui._publish_runtime()

    def close(self):
        self.closed = True
        self.timer.stop()
        for document in self.documents:
            document.removeDocumentListener(self.document_listener)
        for item in self.items:
            item.removeItemListener(self.item_listener)
        self.documents, self.items = [], []



class FilterDialog(object):
    def __init__(self, parent):
        from java.awt.event import WindowAdapter
        self.parent, self.closed = parent, False
        self.dialog = swing.JDialog()
        self.dialog.setTitle("Display filter")
        self.dialog.setModal(True)
        self.dialog.setDefaultCloseOperation(swing.JDialog.DISPOSE_ON_CLOSE)
        owner = self
        class Closing(WindowAdapter):
            def windowClosing(self, event):
                owner._on_cancel()
        self.dialog.addWindowListener(Closing())
        panel = swing.JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets, c.fill = Insets(4,4,4,4), GridBagConstraints.HORIZONTAL
        self.controls = {}
        self.loaded_text, self.loaded_values = {}, {}
        for row, name in enumerate(DISPLAY_FILTER_FIELDS):
            enabled = swing.JCheckBox("",False)
            mode = swing.JComboBox(["eq","not eq"])
            value = swing.JTextArea(3,40) if name == "ResponseContent" else swing.JTextField("",40)
            value.setToolTipText("One Java regex per line; commas stay inside a pattern." if name == "ResponseContent"
                                 else "Comma-separated values")
            c.gridy, c.gridx, c.weightx = row,0,0.0
            panel.add(enabled,c)
            c.gridx = 1
            panel.add(swing.JLabel(name),c)
            c.gridx = 2
            panel.add(mode,c)
            c.gridx, c.weightx = 3,1.0
            panel.add(swing.JScrollPane(value) if name == "ResponseContent" else value,c)
            self.controls[name] = enabled,mode,value
        self.errorLabel = swing.JLabel("")
        c.gridy, c.gridx, c.gridwidth = len(DISPLAY_FILTER_FIELDS),0,4
        panel.add(self.errorLabel,c)
        buttons = swing.JPanel(FlowLayout(FlowLayout.RIGHT,6,0))
        self.applyBtn = swing.JButton("Apply",actionPerformed=self._on_apply)
        buttons.add(self.applyBtn)
        buttons.add(swing.JButton("Reset",actionPerformed=self._on_reset))
        buttons.add(swing.JButton("Cancel",actionPerformed=self._on_cancel))
        c.gridy += 1
        panel.add(buttons,c)
        self.dialog.setContentPane(panel)
        self.dialog.pack()
        self.dialog.setLocationRelativeTo(parent._component)
        parent._filter_dialog = self

    def load_from_parent(self):
        for name, (enabled,mode,field) in self.controls.items():
            config = self.parent.display_filters.get(name,{})
            enabled.setSelected(bool(config.get("active")))
            mode.setSelectedItem(config.get("mode","eq"))
            values = list(config.get("values",[]))
            text = ("\n" if name == "ResponseContent" else ",").join(_filter_text(value) for value in values)
            field.setText(text)
            self.loaded_text[name], self.loaded_values[name] = text,values

    def candidate(self):
        result = {}
        for name, (enabled,mode,field) in self.controls.items():
            text = _filter_text(field.getText() or "")
            if text == self.loaded_text.get(name):
                # Preserve existing in-memory list items, even a legacy pattern
                # containing a literal newline, until the user edits that text.
                values = list(self.loaded_values[name])
            else:
                parts = text.splitlines() if name == "ResponseContent" else text.split(",")
                values = [part.strip() for part in parts if part.strip()]
            result[name] = dict(active=bool(enabled.isSelected()),
                               mode=_filter_text(mode.getSelectedItem()),values=values)
        return result

    def _on_apply(self, event=None):
        self.parent._apply_display_filters(self.candidate(),self)

    def _on_cancel(self, event=None):
        self.closed = True
        if self.parent._filter_dialog is self:
            self.parent._filter_dialog = None
        self.dialog.dispose()

    def _on_reset(self, event=None):
        for enabled,mode,field in self.controls.values():
            enabled.setSelected(False)
            mode.setSelectedItem("eq")
            field.setText("")
        self.errorLabel.setText("")
        self.parent._apply_display_filters(self.candidate())


class LoggerUI(ITab):
    """Burp tab implementation that owns the UI state and the proxy workflow."""

    def __init__(self, callbacks, controller, msgEditor, callbacks_ref):
        # -------- core references / state ----------
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.controller = controller
        self.msgEditor = msgEditor
        self.callbacks_ref = callbacks_ref
        self._init_custom_runtime()
        self._http_sender = None
        self._workflow_lock = threading.Lock()
        self._workflow_counter = 0
        self._suspend_selection_events = False

        #------------------NEW---------------------------
        #  LogStore
        self.logStore = LogStore()

        #  LogTableModel
        self.logTableModel = LogTableModel(self.logStore)

        #  JTable
        self.table = JTable(self.logTableModel)
        self.table.setSelectionMode(
            ListSelectionModel.SINGLE_SELECTION
        )

        #  Sorter
        self.rowSorter = TableRowSorter(self.logTableModel)
        self.table.setRowSorter(self.rowSorter)

        # 5 Selection listener
        self.table.getSelectionModel().addListSelectionListener(
            self.on_table_select
        )
        #------------------NEW---------------------------

        self._init_display_filters()
        self._init_filter_runtime()

        # search / highlight state
        self._search_matches = []
        self._current_match_idx = -1

        # Proxy toggle state: when True, extension will intercept proxy requests and run the processing flow
        self._proxy_mode_active = False

        # other flags / storage
        self.paused = False
        self.running = False


        # Custom codeblock defaults
        self.default_code_text = (
            "def custom_codeblock(payload1, payload2, csrf_token):\n"
            "    \"\"\"\n"
            "    Custom transform hook that MUST accept and MUST return exactly three values.\n"
            "    Parameters\n"
            "    - payload1: first incoming payload (string)\n"
            "    - payload2: second incoming payload (string)\n"
            "    - csrf_token: csrf token (string)\n"
            "    MUST return exactly three elements in this order:\n"
            "    return payload1, payload2, csrf_token\n"
            "    \"\"\"\n"
            "    # Default behaviour: pass inputs through unchanged\n"
            "\n"
            "\n"
            "    return payload1, payload2, csrf_token\n"
        )

        self.custom_timeout_ms = 500
        self.payload_param_name = "q"

        # Cookie / CSRF managers + flags
        self.cookieManager = CookieManager()
        self.autoUpdateCookies = False

        self.csrfManager = CsrfManager()
        self._init_session_runtime()
        self.autoUpdateCsrf = False

        # default CSRF regex pattern (use %s for insertion of param name)
        self.csrf_default_pattern = r'<input[^>]+name=["\\\']csrfmiddlewaretoken["\\\'][^>]*value=["\\\']([^"\\\']*)["\\\']'

        # -------- main split panes ----------
        self.mainSplit = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.mainSplit.setDividerLocation(1280)

        # left split: detail (top) / table (bottom)
        self.leftSplit = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)
        self.leftSplit.setDividerLocation(500)

        # ---------- BUILD LEFT SIDE (tabs) ----------
        # Viewer panel (Burp request/response message editors split)
        # Replace plain text detailArea with two IMessageEditor viewers (request / response)
        viewerPanel = swing.JPanel(GridBagLayout())
        vgc = GridBagConstraints()
        vgc.insets = Insets(0,0,0,0)
        vgc.fill = GridBagConstraints.BOTH
        vgc.weightx = 1.0
        vgc.weighty = 1.0

        # Create IMessageEditor instances (use controller that will be setMessageInfo on selection)
        # left: request editor (editable False), right: response editor (editable False)
        # prefer the msgEditor passed in (existing), but create separate viewers via callbacks if available
        self.reqViewer = callbacks.createMessageEditor(self.controller, False)
        self.respViewer = callbacks.createMessageEditor(self.controller, False)
        # obtain Swing components
        reqComp = self.reqViewer.getComponent()
        respComp = self.respViewer.getComponent()


        # split pane: left=request, right=response (equal divider)
        self.viewerSplit = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        self.viewerSplit.setLeftComponent(reqComp)
        self.viewerSplit.setRightComponent(respComp)
        # set a sensible initial divider location (half)
        self.viewerSplit.setDividerLocation(600)

        vgc.gridx = 0; vgc.gridy = 0; vgc.weighty = 1.0
        viewerPanel.add(self.viewerSplit, vgc)

        # Request Template panel
        reqTemplatePanel = swing.JPanel(GridBagLayout())
        rtc = GridBagConstraints()
        rtc.insets = Insets(2,2,2,2)
        rtc.fill = GridBagConstraints.BOTH
        rtc.weightx = 1.0
        rtc.weighty = 1.0

        # === Request Template: use Burp IMessageEditor (editable) ===
        # controller for template editors: simple controller that will provide no
        # associated IMessageInfo when editor is used stand-alone.
        self._template_req_controller = SimpleMessageController()
        self.reqTemplateEditor = callbacks.createMessageEditor(self._template_req_controller, True)
        self.reqTemplateComp = self.reqTemplateEditor.getComponent()


        # small control row for request template (existing ctrlPanel kept)
        rtc.gridx = 0; rtc.gridy = 0; rtc.weighty = 1.0
        reqTemplatePanel.add(self.reqTemplateComp, rtc)

        # compact single-row control: buttons on the left, tooltip on the right (one line)
        rowPanel = swing.JPanel(GridBagLayout())
        rpc = GridBagConstraints()
        rpc.insets = Insets(2,2,2,2)
        rpc.fill = GridBagConstraints.HORIZONTAL
        rpc.gridy = 0

        # right: tooltip text field (non-editable) that expands to fill remaining width
        self.reqTooltipField = swing.JTextField(TEMPLATE_MARKER_HINT)
        self.reqTooltipField.setEditable(False)
        self.reqTooltipField.setFont(Font("Dialog", Font.PLAIN, 12))
        self.reqTooltipField.setBorder(None)
        try:
            # subtle background to look like a label (optional)
            self.reqTooltipField.setForeground(Color(220,220,220))
        except:
            pass

        # place btnPanel at gridx 0, weightx 0 (does not expand)
        rpc.gridx = 0
        rpc.weightx = 1.0    # tooltip stretches
        rpc.anchor = GridBagConstraints.WEST
        rowPanel.add(self.reqTooltipField, rpc)

        # left: buttons in a small flow panel
        btnPanel = swing.JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        self.loadFromViewerBtn = swing.JButton("Load from Viewer", actionPerformed=self._load_template_from_viewer)
        btnPanel.add(self.loadFromViewerBtn)
        self.clearReqTemplateBtn = swing.JButton("Clear", actionPerformed=self._clear_req_template)
        btnPanel.add(self.clearReqTemplateBtn)

        rpc.gridx = 2
        rpc.weightx = 0.0
        rpc.anchor = GridBagConstraints.EAST
        rowPanel.add(btnPanel, rpc)


        # add the single-row panel into the template panel (same grid row as before)
        rtc.gridy = 1; rtc.weighty = 0.0; rtc.fill = GridBagConstraints.HORIZONTAL
        reqTemplatePanel.add(rowPanel, rtc)


        # === CheckPageTemplate: use Burp IMessageEditor (editable) ===
        self._template_check_controller = SimpleMessageController()
        self.checkPageEditor = callbacks.createMessageEditor(self._template_check_controller, True)
        self.checkPageComp = self.checkPageEditor.getComponent()
 
        # CheckPageTemplate panel
        checkPagePanel = swing.JPanel(GridBagLayout())
        cpc = GridBagConstraints()
        cpc.insets = Insets(2,2,2,2)
        cpc.fill = GridBagConstraints.BOTH
        cpc.weightx = 1.0
        cpc.weighty = 1.0
        cpc.gridx = 0; cpc.gridy = 0; cpc.weighty = 1.0
        checkPagePanel.add(self.checkPageComp, cpc)

        # compact single-row control for CheckPageTemplate: buttons on the left, tooltip on the right
        checkRowPanel = swing.JPanel(GridBagLayout())
        crpc = GridBagConstraints()
        crpc.insets = Insets(2,2,2,2)
        crpc.fill = GridBagConstraints.HORIZONTAL
        crpc.gridy = 0

        # right: tooltip text field (non-editable) that expands to fill remaining width
        self.checkTooltipField = swing.JTextField(TEMPLATE_MARKER_HINT)
        self.checkTooltipField.setEditable(False)
        self.checkTooltipField.setFont(Font("Dialog", Font.PLAIN, 12))
        self.checkTooltipField.setBorder(None)
        try:
            self.checkTooltipField.setForeground(Color(220,220,220))
        except:
            pass

        crpc.gridx = 0
        crpc.weightx = 1.0    # tooltip stretches
        crpc.anchor = GridBagConstraints.WEST
        checkRowPanel.add(self.checkTooltipField, crpc)

        # left: buttons in a small flow panel
        checkBtnPanel = swing.JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        self.loadToCheckBtn = swing.JButton("Load from Viewer", actionPerformed=self._load_check_from_viewer)
        checkBtnPanel.add(self.loadToCheckBtn)
        self.clearCheckTemplateBtn = swing.JButton("Clear", actionPerformed=self._clear_check_template)
        checkBtnPanel.add(self.clearCheckTemplateBtn)

        crpc.gridx = 1
        crpc.weightx = 0.0    # buttons do not expand
        checkRowPanel.add(checkBtnPanel, crpc)

        # add the single-row panel into the checkPage panel (reuse same grid row as before)
        cpc.gridy = 1; cpc.weighty = 0.0; cpc.fill = GridBagConstraints.HORIZONTAL
        checkPagePanel.add(checkRowPanel, cpc)


        # tabs on the left
        self.tabbed = swing.JTabbedPane()
        self.tabbed.addTab("Viewer", viewerPanel)
        self.tabbed.addTab("Request Template", reqTemplatePanel)
        self.tabbed.addTab("CheckPageTemplate", checkPagePanel)

        # Tab change handling: reset scroll/caret so user sees top

        self.leftSplit.setLeftComponent(self.tabbed)


        self.table.setSelectionMode(swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        self.leftSplit.setRightComponent(swing.JScrollPane(self.table))

        # attach left split to main split
        self.mainSplit.setLeftComponent(self.leftSplit)

        # ---------- RIGHT: controls (mode + filters + utility) ----------
        # We'll use a GridBagLayout for overall placement, but make groups use horizontal Box/Flow where needed
        rightWrapper = swing.JPanel()
        rightWrapper.setLayout(swing.BoxLayout(rightWrapper, swing.BoxLayout.Y_AXIS))        

        # Inner grid content (kept same as before)        
        rightContent = swing.JPanel(GridBagLayout())
        # FIX minimum width – NO dynamic resizing
        rightContent.setMinimumSize(Dimension(610, 0))
        c = GridBagConstraints()
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 0.5
        row = 0

        # Mode selector (proxy / local)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        modePanel = swing.JPanel()
        self.proxyModeBtn = swing.JToggleButton("Injecting proxy from templates", False, actionPerformed=lambda e: self._on_proxy_toggle())
        modePanel.add(self.proxyModeBtn)
        rightContent.add(modePanel, c)
        row += 1

        # Logging header
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(swing.JLabel("Logging options"), c)
        row += 1
        c.gridwidth = 1

        # Status checks label + checkboxes on same row (compact)
        c.gridy = row; c.gridx = 0; c.gridwidth = 1
        c.weightx = 1.0
        c.anchor = GridBagConstraints.WEST
        rightContent.add(swing.JLabel("Status groups:"), c)

        # Use FlowLayout for the checkbox row (keeps them in one line and allows wrapping when needed)
        try:
            statusPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        except:
            statusPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))

        self.statusChecks = {}
        for label in ["1xx", "2xx", "3xx", "4xx", "5xx"]:
            cb = swing.JCheckBox(label, False)
            self.statusChecks[label] = cb
            statusPanel.add(cb)

        c.gridx = 1; c.gridwidth = 1
        c.weightx = 0.0
        c.anchor = GridBagConstraints.EAST
        rightContent.add(statusPanel, c)

        # restore defaults
        c.anchor = GridBagConstraints.CENTER
        c.weightx = 0.0
        row += 1

        # Len filter controls
        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Len filter:"), c)
        self.lenTypeCombo = swing.JComboBox(["Total len", "Response body len"])
        c.gridx = 1
        rightContent.add(self.lenTypeCombo, c)
        row += 1

        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Comparator:"), c)
        self.compCombo = swing.JComboBox(["Min Len", "Max Len", "Not eq Len"])
        c.gridx = 1
        rightContent.add(self.compCombo, c)
        row += 1

        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Value (bytes):"), c)
        self.sizeField = swing.JTextField("", 10)
        self.sizeField.setToolTipText("Enter one or more byte values, separated by commas (e.g. 100,200,512)")
        c.gridx = 1
        rightContent.add(self.sizeField, c)
        row += 1

        # Regex field
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(swing.JLabel("Response regex (Java Pattern, .find() must match):"), c)
        row += 1
        c.gridy = row
        self.regexField = swing.JTextField("", 20)
        self.regexField.setToolTipText("Uses Java regex (java.util.regex.Pattern); escape backslashes (\\w, \\d, etc.); evaluated with .find(), not .matches().")

        rightContent.add(self.regexField, c)
        row += 1

        # Sitemap / Clear / Pause - horizontal button row (FlowLayout)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        c.weightx = 1.0
        c.anchor = GridBagConstraints.CENTER

        buttonPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        # Add same set of buttons and keep names/actions
        self.addSitemapBtn = swing.JButton("Add selected to Site map", actionPerformed=self.add_selected_to_sitemap)
        buttonPanel.add(self.addSitemapBtn)

        self.clearBtn = swing.JButton("Clear log", actionPerformed=self.clear_log)
        buttonPanel.add(self.clearBtn)

        self.clearSelBtn = swing.JButton("Clear selected", actionPerformed=self.clear_selected)
        buttonPanel.add(self.clearSelBtn)

        self.pauseBtn = swing.JToggleButton("Pause logging", False, actionPerformed=self.toggle_pause)
        buttonPanel.add(self.pauseBtn)

        # Filter button: next to the Pause button (located on the right side)
        self.filterBtn = swing.JButton("Filter", actionPerformed=lambda e: self._open_filter_dialog())
        buttonPanel.add(self.filterBtn)

        # limit maximum expansion of the button row to avoid forcing horizontal scroll early
        buttonPanel.setMaximumSize(buttonPanel.getPreferredSize())
        rightContent.add(buttonPanel, c)

        # restore defaults
        c.gridwidth = 1
        c.weightx = 0.0
        row += 1


        # instantiate:
        self.useCheckPageChk = swing.JCheckBox("Use CheckPageTemplate", False, actionPerformed=self._on_use_checkpage_toggle)
        self.useCheckPageTemplate = False

        self.autoFollowRTChk = swing.JCheckBox("AutoFollow redirect on RT", False)
        self.autoFollowRTChk.setEnabled(False)

        # add to UI in one row:
        c.gridy = row
        c.gridx = 0
        rightContent.add(self.useCheckPageChk, c)
        c.gridx = 1
        rightContent.add(self.autoFollowRTChk, c)
        row += 1


        # --- Cookies checkbox ---
        self.autoUpdateChk = swing.JCheckBox(
            "Auto-update cookies from responses", False,
            actionPerformed=lambda e: setattr(self, "autoUpdateCookies", bool(self.autoUpdateChk.isSelected()))
        )

        # --- CSRF checkbox ---
        self.autoUpdateCsrfChk = swing.JCheckBox(
            "Auto-update CSRF from responses", False,
            actionPerformed=lambda e: setattr(self, "autoUpdateCsrf", bool(self.autoUpdateCsrfChk.isSelected()))
        )

        # --- Cookies buttons ---
        cookiePanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        self.clearCookiesBtn = swing.JButton("Clear Cookies", actionPerformed=lambda e: self._on_clear_cookies())
        cookiePanel.add(self.clearCookiesBtn)
        self.showCookiesBtn = swing.JButton("Show Cookies", actionPerformed=lambda e: self._on_show_cookies())
        cookiePanel.add(self.showCookiesBtn)
        cookiePanel.setMaximumSize(cookiePanel.getPreferredSize())

        # --- CSRF buttons ---
        csrfPanel = swing.JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        self.clearCsrfBtn = swing.JButton("Clear CSRF", actionPerformed=lambda e: self._on_clear_csrf())
        csrfPanel.add(self.clearCsrfBtn)
        self.showCsrfBtn = swing.JButton("Show CSRF", actionPerformed=lambda e: self._on_show_csrf())
        csrfPanel.add(self.showCsrfBtn)
        csrfPanel.setMaximumSize(csrfPanel.getPreferredSize())


        # --- Elrendezés: két sor, két oszlop ---
        # sor 1: checkboxok
        c.gridy = row; c.gridx = 0
        rightContent.add(self.autoUpdateChk, c)
        c.gridx = 1
        rightContent.add(self.autoUpdateCsrfChk, c)
        row += 1

        # sor 2: gombpárok
        c.gridy = row; c.gridx = 0
        rightContent.add(cookiePanel, c)
        c.gridx = 1
        rightContent.add(csrfPanel, c)
        row += 1


        # CSRF regex label + reset button (kept in the same style as other rows)
        c.gridy = row; c.gridx = 0; c.gridwidth = 1
        rightContent.add(swing.JLabel("Regex pattern (Python-style, first capturing group = token):"), c)
        self.resetCsrfRegexBtn = swing.JButton("Reset to default", actionPerformed=lambda e: self._on_reset_csrf_regex())
        c.gridx = 1
        rightContent.add(self.resetCsrfRegexBtn, c)
        row += 1

        # two-line text area for custom regex pattern
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.csrfRegexArea = swing.JTextArea(self.csrf_default_pattern, 2, 40)
        self.csrfRegexArea.setLineWrap(False)
        from javax.swing.event import DocumentListener
        ui = self
        class CsrfRegexListener(DocumentListener):
            def insertUpdate(self, event):
                ui._on_csrf_regex_changed()
            def removeUpdate(self, event):
                ui._on_csrf_regex_changed()
            def changedUpdate(self, event):
                ui._on_csrf_regex_changed()
        self.csrfRegexArea.getDocument().addDocumentListener(CsrfRegexListener())
        self._on_csrf_regex_changed()
        self.csrfRegexArea.setToolTipText("Custom regex to extract the CSRF token. The first capturing group is used.")
        self.csrfRegexScroll = swing.JScrollPane(self.csrfRegexArea)
        rightContent.add(self.csrfRegexScroll, c)
        row += 1

        # ---------- Custom codeblock UI ----------
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        rightContent.add(swing.JLabel("Custom payload transform"), c)
        row += 1
        c.gridwidth = 1

        self.useCustomChk = swing.JCheckBox("Use custom codeblock", False, actionPerformed=self._on_toggle_custom)
        c.gridy = row; c.gridx = 0
        rightContent.add(self.useCustomChk, c)
        self.timeoutField = swing.JTextField(str(self.custom_timeout_ms), 6)
        self.timeoutField.setToolTipText("Timeout (ms)")
        self.custom_codeblock_status = False
        c.gridx = 1
        rightContent.add(self.timeoutField, c)
        row += 1

        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Payload1 param name (%s):" % TEMPLATE_PAYLOAD_MARKER_1), c)
        self.payloadParamField = swing.JTextField(self.payload_param_name, 10)
        c.gridx = 1
        rightContent.add(self.payloadParamField, c)
        row += 1

        # new attribute default
        self.payload_param2_name = "w"

        # UI: second payload param name field (next to payloadParamField)
        c.gridy = row; c.gridx = 0
        rightContent.add(swing.JLabel("Payload2 param name (%s):" % TEMPLATE_PAYLOAD_MARKER_2), c)
        self.payloadParam2Field = swing.JTextField(self.payload_param2_name, 10)
        c.gridx = 1
        rightContent.add(self.payloadParam2Field, c)
        row += 1


        # custom code text area (multi-line)
        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.customCodeArea = swing.JTextArea(self.default_code_text, 10, 40)
        self.customCodeArea.setLineWrap(False)
        self.customCodeScroll = swing.JScrollPane(self.customCodeArea)
        rightContent.add(self.customCodeScroll, c)
        row += 1

        # Buttons: Test | Reset (keep separated and with small gap)
        c.gridy = row
        c.gridwidth = 1
        c.gridx = 0
        self.testCodeBtn = swing.JButton("Test", actionPerformed=self._on_test_code)
        rightContent.add(self.testCodeBtn, c)

        c.gridx = 1
        self.resetBtn = swing.JButton("Reset", actionPerformed=self._reset_custom_code)
        rightContent.add(self.resetBtn, c)
        row += 1

        # Error/output area (fills remaining vertical space)
        # Create a sub-panel with BorderLayout so the scroll pane fills it completely
        outputPanel = swing.JPanel(BorderLayout())

        # Create the output text area
        self.customStatusArea = swing.JTextArea()
        self.customStatusArea.setEditable(False)
        self.customStatusArea.setLineWrap(True)
        self.customStatusArea.setWrapStyleWord(True)
        self.customStatusArea.setFocusable(True)

        # Wrap text area in a scroll pane
        scroll = swing.JScrollPane(self.customStatusArea)
        scroll.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        scroll.setHorizontalScrollBarPolicy(swing.JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        scroll.setPreferredSize(Dimension(0, 120))  # default visible area (~5 lines)

        ui = self
        class CustomSettingsListener(DocumentListener):
            def insertUpdate(self, event):
                ui._on_custom_settings_changed()
            def removeUpdate(self, event):
                ui._on_custom_settings_changed()
            def changedUpdate(self, event):
                ui._on_custom_settings_changed()
        self.customCodeArea.getDocument().addDocumentListener(CustomSettingsListener())
        self.timeoutField.getDocument().addDocumentListener(CustomSettingsListener())

        # initially disable custom controls (preserve original behavior)
        self._on_toggle_custom()

        # Add scroll pane to the output panel (fills the panel)
        outputPanel.add(scroll, BorderLayout.CENTER)

        # Layout constraints for the output panel itself
        c.gridy = row
        c.gridx = 0
        c.gridwidth = 2
        c.fill = GridBagConstraints.BOTH
        c.weightx = 1.0
        c.weighty = 1.0

        # Add the output panel instead of the scroll directly
        rightContent.add(outputPanel, c)
        row += 1

        # reset fill/grid hints
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridwidth = 1
        c.weighty = 0.0
        row += 1  

        c.gridy = row; c.gridx = 0; c.gridwidth = 2
        self.filterStatusLabel = swing.JLabel("Filters ready")
        rightContent.add(self.filterStatusLabel, c)
        row += 1
        c.gridy = row
        self.statusLabel = swing.JLabel("Running")
        rightContent.add(self.statusLabel, c)
        row += 1
        c.gridwidth = 1

        # spacer at the end to push items to top
        c.gridy = row; c.weighty = 1.0
        rightContent.add(swing.JPanel(), c)
        row += 1

        # wrap rightContent into wrapper so layout can flexibly shrink
        rightWrapper.add(rightContent)
        # small rigid spacer below to prevent jitter when resizing
        rightWrapper.add(swing.Box.createRigidArea(Dimension(0, 5)))
        # scroll pane around the wrapper (not directly rightContent!)
        self.rightScroll = swing.JScrollPane(rightWrapper)
        
        self.rightScroll.setHorizontalScrollBarPolicy(swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self.rightScroll.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        self.rightScroll.getViewport().setScrollMode(swing.JViewport.SIMPLE_SCROLL_MODE)

        # attach to main split
        self.mainSplit.setRightComponent(self.rightScroll)

        # expose final component
        self._component = self.mainSplit

        # ensure mode buttons reflect initial state
        try:
            _sync_mode_buttons()
        except:
            pass

        self._creation_on_edt = bool(swing.SwingUtilities.isEventDispatchThread())
        self._runtime_publisher = RuntimePublisher(self)
        self._filter_timer = swing.Timer(50, lambda event: self._filter_tick())
        self._filter_timer.start()

    # --- Error/output area (isolated in its own container, expands only within itself) ---
    def _log(self, msg):
        def publish():
            if getattr(self, "_custom_ui_closed", False):
                return
            try:
                try:
                    text_type = unicode
                except NameError:
                    text_type = str
                self.customStatusArea.setText(text_type(msg))
            except (Exception, JavaException) as error:
                print("customStatusArea_SETTEXT_ERROR:", error)
        if swing.SwingUtilities.isEventDispatchThread():
            publish()
        else:
            swing.SwingUtilities.invokeLater(publish)


    def _to_text(self, data):
        """
        Robust conversion of various response forms to a unicode string.
        Handles:
         - bytes / bytearray
         - iterable of ints (Java byte[] / Jython byte[] view)
         - string repr like "array('b', [72, 84, ...])"
         - fallback to str()
        """
        try:
            # already bytes-like
            if isinstance(data, (bytes, bytearray)):
                try:
                    return data.decode("latin-1", "replace")
                except:
                    return data.decode("utf-8", "replace")

            # If it's an actual iterable (Java byte[], list of ints, etc.) but not a str
            if hasattr(data, '__iter__') and not isinstance(data, str):
                try:
                    out = bytearray()
                    for b in data:
                        try:
                            iv = int(b)
                        except Exception:
                            try:
                                iv = ord(b)
                            except Exception:
                                iv = 0
                        if iv < 0:
                            iv = iv + 256
                        out.append(iv)
                    return bytes(out).decode("latin-1", "replace")
                except Exception:
                    # fallthrough to string handling
                    pass

            # otherwise, try to parse common textual reprs like: array('b', [72, 84, ...])
            s = str(data)

            # pattern: array('b', [72, 84, ...])
            try:
                m = re.match(r"^\s*array\('b'\s*,\s*\[([0-9,\s]+)\]\s*\)\s*$", s)
                if m:
                    nums = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
                    if nums:
                        return bytes(nums).decode("latin-1", "replace")
            except Exception:
                pass

            # fallback: if string contains bracketed numbers like [72, 84, ...], try that
            try:
                m2 = re.search(r"\[([0-9,\s]+)\]", s)
                if m2:
                    parts = [p.strip() for p in m2.group(1).split(',') if p.strip().isdigit()]
                    if parts:
                        nums = [int(p) for p in parts]
                        return bytes(nums).decode("latin-1", "replace")
            except Exception:
                pass

            # final fallback: return the string representation
            return s

        except Exception:
            try:
                return str(data)
            except:
                return ""


    def _on_proxy_toggle(self):
        """
        Toggle the proxy-mode processing flag. When enabled, the extension will
        actively intercept proxy requests and run the processing flow.
        """
        try:
            self._proxy_mode_active = bool(self.proxyModeBtn.isSelected())

            # mutual exclusion: if proxy ON, force local OFF
            if self._proxy_mode_active:
                try:
                    self._update_autofollow_enabled_on_proxy()
                except:
                    pass
            else:
                try:
                    self._update_autofollow_enabled_on_proxy()
                except:
                    pass

            self._log("Proxy processing toggled: %s" % ("ON" if self._proxy_mode_active else "OFF"))
        except Exception as e:
            self._log("Error toggling proxy processing: %s" % str(e))


    def _update_autofollow_enabled_on_proxy(self):
        """
        Enable autoFollowRTChk only if proxy mode is active AND
        useCheckPageChk is selected.
        """
        if self._proxy_mode_active and self.useCheckPageChk.isSelected():
            self.autoFollowRTChk.setEnabled(True)
        else:
            self.autoFollowRTChk.setSelected(False)
            self.autoFollowRTChk.setEnabled(False)


    def _on_use_checkpage_toggle(self, event=None):
        self.useCheckPageTemplate = self.useCheckPageChk.isSelected()
        self._update_autofollow_enabled_on_proxy()


    def _open_filter_dialog(self, evt=None):
        try:
            # I assume that there is a FilterDialog class that expects the parent in its constructor.
            dlg = FilterDialog(self)
            # if the dialog has a load_from_parent method, call it
            try:
                dlg.load_from_parent()
            except Exception:
                # if there is no such method, it is not critical
                pass
            # position relative to the logger component
            try:
                dlg.dialog.setLocationRelativeTo(self._component)
            except Exception:
                try:
                    dlg.dialog.setLocationRelativeTo(None)
                except Exception:
                    pass
            dlg.dialog.setVisible(True)
        except Exception as e:
            # Let's try to update customStatusArea if it is available
            try:
                self.customStatusArea.setText("Cannot open filter dialog: %s" % e)
            except Exception:
                # completely silent fallback
                pass


    def _get_request_text_from_selected(self):
        # Compatibility reader: only the already-loaded viewer snapshot is read.
        request = self.controller.getRequest()
        return self.helpers.bytesToString(request) if request is not None else ""

    def _load_template_from_viewer(self,event=None):
        def loaded(message):
            self.reqTemplateEditor.setMessage(message.getRequest(),True)
            self.tabbed.setSelectedIndex(1)
            self.set_status("Loaded request into Request Template")
        self._request_selected_message(loaded)

    def _clear_req_template(self, event=None):
        try:
            if hasattr(self, "reqTemplateEditor"):
                try:
                    self.reqTemplateEditor.setMessage(None, True)
                except:
                    # fall back to setting empty bytes
                    try:
                        self.reqTemplateEditor.setMessage(self.helpers.stringToBytes(""), True)
                    except:
                        pass
            self.set_status("Request Template cleared")
        except:
            pass

    def _load_check_from_viewer(self,event=None):
        def loaded(message):
            self.checkPageEditor.setMessage(message.getRequest(),True)
            self.tabbed.setSelectedIndex(2)
            self.set_status("Loaded request into CheckPageTemplate")
        self._request_selected_message(loaded)

    def _clear_check_template(self, event=None):
        try:
            if hasattr(self, "checkPageEditor"):
                try:
                    self.checkPageEditor.setMessage(None, True)
                except:
                    try:
                        self.checkPageEditor.setMessage(self.helpers.stringToBytes(""), True)
                    except:
                        pass
            self.set_status("CheckPageTemplate cleared")
        except:
            pass


    def _set_right_controls_enabled(self, enabled):
        try:
            vp = self.rightScroll.getViewport().getView()
            for comp in vp.getComponents():
                pass
        except:
            pass
        for w in [self.sizeField, self.compCombo, self.lenTypeCombo, self.regexField,
                  self.addSitemapBtn, self.clearBtn, self.clearSelBtn, self.pauseBtn]:
            try:
                w.setEnabled(enabled)
            except:
                pass


    def getTabCaption(self): return "BoberProxy"
    def getUiComponent(self): return self._component

    # helpers

    # --- Filter storage / apply helpers ---------------------------------
    # structure:
    # self.display_filters = {
    #   "Host": {"active": False, "mode": "eq"/"not eq", "values": ["a","b"]},
    #   "Method": {...},
    #   ...
    # }
    def _init_filter_runtime(self):
        self._capture_filter_plan = CaptureFilterPlan({})
        self._display_filter_plan = DisplayFilterPlan({})
        self._filter_worker = FilterWorker()
        self._capture_signature = None
        self._capture_error = self._display_error = None
        self._capture_serial = self._display_serial = 0
        self._filter_generation = self._log_generation = 0
        self._filter_store_epoch = 0
        self._rebuild_serial = self._filter_rebuilding = 0
        self._filter_dirty = False
        self._filter_rejected = 0
        self._filter_timer = None
        self._filter_dialog = None
        self._log_archive = LogArchive()
        self._log_writer = FilterWorker()
        self._log_writer.gate_name = "BoberProxy.logwrite.v1"
        self._log_budget = RawLogBudget()
        self._log_writer.budget = self._filter_worker.budget = self._log_budget
        self._log_io = LogIoWorker(self._log_archive)
        self._log_error, self._log_not_accepted = None, 0
        self._viewer_serial, self._viewer_entry = 0, None

    def _filter_message(self):
        errors = [s for s in (self._capture_error, self._display_error) if s]
        state = self._filter_worker.state()
        if errors:
            message = "Filter error: " + "; ".join(errors)
        elif self._filter_rebuilding or state["active"] or state["controls"]:
            message = "Filtering... (%d queued; %d ms running)" % (state["rows"], state["running_ms"])
        else:
            message = "Filters ready"
        if errors and (self._filter_rebuilding or state["active"] or state["controls"]):
            message += " | Filtering... (%d ms running)" % state["running_ms"]
        if self._filter_rejected:
            message += " | %d log responses not accepted (FILTER_BUSY/ERROR)" % self._filter_rejected
        if self._log_error:
            message += " | " + self._log_error
        if self._log_not_accepted:
            message += " | %d log responses not accepted" % self._log_not_accepted
        if self._log_archive.cleanup_error:
            message += " | " + self._log_archive.cleanup_error
        label = getattr(self, "filterStatusLabel", None)
        if label is not None and label.getText() != message:
            label.setText(message)

    def _observe_capture_filter(self, values):
        keys = ("statuses","size","len_type","size_comp","log_regex")
        values = dict((key,values.get(key)) for key in keys)
        signature = tuple(values.get(key) for key in keys)
        if signature == self._capture_signature:
            return
        self._capture_serial += 1
        serial = self._capture_serial
        def apply(result, error):
            if self._custom_ui_closed or serial != self._capture_serial:
                return
            if error is not None:
                self._capture_error = "Previous capture filter retained: " + _filter_diagnostic(error)
            else:
                self._capture_filter_plan = result
                self._capture_error = None
                self._publish_runtime()
        known_size = not values.get("size") or values.get("size") == self._capture_filter_plan.size_text
        known_pattern = not values.get("log_regex") or values.get("log_regex") == self._capture_filter_plan.pattern_text
        if known_size and known_pattern:
            self._capture_signature = signature
            self._capture_filter_plan = CaptureFilterPlan(values,self._capture_filter_plan)
            self._capture_error = None
        elif self._filter_worker.submit(lambda previous=self._capture_filter_plan: CaptureFilterPlan(values,previous), apply, "capture"):
            self._capture_signature = signature
        else:
            self._capture_error = "FILTER_BUSY: previous regex worker still occupied"

    def _apply_display_filters(self, candidate, dialog=None):
        if self._custom_ui_closed or dialog is not None and dialog.closed:
            return
        import copy
        candidate = copy.deepcopy(candidate)
        self._display_serial += 1
        serial = self._display_serial
        if candidate == self.display_filters:
            self._display_error = None
            if dialog is not None:
                dialog._on_cancel()
            self._refresh_table_display()
            return
        def apply(plan, error):
            if self._custom_ui_closed or serial != self._display_serial:
                return
            if dialog is not None and (dialog.closed or dialog.candidate() != candidate):
                if not dialog.closed:
                    dialog.errorLabel.setText("Settings changed; press Apply again.")
                return
            if error is not None:
                message = "Previous display filter retained: " + _filter_diagnostic(error)
                self._display_error = message
                if dialog is not None:
                    dialog.errorLabel.setText("Filter error: " + message)
                return
            self._display_error = None
            self._filter_generation += 1
            plan.version = self._filter_generation
            self.display_filters = candidate
            self._display_filter_plan = plan
            self._publish_runtime()
            if dialog is not None:
                dialog._on_cancel()
            self._refresh_table_display()
        if not any(cfg.get("active") for cfg in candidate.values()):
            apply(DisplayFilterPlan(candidate), None)
        elif not self._filter_worker.submit(lambda previous=self._display_filter_plan: DisplayFilterPlan(candidate,previous), apply, "display"):
            apply(None, FilterInputError("Filter", "FILTER_BUSY: previous regex worker still occupied"))
        elif dialog is not None:
            dialog.errorLabel.setText("Validating filters...")

    def _filter_tick(self):
        if self._custom_ui_closed:
            return
        end = _monotonic_ms() + 6
        model = getattr(self,"logTableModel",None)
        if model is not None: model.begin_batch()
        for unused in range(100):
            workers = (self._log_writer,self._filter_worker) if unused % 2 == 0 else (self._filter_worker,self._log_writer)
            job = workers[0].poll() or workers[1].poll()
            if job is None:
                break
            try:
                job.apply(job.result, job.error)
            except (Exception, JavaThrowable) as error:
                self._display_error = "Filter result error: " + _filter_diagnostic(error)
            if _monotonic_ms() >= end:
                break
        if model is not None: model.end_batch()
        for unused in range(2):
            item = self._log_io.poll()
            if item is None: break
            apply,value,error = item
            apply(value,error)
        if self._filter_dirty and not self._filter_rebuilding:
            self._refresh_table_display()
        if self._log_error and hasattr(self,"pauseBtn") and not self.pauseBtn.isSelected():
            self.paused = True
            self.pauseBtn.setSelected(True)
            self._publish_runtime()
        self._filter_message()

    def _set_display_rows(self, entries):
        table = getattr(self,"table",None)
        selected = set()
        if table is not None:
            for row in table.getSelectedRows():
                try: selected.add(self.logTableModel.displayed[table.convertRowIndexToModel(row)])
                except (IndexError,Exception): pass
        self._suspend_selection_events = True
        try:
            self.logTableModel.displayed = entries
            self.logTableModel.fireTableDataChanged()
            if table is not None and hasattr(table,"clearSelection"):
                table.clearSelection()
                for row,entry in enumerate(self.logTableModel.displayed):
                    if entry in selected:
                        view = table.convertRowIndexToView(row)
                        if view >= 0: table.addRowSelectionInterval(view,view)
        finally: self._suspend_selection_events = False
        if table is not None and hasattr(self,"controller"): self._request_selected_message()

    def _refresh_table_display(self):
        if self._custom_ui_closed:
            return
        plan, epoch = self._display_filter_plan, (self._log_generation,self._filter_store_epoch)
        if not plan.fields:
            self._filter_dirty = False
            self._filter_rebuilding = 0
            self._set_display_rows(self.logStore.entries)
            return
        entries = tuple(self.logStore.entries)
        newest = entries[0].index if entries else 0
        self._rebuild_serial += 1
        serial = self._rebuild_serial
        def match():
            return [entry for entry in entries if plan.matches(entry, self.helpers)]
        def apply(matches, error):
            if serial == self._filter_rebuilding:
                self._filter_rebuilding = 0
            if self._custom_ui_closed or epoch != (self._log_generation,self._filter_store_epoch) or plan is not self._display_filter_plan:
                return
            if error is not None:
                self._filter_dirty = False
                self._display_error = "Search failed: " + _filter_diagnostic(error)
                return
            additions = []
            for entry in self.logStore.entries:
                if entry.index <= newest:
                    break
                if getattr(entry,"_filter_version",None) != plan.version:
                    self._filter_dirty = True
                    return  # Rebuild from a fresh snapshot; never lose a new row.
                if entry._filter_match:
                    additions.append(entry)
            self._set_display_rows(additions + matches)
        if self._filter_worker.submit(match, apply, "rebuild"):
            self._filter_dirty, self._filter_rebuilding = False, serial
        else:
            self._display_error = "FILTER_BUSY: previous regex worker still occupied"

    def _reject_log(self,message=None,capture=False):
        # Jython has no GIL: rejection accounting must be a single transaction.
        with self._log_budget.lock:
            if message is not None: self._log_error = message
            self._log_not_accepted += 1
            if capture: self._filter_rejected += 1

    def _queue_filter_log(self, data, config, log_generation=None):
        if self._custom_ui_closed or config.get("paused"):
            return
        epoch = self._log_generation if log_generation is None else log_generation
        if epoch != self._log_generation:
            return
        capture = config.get("capture_filter_plan") or self._capture_filter_plan
        display = config.get("display_filter_plan") or self._display_filter_plan
        tool,host,method,path,status,length,info,is_request,body_len = data
        if not capture.accepts(status,length,body_len,None,self.helpers,search=False):
            return
        if self._log_error:
            self._reject_log()
            return
        response = info.getResponse()
        request = info.getRequest() if hasattr(info,"getRequest") else None
        cost = len(response) + (len(request) if request is not None else 0)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())
        archive_epoch = self._log_archive.epoch
        def fail(message):
            self._reject_log(message)
        def prepare():
            snapshot = FrozenLogMessage(self.helpers,info,request,response)
            def evaluate():
                if self._custom_ui_closed or epoch != self._log_generation:
                    return None
                if self._log_error:
                    self._reject_log()
                    return None
                raw = snapshot.getResponse()
                if not capture.accepts(status,length,body_len,raw,self.helpers):
                    return None
                entry = LogEntry(0,timestamp,host,method,path,status,length,body_len,snapshot)
                failure, visible = None, None
                try:
                    if not display.has_regex: visible = display.matches(entry,self.helpers)
                except (Exception, JavaThrowable) as error:
                    failure = _filter_diagnostic(error)
                try:
                    stored = self._log_archive.put(snapshot,archive_epoch)
                    return stored,visible,failure
                except (Exception, JavaThrowable) as error:
                    if epoch == self._log_generation and not self._custom_ui_closed:
                        fail("STORAGE_WRITE_FAILED: new log admission paused")
                    raise
            return evaluate
        def apply(result,error):
            if self._custom_ui_closed or epoch != self._log_generation:
                return
            if error is not None:
                if not self._log_error: fail("LOG_PROCESSING_FAILED: new log admission paused")
                return
            if result is None: return
            stored,visible,failure = result
            if failure: self._display_error = "Search failed: " + failure
            self.append_log_row(tool,host,method,path,status,length,stored,is_request,config,
                                filter_result=(display,visible),log_generation=epoch,
                                provided_body_len=body_len,capture_timestamp=timestamp)
        try:
            worker = self._filter_worker if capture.pattern is not None else self._log_writer
            if not self._log_io.start() or not worker.submit_log(prepare,apply,cost):
                self._reject_log("LOG_BUSY: new log admission paused (128 jobs / 32 MiB limit)",capture.pattern is not None)
        except (Exception, JavaThrowable):
            fail("LOG_SNAPSHOT_FAILED: new log admission paused")


    def _init_display_filters(self):
        # default fields (extended)
        try:
            self.display_filters = {
                "Host": {"active": False, "mode": "eq", "values": []},
                "Method": {"active": False, "mode": "eq", "values": []},
                "Path": {"active": False, "mode": "eq", "values": []},
                "Status": {"active": False, "mode": "eq", "values": []},
                "BodyLen": {"active": False, "mode": "eq", "values": []},            # new: numeric list
                "ResponseContent": {"active": False, "mode": "eq", "values": []},    # new: regex values
            }
        except:
            self.display_filters = {}


    def _row_matches_filters(self, entry, filters=None):
        # Compatibility reader for explicit model callers. Production passes a
        # compiled plan and runs response regexes only on the filter worker.
        if isinstance(filters, DisplayFilterPlan):
            plan = filters
        else:
            config = self.display_filters if filters is None else filters
            if config == getattr(self, "_row_filter_config", None):
                plan = self._row_filter_plan
            else:
                import copy
                plan = DisplayFilterPlan(config)
                self._row_filter_config = copy.deepcopy(config)
                self._row_filter_plan = plan
        return plan.matches(entry,self.helpers)

    def set_status(self, txt):
        def publish():
            if self._custom_ui_closed:
                return
            label = getattr(self, "statusLabel", None)
            if label is not None:
                label.setText(txt)
        if swing.SwingUtilities.isEventDispatchThread():
            publish()
        else:
            swing.SwingUtilities.invokeLater(publish)

    def clear_log(self, evt=None):
        try:
            self._log_generation += 1
            self._log_archive.clear()
            self._filter_store_epoch += 1
            self._filter_dirty = False
            self._filter_rebuilding = 0
            self.logStore.clear()
            self.logTableModel.clear()
            if hasattr(self,"controller"): self._clear_log_viewer()
            self._log("Log cleared OK!")
        except Exception as e:
            try:
                self._log("Log cleared ERROR: %s\n" % str(e))
            except:
                pass

        
    def clear_selected(self, evt=None):
        try:
            view_rows = self.table.getSelectedRows()
            if not view_rows:
                swing.JOptionPane.showMessageDialog(None, "No rows selected.")
                return

            # view -> model index
            model_rows = sorted(
                [self.table.convertRowIndexToModel(v) for v in view_rows],
                reverse=True
            )

            removed_entries = set(self.logTableModel.displayed[r] for r in model_rows)
            removed = len(removed_entries)
            self.logStore.entries = [entry for entry in self.logStore.entries if entry not in removed_entries]
            self._suspend_selection_events = True
            try:
                if hasattr(self.table,"clearSelection"): self.table.clearSelection()
            finally: self._suspend_selection_events = False

            self._filter_store_epoch += 1
            self.logTableModel.displayed = [e for e in self.logTableModel.displayed if e not in removed_entries]
            for entry in removed_entries:
                if isinstance(entry.messageInfo,StoredLogMessage): self._log_archive.release(entry.messageInfo)
            if getattr(self,"_viewer_entry",None) in removed_entries: self._clear_log_viewer()
            self.logTableModel.fireTableDataChanged()
            self._refresh_table_display()

            self._log("Cleared %d selected" % removed)

        except Exception as e:
            try:
                self._log("clear_selected error: %s\n" % str(e))
            except:
                pass


    def toggle_pause(self, evt=None):
        self.paused = bool(self.pauseBtn.isSelected())
        if not self.paused:
            with self._log_budget.lock: self._log_error = None
        self.set_status("Paused" if self.paused else "Running")


    def reset_sorting_to_model_order(self):
        """Reset JTable sorter to the model's natural order (disable sorting)."""
        try:
            sorter = self.table.getRowSorter()
            if sorter:
                sorter.setSortKeys(None)
        except Exception as e:
            try:
                self.customStatusArea.append("reset_sorting_to_model_order error: %s\n" % str(e))
            except:
                pass

    def sort_by_index_asc(self):
        """Sort JTable by '#' column (index ascending)."""
        try:
            sorter = self.table.getRowSorter()
            if sorter:
                sorter.setSortKeys([RowSorter.SortKey(0, SortOrder.ASCENDING)])
        except Exception as e:
            try:
                self._log("sort_by_index_asc ERROR: %s\n" % str(e))
            except:
                pass


    def _clear_log_viewer(self):
        self._viewer_serial += 1
        self._viewer_entry = None
        self.controller.setMessageInfo(None)
        self.reqViewer.setMessage(self.helpers.stringToBytes(""),True)
        self.respViewer.setMessage(self.helpers.stringToBytes(""),False)

    def _request_selected_message(self, on_loaded=None):
        if self._custom_ui_closed or self._suspend_selection_events: return
        row = self.table.getSelectedRow()
        if row < 0:
            self._clear_log_viewer()
            return
        entry = self.logTableModel.displayed[self.table.convertRowIndexToModel(row)]
        if on_loaded is None and entry is self._viewer_entry: return
        self._clear_log_viewer()
        self._viewer_entry = entry
        serial,epoch = self._viewer_serial,self._log_generation
        def read():
            message = entry.messageInfo
            return message.snapshot(self.helpers) if isinstance(message,StoredLogMessage) else message
        def apply(message,error):
            if self._custom_ui_closed or serial != self._viewer_serial or epoch != self._log_generation: return
            if error is not None:
                self._viewer_entry = None
                self.set_status("STORAGE_READ_FAILED: selected message could not be loaded")
                return
            self.controller.setMessageInfo(message)
            self.reqViewer.setMessage(message.getRequest() or self.helpers.stringToBytes(""),True)
            self.respViewer.setMessage(message.getResponse() or self.helpers.stringToBytes(""),False)
            if on_loaded is not None: on_loaded(message)
        if not self._log_io.submit("viewer",read,apply):
            self._viewer_entry = None
            self.set_status("STORAGE_BUSY: viewer load not started")

    def on_table_select(self,event):
        if event is not None and event.getValueIsAdjusting(): return
        self._request_selected_message()

    def add_selected_to_sitemap(self,event=None):
        rows = self.table.getSelectedRows()
        if not rows:
            swing.JOptionPane.showMessageDialog(None,"No rows selected.")
            return
        entries = tuple(self.logTableModel.displayed[self.table.convertRowIndexToModel(row)] for row in rows)
        epoch = self._log_generation
        def export():
            count,failed = 0,False
            for entry in entries:
                if self._custom_ui_closed or epoch != self._log_generation: break
                try:
                    msg = entry.messageInfo
                    if isinstance(msg,StoredLogMessage): msg = msg.snapshot(self.helpers)
                    self.callbacks_ref.addToSiteMap(msg)
                    count += 1
                    url = self.helpers.analyzeRequest(msg).getUrl()
                    if url: self.callbacks_ref.includeInScope(url)
                except (Exception, JavaThrowable):
                    failed = True
                    break
            return count,failed
        def apply(result,error):
            if self._custom_ui_closed: return
            if error is not None: self._log("STORAGE_EXPORT_FAILED")
            else: self._log("Added %d selected to Site map%s" % (result[0],"; STORAGE_EXPORT_FAILED" if result[1] else ""))
        if not self._log_io.submit("export",export,apply): self.set_status("STORAGE_BUSY: Site map export not started")

    # append_log_row (filter-aware)
    # append_log_row (LogStore-alapú, de UI-kompatibilis)
    def append_log_row(self, toolFlag, host, method, path,
                    status, total_length, messageInfo, isRequest, runtime_config=None,
                    filter_result=None, log_generation=None, provided_body_len=None, capture_timestamp=None):

        if self._custom_ui_closed:
            return
        if log_generation is not None and log_generation != self._log_generation:
            return
        config = runtime_config or self._capture_runtime()
        if config.get("paused"):
            return

        ts = capture_timestamp or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        body_len = provided_body_len if provided_body_len is not None else ""
        try:
            if provided_body_len is None and not isRequest and messageInfo.getResponse():
                ar = self.helpers.analyzeResponse(messageInfo.getResponse())
                body_len = len(messageInfo.getResponse()) - ar.getBodyOffset()
        except:
            pass

        entry = self.logStore.add(
            ts, host, method, path,
            status or "",
            total_length or "",
            body_len,
            messageInfo
        )

        plan, show = filter_result if filter_result is not None else (self._display_filter_plan, None)
        if plan is not self._display_filter_plan:
            show = None
        if show is None and not self._display_filter_plan.has_regex:
            plan = self._display_filter_plan
            show = plan.matches(entry,self.helpers)
        entry._filter_version = plan.version if show is not None else None
        entry._filter_match = bool(show)
        if show is None:
            self._filter_dirty = True
        self.logTableModel.add_entry_top(entry, show)

        try:
            self.set_status("Logged: %s" % path)
        except:
            pass



    def should_log(self, toolFlag, messageIsRequest, messageInfo, runtime_config=None):
        config = runtime_config or self._capture_runtime()
        if config.get("paused") or messageIsRequest:
            return False
        response = messageInfo.getResponse()
        if response is None:
            return False
        status, body_len = None, len(response)
        try:
            analyzed = self.helpers.analyzeResponse(response)
            status = analyzed.getStatusCode()
            body_len = len(response)-analyzed.getBodyOffset()
        except (Exception, JavaException):
            pass
        plan = config.get("capture_filter_plan")
        if plan is None:
            plan = CaptureFilterPlan(config._values)  # Explicit compatibility callers.
        return plan.accepts(status,len(response),body_len,response,self.helpers)


    # COOKIE and CSRF HELPERS
    def _on_clear_cookies(self, evt=None):
        try:
            self.sessions.clear("cookies")
            self.customStatusArea.setText("Cookies cleared.")
        except Exception as e:
            try:
                self.customStatusArea.setText("Error clearing cookies: %s" % e)
            except:
                pass

    def _on_show_cookies(self, evt=None):
        try:
            txt = self.cookieManager.dump()
            # put into customStatusArea so user sees current jar
            self.customStatusArea.setText("Current cookies:\n%s" % txt)
        except Exception as e:
            try:
                self.customStatusArea.setText("Error showing cookies: %s" % e)
            except:
                pass

    def _on_clear_csrf(self, evt=None):
        try:
            self.sessions.clear("csrf")
            self.customStatusArea.setText("CSRF_token cleared")
        except Exception as e:
            try:
                self.customStatusArea.setText("Error clearing CSRF: %s" % e)
            except:
                pass

    def _on_show_csrf(self, evt=None):
        try:
            txt = self.csrfManager.dump()
            # put into customStatusArea so user sees current jar
            self.customStatusArea.setText("CSRF_token:\n%s" % txt)
        except Exception as e:
            try:
                self.customStatusArea.setText("Error showing CSRF: %s" % e)
            except:
                pass

    def _on_csrf_regex_changed(self):
        # Invoked by Swing document events on the UI thread.
        self.csrfManager.set_pattern(self.csrfRegexArea.getText())
        status, detail = self.csrfManager.get_status()
        message = "CSRF %s" % status
        if detail:
            message += ": " + detail
        if hasattr(self, "customStatusArea"):
            self.customStatusArea.setText(message)

    def _on_reset_csrf_regex(self, evt=None):
        try:
            self.csrfRegexArea.setText(self.csrf_default_pattern)
            self.customStatusArea.setText("CSRF regex reset to default.")
        except Exception as e:
            try:
                self.customStatusArea.setText("Error resetting CSRF regex: %s" % e)
            except:
                pass


    # ---------------------------
    # Custom codeblock helpers
    # ---------------------------
    def _on_toggle_custom(self, evt=None):
        self.custom_codeblock_status = bool(self.useCustomChk.isSelected())
        self._on_custom_settings_changed()
        for w in [self.customCodeArea, self.testCodeBtn, self.resetBtn, self.timeoutField]:
            try:
                w.setEnabled(self.custom_codeblock_status)
            except:
                pass
        # show brief status
        try:
            if self.custom_codeblock_status:
                self._log("Custom codeblock enabled")
            else:
                self._log("")
        except:
            pass

    def _init_custom_runtime(self):
        self._custom_executor = CustomExecutor(self.helpers)
        self._custom_settings_lock = threading.Lock()
        self._custom_context = threading.local()
        self._custom_settings = None
        self._custom_version = 0
        self._custom_ui_closed = False
        self._custom_test_timer = None

    def _on_custom_settings_changed(self):
        # Document/action listeners run on the EDT; callbacks use this snapshot.
        code = self.customCodeArea.getText()
        timeout = self.timeoutField.getText()
        enabled = self.custom_codeblock_status
        with self._custom_settings_lock:
            self._custom_version += 1
            self._custom_settings = (enabled, code, timeout, self._custom_version)

    def _capture_custom_settings(self):
        with self._custom_settings_lock:
            snapshot = self._custom_settings
        if snapshot is not None:
            return snapshot
        # Isolated source harnesses bypass __init__ and use plain field doubles.
        return (self.custom_codeblock_status,
                self.customCodeArea.getText() if hasattr(self, "customCodeArea") else "",
                self.timeoutField.getText(), 0)

    def _on_test_code(self, evt=None):
        if self._custom_ui_closed:
            return
        if self._custom_test_timer is not None:
            self.customStatusArea.setText("CUSTOM_BUSY: a Test is already pending")
            return
        snapshot = self._capture_custom_settings()
        code = snapshot[1] if snapshot[0] else getattr(self, "default_code_text", "")
        job = self._custom_executor.submit(code, snapshot[2],
                                           ("TestPayload1", "TestPayload2", "TestCSRF_Token"))
        self.testCodeBtn.setEnabled(False)
        self.customStatusArea.setText("Custom test running...")

        def finish(event):
            result = self._custom_executor.poll(job)
            if not self._custom_ui_closed and result is None:
                return
            timer = self._custom_test_timer
            if timer is not None:
                timer.stop()
            self._custom_test_timer = None
            if self._custom_ui_closed:
                return
            self.testCodeBtn.setEnabled(bool(self.custom_codeblock_status))
            if self._capture_custom_settings() != snapshot:
                self.customStatusArea.setText("Custom test result discarded: settings changed.")
                return
            ok, out, error = result
            if ok:
                self.customStatusArea.setText("Test OK!\nOutput:\npayload1=%s\npayload2=%s\ncsrf_token=%s" % out)
            else:
                self.customStatusArea.setText("Error:\n%s" % error)

        self._custom_test_timer = swing.Timer(20, finish)
        self._custom_test_timer.start()

    def close_custom_runtime(self):
        self._custom_ui_closed = True
        self._custom_executor.close()
        self.sessions.close()
        if hasattr(self, "_filter_worker"):
            self._filter_worker.close()
        self._log_writer.close()
        self._log_io.close()
        def close_timer():
            if getattr(self, "_filter_dialog", None) is not None:
                self._filter_dialog._on_cancel()
            if getattr(self, "_filter_timer", None) is not None:
                self._filter_timer.stop()
                self._filter_timer = None
            if self._runtime_publisher is not None:
                self._runtime_publisher.close()
            if self._custom_test_timer is not None:
                self._custom_test_timer.stop()
                self._custom_test_timer = None
            try:
                if hasattr(self,"controller") and hasattr(self,"reqViewer"):
                    self._clear_log_viewer()
            finally:
                if hasattr(self,"logStore"): self.logStore.clear()
                if hasattr(self,"logTableModel"): self.logTableModel.clear()
        swing.SwingUtilities.invokeLater(close_timer)

    def _reset_custom_code(self, event=None):
        # Reset the user code area to a simple backward-compatible template.
        # English comments inside code are required — keep them short.
        try:
            default_code_text = getattr(self, "default_code_text", "")
            self.customCodeArea.setText(default_code_text)
        except:
            pass



    def run_user_code(self, incoming_payload1, timeout_ms=500, incoming_payload2=None, incoming_csrf=None):
        """Frozen source; compile/exec/call/validation all use one bounded worker."""
        snapshot = getattr(self._custom_context, "snapshot", None)
        if snapshot is None:
            snapshot = self._capture_custom_settings()
        code = snapshot[1] if snapshot[0] else getattr(self, "default_code_text", "")
        job = self._custom_executor.submit(code, timeout_ms,
                                           (incoming_payload1, incoming_payload2, incoming_csrf))
        return self._custom_executor.wait(job)

    def extract_param_from_request(self, messageInfo, param_name):
        """
        Tries to extract parameter by name from the request's parameters.
        If not found, falls back to returning request body as string.
        """
        try:
            if not param_name:
                return ""
            try:
                analyzedReq = self.helpers.analyzeRequest(messageInfo)
            except:
                analyzedReq = None
            if analyzedReq:
                try:
                    params = analyzedReq.getParameters()
                    for p in params:
                        try:
                            if p.getName() == param_name:
                                try:
                                    return p.getValue()
                                except:
                                    return ""
                        except:
                            pass
                except:
                    pass
        except:
            pass
        return ""


    def _update_cookies_and_csrf(self, response_bytes):
        if response_bytes is None:
            return
        context = getattr(self._flow_local, "context", None)
        if context is None:
            context, error = self.sessions.register(None, self._runtime_for_flow(), False)
            if error:
                return
        status, detail = self.sessions.update(context, response_bytes)
        if status in ("REGEX_INVALID", "REGEX_NO_CAPTURE", "DECODE_ERROR"):
            self._log("CSRF %s: %s" % (status, detail or ""))

    def _send_http_request(self, host, port, https, request_bytes):
        context = getattr(self._flow_local, "context", None)
        if context is not None and not self.sessions.valid(context):
            return HttpSendResult(error_code="SESSION_CLEARED")
        if self._http_sender is None:
            self._http_sender = HttpRequestSender(self.callbacks, self.helpers)
        result = self._http_sender.send(host, port, https, request_bytes)
        if context is not None:
            context.any_sent = context.any_sent or result.attempted
        return result

    def _template_preflight_error(self, template_bytes):
        if template_bytes is None or len(template_bytes) == 0:
            return "EMPTY"
        try:
            text = self.helpers.bytesToString(template_bytes)
            first_line = text.split("\n", 1)[0].rstrip("\r")
            parts = first_line.split()
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                return "INVALID"
        except (Exception, JavaException):
            return "INVALID"
        return None

    def _follow_redirects_chain(self, initial_request_bytes, initial_response_bytes,
                                initial_target_host, initial_target_port, initial_https,
                                max_redirects=10, deadline_ms=None):
        previous = getattr(self._flow_local, "config", None)
        previous_context = getattr(self._flow_local, "context", None)
        if previous is None:
            self._flow_local.config = self._capture_runtime()
        if previous_context is None:
            # Standalone callers also freeze the epoch and local stores for the
            # entire chain. Production workflows already own a managed context.
            with self.sessions.condition:
                context = SessionContext(None, self._flow_local.config, self.sessions.epoch, False)
                context.cookies = _session_cookie_copy(self.cookieManager)
                context.csrf = _session_csrf_copy(self.csrfManager, context.pattern_state)
            self._flow_local.context = context
        try:
            return self._follow_redirects_frozen(initial_request_bytes, initial_response_bytes,
                initial_target_host, initial_target_port, initial_https, max_redirects, deadline_ms)
        finally:
            self._flow_local.config = previous
            self._flow_local.context = previous_context

    def _follow_redirects_frozen(self, initial_request_bytes, initial_response_bytes,
                                initial_target_host, initial_target_port, initial_https,
                                max_redirects=10, deadline_ms=None):
        """Follow minimal GET redirects with one shared scheduling deadline.

        Every received response is updated once, including the last allowed
        hop. This cannot interrupt an already-blocking synchronous Burp call.
        """
        config = self._runtime_for_flow()
        cookie_manager, csrf_manager = self._flow_managers()
        current_request = initial_request_bytes
        current_response = initial_response_bytes
        host, port, https = initial_target_host, int(initial_target_port), bool(initial_https)
        hops = 0
        if deadline_ms is None:
            deadline_ms = _monotonic_ms() + WORKFLOW_TIMEOUT_MS
        visited = set()
        try:
            while True:
                # A received response is real state even if time/limit is now up.
                self._update_cookies_and_csrf(current_response)
                context = getattr(self._flow_local, "context", None)
                if context is not None and not self.sessions.valid(context):
                    return RedirectResult(current_response, hops, "SESSION_CLEARED")
                if _monotonic_ms() >= deadline_ms:
                    return RedirectResult(current_response, hops, "WORKFLOW_TIMEOUT")
                response = self.helpers.analyzeResponse(current_response)
                status = int(response.getStatusCode())
                location = None
                for header in response.getHeaders():
                    text = _wire_text(header)
                    if text.lower().startswith("location:"):
                        location = text.split(":", 1)[1].strip()
                        break
                if not (300 <= status < 400) or not location:
                    return RedirectResult(current_response, hops)
                if hops >= int(max_redirects):
                    return RedirectResult(current_response, hops, "REDIRECT_LIMIT")

                request_text = _wire_text(current_request, self.helpers)
                base, method = _redirect_base(request_text, host, port, https)
                current_url = urlparse(base)
                current_target = (current_url.path or "/") + (";" + current_url.params if current_url.params else "")
                if current_url.query:
                    current_target += "?" + current_url.query
                visited.add((method, bool(https), host.lower().strip("[]"), int(port), current_target))
                try:
                    new_host, new_port, new_https, target = _redirect_destination(base, location)
                except (Exception, JavaException) as error:
                    return RedirectResult(current_response, hops, "REDIRECT_INVALID_LOCATION", type(error).__name__)
                key = ("GET", new_https, new_host.lower().strip("[]"), new_port, target)
                if key in visited:
                    return RedirectResult(current_response, hops, "REDIRECT_LOOP")

                headers = ["GET %s HTTP/1.1" % target,
                           "Host: " + _redirect_host_header(new_host, new_port, new_https),
                           "Connection: close"]
                # Preserve the established minimal-GET policy, including 307/308:
                # only User-Agent and managed cookies carry over; no body/auth.
                for header in self.helpers.analyzeRequest(current_request).getHeaders():
                    text = _wire_text(header)
                    if text.lower().startswith("user-agent:"):
                        headers.append(text)
                        break
                new_request = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(""))
                if config.get("cookies"):
                    text = _wire_text(new_request, self.helpers)
                    injected = cookie_manager.inject_into_request(text)
                    new_request = self.helpers.stringToBytes(_wire_text(injected))
                if _monotonic_ms() >= deadline_ms:
                    return RedirectResult(current_response, hops, "WORKFLOW_TIMEOUT")
                sent = self._send_http_request(new_host, new_port, new_https, new_request)
                if sent.attempted:
                    hops += 1
                    visited.add(key)
                if sent.error_code:
                    return RedirectResult(current_response, hops, sent.error_code, sent.error_type)
                current_request, current_response = new_request, sent.response_bytes
                host, port, https = new_host, new_port, new_https
        except (Exception, JavaException) as error:
            return RedirectResult(current_response, hops, "REDIRECT_FAILED", type(error).__name__)


    def build_request_from_template(
        self,
        get_editor_message=None,
        helpers=None,
        cookie_manager=None,
        csrf_manager=None,
        auto_update_cookies=False,
        auto_update_csrf=False,
        normalize_func=None,
        custom_status_setter=None,
        incoming_payload1="",
        incoming_payload2="",
        fallback_resp=None,
        custom_settings=None
    ):
        """Return complete request bytes, or fallback_resp with TRANSFORM_ERROR.

        Only markers in the original template are substituted. The public
        bytes-or-fallback contract is retained for the workflow's send states.
        """
        try:
            template = get_editor_message() if callable(get_editor_message) else None
            if template is None or len(template) == 0:
                raise TemplateBuildError("TEMPLATE_EMPTY", "No Request Template configured")
            template_text = _wire_text(template, helpers)
            csrf_token = csrf_manager.get_token() if csrf_manager is not None else None
            outgoing_payload1, outgoing_payload2 = incoming_payload1, incoming_payload2

            snapshot = custom_settings if custom_settings is not None else self._capture_custom_settings()
            if snapshot[0] and (incoming_payload1 or incoming_payload2):
                previous = getattr(self._custom_context, "snapshot", None)
                self._custom_context.snapshot = snapshot
                try:
                    ok, out, err = self.run_user_code(incoming_payload1, snapshot[2], incoming_payload2, csrf_token)
                finally:
                    self._custom_context.snapshot = previous
                if not ok:
                    raise TemplateBuildError("CUSTOM_FAILED", err if err is not None else "Unknown custom error")
                if not isinstance(out, (list, tuple)) or len(out) != 3:
                    raise TemplateBuildError("CUSTOM_INVALID_RESULT", "custom_codeblock must return exactly 3 values")
                outgoing_payload1, outgoing_payload2, csrf_token = out

            try:
                values = {
                    TEMPLATE_PAYLOAD_MARKER_1: _custom_value(outgoing_payload1, helpers),
                    TEMPLATE_PAYLOAD_MARKER_2: _custom_value(outgoing_payload2, helpers),
                }
                if csrf_token is not None:
                    csrf_token = _custom_value(csrf_token, helpers)
                if auto_update_csrf and csrf_token is not None:
                    values[TEMPLATE_CSRF_MARKER] = csrf_token
            except (TypeError, ValueError, UnicodeError) as error:
                raise TemplateBuildError("CUSTOM_VALUE_TYPE", str(error))

            # A callback replacement treats backslashes literally and never scans
            # inserted payloads, token values or injected cookie values again.
            marker_pattern = "|".join(re.escape(marker) for marker in values)
            final_request_text = re.sub(marker_pattern, lambda match: values[match.group(0)], template_text)
            if auto_update_cookies and cookie_manager is not None:
                injected = cookie_manager.inject_into_request(final_request_text)
                if injected is not None:
                    final_request_text = _wire_text(injected)
            if callable(normalize_func):
                final_request_text = _wire_text(normalize_func(final_request_text))

            # Burp's conversion is byte-valued, not an implicit charset encoder.
            request_bytes = (helpers.stringToBytes(final_request_text) if helpers is not None
                             else final_request_text.encode("latin-1"))
            if helpers is not None:
                parsed = helpers.analyzeRequest(request_bytes)
                if parsed is None:
                    raise TemplateBuildError("REQUEST_PARSE_FAILED", "No request analysis result")
                headers = list(parsed.getHeaders())
                body_offset = parsed.getBodyOffset()
                if body_offset <= 0 or body_offset > len(request_bytes):
                    raise TemplateBuildError("REQUEST_PARSE_FAILED", "Invalid request body offset")
                body_bytes = request_bytes[body_offset:]
            else:
                wire = _wire_text(request_bytes)
                if "\r\n\r\n" not in wire:
                    raise TemplateBuildError("REQUEST_PARSE_FAILED", "Missing HTTP header separator")
                head, body = wire.split("\r\n\r\n", 1)
                headers = head.split("\r\n")
                body_bytes = body.encode("latin-1")
            headers = [_wire_text(header) for header in headers]
            parts = headers[0].split() if headers else []
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                raise TemplateBuildError("REQUEST_PARSE_FAILED", "Invalid request line")

            # Keep the existing framing normalization until real-helper evidence
            # supports removing it. Duplicate length headers retain their shape.
            new_headers = []
            has_length = False
            for header in headers:
                if header.lower().startswith("content-length:"):
                    new_headers.append("Content-Length: %d" % len(body_bytes))
                    has_length = True
                else:
                    new_headers.append(header)
            if not has_length and len(body_bytes) > 0:
                new_headers.append("Content-Length: %d" % len(body_bytes))
            if helpers is not None:
                request_bytes = helpers.buildHttpMessage(new_headers, body_bytes)
            else:
                request_bytes = ("\r\n".join(new_headers) + "\r\n\r\n").encode("latin-1") + body_bytes
            if request_bytes is None or len(request_bytes) == 0:
                raise TemplateBuildError("REQUEST_BUILD_FAILED", "Empty HTTP rebuild result")
            _wire_text(request_bytes, helpers)  # reject accidental object/string representations
            return request_bytes
        except (Exception, JavaException) as error:
            code = error.code if isinstance(error, TemplateBuildError) else "TEMPLATE_BUILD_FAILED"
            detail = error.detail if isinstance(error, TemplateBuildError) else str(error)
            diagnostic = "TRANSFORM_ERROR [%s]\n%s" % (code, detail)
            try:
                if callable(custom_status_setter):
                    custom_status_setter(diagnostic)
                else:
                    self._log(diagnostic)
            except (Exception, JavaException):
                pass
            try:
                print("[BoberProxy template] TRANSFORM_ERROR %s" % code)
            except (Exception, JavaException):
                pass
            return fallback_resp


    def _init_session_runtime(self):
        self._runtime_lock = threading.Lock()
        self._runtime_config = None
        self._runtime_version = 0
        self._runtime_publisher = None
        self._flow_local = threading.local()
        self.sessions = SessionCoordinator(self.cookieManager, self.csrfManager)
        self._last_session_warning = -10000

    def _collect_runtime_values(self):
        # Production calls this only on the EDT. Field-double harnesses explicitly
        # have no publisher and collect their own test values at invocation.
        import copy
        def text(name, default=""):
            field = getattr(self, name, None)
            return field.getText().strip() if field is not None else default
        def selected(name, fallback=False):
            field = getattr(self, name, None)
            return bool(field.isSelected()) if field is not None else bool(fallback)
        def combo(name, default=""):
            field = getattr(self, name, None)
            return str(field.getSelectedItem()) if field is not None else default
        def template(name):
            editor = getattr(self, name, None)
            raw = editor.getMessage() if editor is not None else None
            return _wire_text(raw, self.helpers).encode("latin-1") if raw is not None else None
        auto = getattr(self, "autoFollowRTChk", None)
        statuses = tuple(sorted(int(label[0]) for label, field in getattr(self, "statusChecks", {}).items()
                                if field.isSelected()))
        values = dict(proxy=selected("proxyModeBtn", getattr(self, "_proxy_mode_active", False)),
                    use_cp=selected("useCheckPageChk", getattr(self, "useCheckPageTemplate", False)),
                    follow=bool(auto and auto.isSelected() and auto.isEnabled()),
                    payload1=text("payloadParamField", "q"), payload2=text("payloadParam2Field", "w"),
                    rt=template("reqTemplateEditor"), cp=template("checkPageEditor"),
                    custom=self._capture_custom_settings(),
                    cookies=selected("autoUpdateChk", getattr(self, "autoUpdateCookies", False)),
                    csrf=selected("autoUpdateCsrfChk", getattr(self, "autoUpdateCsrf", False)),
                    csrf_pattern=_session_pattern_state(self.csrfManager),
                    paused=selected("pauseBtn", getattr(self, "paused", False)), statuses=statuses,
                    size=text("sizeField"), len_type=combo("lenTypeCombo", "Total len"),
                    size_comp=combo("compCombo", "Min Len"), log_regex=text("regexField"),
                    display_filters=copy.deepcopy(getattr(self, "display_filters", {})))
        self._observe_capture_filter(values)
        values["capture_filter_plan"] = self._capture_filter_plan
        values["display_filter_plan"] = self._display_filter_plan
        return values

    def _publish_runtime(self):
        if self._custom_ui_closed:
            return
        try:
            values = self._collect_runtime_values()
        except (Exception, JavaException) as error:
            if self._runtime_config is None:
                raise
            self._session_warning("CONFIG_SNAPSHOT_ERROR: " + type(error).__name__)
            return
        with self._runtime_lock:
            if self._runtime_config is not None and self._runtime_config._values == values:
                return
            self._runtime_version += 1
            self._runtime_config = RuntimeConfig(values, self._runtime_version)

    def _capture_runtime(self):
        with self._runtime_lock:
            config = self._runtime_config
        if config is not None:
            return config
        # The real extension publishes before it exposes ui/listeners. Isolated
        # legacy logic fixtures intentionally bypass construction/EDT publishing.
        return RuntimeConfig(self._collect_runtime_values(), 0)

    def _runtime_for_flow(self):
        return getattr(self._flow_local, "config", None) or self._capture_runtime()

    def _flow_managers(self):
        context = getattr(self._flow_local, "context", None)
        if context is not None and context.cookies is not None:
            return context.cookies, context.csrf
        return self.cookieManager, self.csrfManager

    def _session_warning(self, code):
        now = _monotonic_ms()
        if now - self._last_session_warning >= 1000:
            self._last_session_warning = now
            self._log(code)
            print("[BoberProxy session] " + code)

    def proxy_flow_process_request(self, raw_request_bytes, orig_host, orig_port, orig_https,
                                   runtime_config=None, session_context=None):
        config = runtime_config or self._capture_runtime()
        # Unmatched requests must not queue behind a managed exchange.
        if not raw_request_bytes:
            return ProxyWorkflowResult(ProxyWorkflowResult.NO_MATCH)
        text = _wire_text(raw_request_bytes, self.helpers)
        payloads = _extract_raw_payloads(text, config.get("payload1"), config.get("payload2"))
        if not any(payloads):
            return ProxyWorkflowResult(ProxyWorkflowResult.NO_MATCH)
        with self._workflow_lock:
            self._workflow_counter += 1
            workflow_id = self._workflow_counter
        deadline = _monotonic_ms() + WORKFLOW_TIMEOUT_MS
        context = session_context
        if context is None:
            context, error = self.sessions.register(None, config, True)
            if error:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id, error_code=error)
        error = self.sessions.begin(context, deadline)
        if error:
            self.sessions.finish(context, original_response=True)
            return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id, error_code=error)
        previous = (getattr(self._flow_local, "config", None), getattr(self._flow_local, "context", None),
                    getattr(self._flow_local, "deadline", None), getattr(self._flow_local, "workflow_id", None))
        self._flow_local.config, self._flow_local.context, self._flow_local.deadline = config, context, deadline
        self._flow_local.workflow_id = workflow_id
        try:
            result = self._prepare_proxy_request(raw_request_bytes, orig_host, orig_port, orig_https)
            if not self.sessions.valid(context) and result.status == ProxyWorkflowResult.READY:
                result = ProxyWorkflowResult(ProxyWorkflowResult.ERROR_AFTER_SEND if context.any_sent else
                                             ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id, error_code="SESSION_CLEARED")
            result.session_context = context
            if result.status != ProxyWorkflowResult.READY or context.key is None:
                self.sessions.finish(context, original_response=result.status == ProxyWorkflowResult.ERROR_BEFORE_SEND)
            return result
        except (Exception, JavaException):
            self.sessions.finish(context)
            raise
        finally:
            (self._flow_local.config, self._flow_local.context,
             self._flow_local.deadline, self._flow_local.workflow_id) = previous



    def _prepare_proxy_request(self, raw_request_bytes, orig_host, orig_port, orig_https):
        """Return an explicit result, preserving whether a send was attempted."""
        config = self._runtime_for_flow()
        workflow_id = self._flow_local.workflow_id
        cookie_manager, csrf_manager = self._flow_managers()
        sent_or_uncertain = False
        try:
            deadline_ms = self._flow_local.deadline
            if not raw_request_bytes:
                return ProxyWorkflowResult(ProxyWorkflowResult.NO_MATCH, workflow_id=workflow_id)

            req_text = _wire_text(raw_request_bytes, self.helpers)

            pname1, pname2 = config.get("payload1"), config.get("payload2")
            incoming_payload1, incoming_payload2 = _extract_raw_payloads(req_text, pname1, pname2)

            # --- If no payloads at all, do not interfere (let proxy forward original) ---
            if not incoming_payload1 and not incoming_payload2:
                return ProxyWorkflowResult(ProxyWorkflowResult.NO_MATCH, workflow_id=workflow_id)

            # One immutable editor/switch version for the complete workflow.
            use_cpt, follow_redirects = config.get("use_cp"), config.get("follow")
            request_template = config.get("rt")
            template_error = self._template_preflight_error(request_template)
            if template_error:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id,
                                           error_code="RT_TEMPLATE_" + template_error)
            check_template = None
            if use_cpt:
                check_template = config.get("cp")
                template_error = self._template_preflight_error(check_template)
                if template_error:
                    return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id,
                                               error_code="CP_TEMPLATE_" + template_error)

            custom_settings = config.get("custom")
            build_errors = []
            request_bytes = self.build_request_from_template(
                get_editor_message=lambda: request_template,
                helpers=self.helpers, cookie_manager=cookie_manager, csrf_manager=csrf_manager,
                auto_update_cookies=config.get("cookies"),
                auto_update_csrf=config.get("csrf"),
                normalize_func=None, custom_status_setter=build_errors.append,
                incoming_payload1=incoming_payload1, incoming_payload2=incoming_payload2,
                fallback_resp=None, custom_settings=custom_settings)
            if not request_bytes:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id,
                                           error_code="RT_BUILD_FAILED",
                                            error_detail=build_errors[-1] if build_errors else None)
            if _monotonic_ms() >= deadline_ms:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id,
                                           error_code="WORKFLOW_TIMEOUT")
            if not use_cpt:
                return ProxyWorkflowResult(ProxyWorkflowResult.READY, request_bytes, workflow_id)

            # Conservatively retain uncertainty if an unexpected sender error escapes.
            sent_or_uncertain = True
            sent = self._send_http_request(orig_host, orig_port, orig_https, request_bytes)
            sent_or_uncertain = sent.attempted
            context = self._flow_local.context
            context.any_sent = context.any_sent or sent.attempted
            if sent.error_code:
                status = ProxyWorkflowResult.ERROR_AFTER_SEND if sent.attempted else ProxyWorkflowResult.ERROR_BEFORE_SEND
                return ProxyWorkflowResult(status, workflow_id=workflow_id,
                                           error_code=sent.error_code, error_type=sent.error_type)

            response_bytes = sent.response_bytes
            if follow_redirects:
                redirected = self._follow_redirects_chain(request_bytes, response_bytes, orig_host, orig_port,
                                                          orig_https, max_redirects=10, deadline_ms=deadline_ms)
                if redirected.error_code:
                    return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_AFTER_SEND, workflow_id=workflow_id,
                                               error_code=redirected.error_code, error_type=redirected.error_type)
            else:
                self._update_cookies_and_csrf(response_bytes)
            if _monotonic_ms() >= deadline_ms:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_AFTER_SEND, workflow_id=workflow_id,
                                           error_code="WORKFLOW_TIMEOUT")

            if not self.sessions.valid(self._flow_local.context):
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_AFTER_SEND, workflow_id=workflow_id,
                                           error_code="SESSION_CLEARED")
            cp_bytes = self.build_checkpage_request(incoming_payload1=incoming_payload1,
                                                    incoming_payload2=incoming_payload2,
                                                    template_bytes=check_template,
                                                    custom_status_setter=build_errors.append,
                                                    custom_settings=custom_settings)
            if not cp_bytes:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_AFTER_SEND, workflow_id=workflow_id,
                                           error_code="CP_BUILD_FAILED",
                                            error_detail=build_errors[-1] if build_errors else None)
            if _monotonic_ms() >= deadline_ms:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_AFTER_SEND, workflow_id=workflow_id,
                                           error_code="WORKFLOW_TIMEOUT")
            return ProxyWorkflowResult(ProxyWorkflowResult.READY, cp_bytes, workflow_id)
        except (Exception, JavaException) as error:
            status = ProxyWorkflowResult.ERROR_AFTER_SEND if sent_or_uncertain else ProxyWorkflowResult.ERROR_BEFORE_SEND
            return ProxyWorkflowResult(status, workflow_id=workflow_id,
                                       error_code="WORKFLOW_FAILED", error_type=type(error).__name__)

    def build_checkpage_request(self, incoming_payload1="", incoming_payload2="", template_bytes=None, custom_status_setter=None, custom_settings=None):
        """
        Build CheckPage request bytes from the CheckPage editor/template.
        Returns request bytes or None on failure; an optional captured template avoids rereading the editor.
        """
        config = self._runtime_for_flow()
        cookie_manager, csrf_manager = self._flow_managers()
        try:
            # get editor content
            try:
                editor_msg = template_bytes
                if editor_msg is None:
                    editor_msg = config.get("cp")
            except:
                editor_msg = None

            # call existing template builder (keeps behavior consistent)
            try:
                request_bytes = self.build_request_from_template(
                    get_editor_message=lambda: editor_msg,
                    helpers=self.helpers,
                    cookie_manager=cookie_manager,
                    csrf_manager=csrf_manager,
                    auto_update_cookies=config.get("cookies"),
                    auto_update_csrf=config.get("csrf"),
                    normalize_func=None,
                    custom_status_setter=custom_status_setter,
                    incoming_payload1=incoming_payload1 or "",
                    incoming_payload2=incoming_payload2 or "",                 
                    fallback_resp=None,
                    custom_settings=custom_settings
                )
            except Exception as e:
                try:
                    print("build_checkpage_request: build_request_from_template error:", e)
                except:
                    pass
                return (None)

            if not request_bytes:
                return (None)

            return (request_bytes)

        except Exception as e:
            try:
                print("build_checkpage_request top-level exception:", e)
            except:
                pass
            return (None)



class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks, self.helpers = callbacks, callbacks.getHelpers()
        self.ui = None
        self._extension_closed = False
        callbacks.setExtensionName("BoberProxy")
        callbacks.registerExtensionStateListener(self)
        def initialize():
            if self._extension_closed:
                return
            ui = None
            installed = []
            def withdraw():
                self.ui = None
                if ui is not None:
                    ui.close_custom_runtime()
                for kind in reversed(installed):
                    try:
                        if kind == "proxy":
                            callbacks.removeProxyListener(self)
                        elif kind == "http":
                            callbacks.removeHttpListener(self)
                        else:
                            callbacks.removeSuiteTab(ui)
                    except (Exception, JavaException):
                        pass
                installed[:] = []
            def still_open():
                if not self._extension_closed:
                    return True
                withdraw()
                return False
            try:
                self.controller = SimpleMessageController()
                self.msgEditor = callbacks.createMessageEditor(self.controller, False)
                ui = LoggerUI(callbacks, self.controller, self.msgEditor, callbacks)
                # Publish before rechecking unload: either the unload callback
                # sees this UI, or this initializer closes it. Never hold a
                # lifecycle mutex across calls into the host.
                self.ui = ui
                if not still_open():
                    return
                callbacks.addSuiteTab(ui)
                installed.append("tab")
                if not still_open():
                    return
                callbacks.registerHttpListener(self)
                installed.append("http")
                if not still_open():
                    return
                callbacks.registerProxyListener(self)
                installed.append("proxy")
                if not still_open():
                    return
                print("BoberProxy loaded (stabilization K08-K09)")
            except (Exception, JavaException):
                diagnostic = traceback.format_exc()
                withdraw()
                callbacks.printError("BoberProxy UI initialization failed:\n" + diagnostic)
        if swing.SwingUtilities.isEventDispatchThread():
            initialize()
        else:
            swing.SwingUtilities.invokeLater(initialize)

    def extensionUnloaded(self):
        self._extension_closed = True
        ui = getattr(self, "ui", None)
        if ui is not None:
            ui.close_custom_runtime()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            ui = getattr(self,"ui",None)
            if ui is None or ui._custom_ui_closed or messageIsRequest:
                return
            epoch = ui._log_generation
            config = ui._capture_runtime()
            if config.get("paused"):
                return
            response = messageInfo.getResponse()
            if response is None:
                return
            host = method = path = ""
            status, body_len = None, ""
            try:
                analyzed = self.helpers.analyzeResponse(response)
                status = analyzed.getStatusCode()
                body_len = len(response)-analyzed.getBodyOffset()
            except (Exception, JavaException):
                pass
            try:
                request = self.helpers.analyzeRequest(messageInfo)
                method = request.getMethod()
                url = request.getUrl()
                if url:
                    host = url.getHost()
                    query = url.getQuery()
                    path = url.getPath()+(("?"+query) if query else "")
            except (Exception, JavaException):
                pass
            data = (toolFlag,host,method,path,status,len(response),messageInfo,False,body_len)
            ui._queue_filter_log(data,config,epoch)
        except (Exception, JavaException) as error:
            print("processHttpMessage error:",error)


    def _report_workflow_error(self, result):
        message = "[BoberProxy workflow %s] %s" % (result.workflow_id, result.error_code)
        if result.error_type:
            message += " (%s)" % result.error_type
        print(message)
        try:
            detail = getattr(result, "error_detail", None)
            diagnostic = message + ("\n" + detail if detail else "")
            swing.SwingUtilities.invokeLater(lambda: self.ui._log(diagnostic))
        except (Exception, JavaException):
            pass

    def processProxyMessage(self, messageIsRequest, interceptedMessage):
        ui = getattr(self, "ui", None)
        if ui is None or ui._custom_ui_closed:
            return
        context = None
        try:
            reference = int(interceptedMessage.getMessageReference())
            info = interceptedMessage.getMessageInfo()
            if info is None:
                if not messageIsRequest:
                    ui.sessions.response(reference, None)
                return
            if not messageIsRequest:
                status, detail = ui.sessions.response(reference, info.getResponse())
                if status in ("SESSION_STALE_RESPONSE", "SESSION_RESPONSE_UNTRACKED"):
                    if ui._capture_runtime().get("cookies") or ui._capture_runtime().get("csrf"):
                        ui._session_warning(status)
                elif status in ("REGEX_INVALID", "REGEX_NO_CAPTURE", "DECODE_ERROR"):
                    ui._log("CSRF %s: %s" % (status, detail or ""))
                return  # Preserve the response's existing interception action.
            config = ui._capture_runtime()
            raw = info.getRequest()
            matched = False
            if config.get("proxy") and raw:
                matched = any(_extract_raw_payloads(_wire_text(raw, ui.helpers),
                                                    config.get("payload1"), config.get("payload2")))
            context, error = ui.sessions.register(reference, config, matched)
            if error == "EXISTING":
                return  # Another listener's rehook must not repeat a workflow.
            if error:
                ui._session_warning(error)
                if matched:
                    interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
                return
            if not matched:
                return  # Passive/unmatched paths preserve the incoming action.
            service = info.getHttpService()
            if service is None:
                ui.sessions.finish(context, original_response=True)
                return
            result = ui.proxy_flow_process_request(raw, service.getHost(), service.getPort(),
                                                    service.getProtocol().lower() == "https",
                                                    runtime_config=config, session_context=context)
            if not isinstance(result, ProxyWorkflowResult):
                ui.sessions.finish(context)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP)
                print("[BoberProxy] WORKFLOW_INVALID_RESULT")
                return
            if result.status in (ProxyWorkflowResult.ERROR_BEFORE_SEND, ProxyWorkflowResult.ERROR_AFTER_SEND):
                action = (interceptedMessage.ACTION_DROP if result.status == ProxyWorkflowResult.ERROR_AFTER_SEND
                          else interceptedMessage.ACTION_DONT_INTERCEPT)
                interceptedMessage.setInterceptAction(action)
                self._report_workflow_error(result)
                return
            if result.status == ProxyWorkflowResult.NO_MATCH:
                ui.sessions.finish(context, original_response=True)
                return
            if result.status != ProxyWorkflowResult.READY or not result.request_bytes:
                ui.sessions.finish(context)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP)
                print("[BoberProxy] WORKFLOW_INVALID_READY_RESULT")
                return
            if not ui.sessions.commit(context):
                ui.sessions.finish(context, original_response=not context.any_sent)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP if context.any_sent else
                                                       interceptedMessage.ACTION_DONT_INTERCEPT)
                self._report_workflow_error(ProxyWorkflowResult(
                    ProxyWorkflowResult.ERROR_AFTER_SEND if context.any_sent else ProxyWorkflowResult.ERROR_BEFORE_SEND,
                    workflow_id=result.workflow_id, error_code="SESSION_CLEARED"))
                return
            try:
                info.setRequest(result.request_bytes)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
            except (Exception, JavaException) as error:
                ui.sessions.finish(context)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP)
                print("[BoberProxy] PROXY_REPLACE_FAILED (%s)" % type(error).__name__)
        except (Exception, JavaException) as error:
            if context is not None and context.matched:
                ui.sessions.finish(context)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP)
            print("[BoberProxy] WORKFLOW_RESULT_UNAVAILABLE (%s)" % type(error).__name__)
