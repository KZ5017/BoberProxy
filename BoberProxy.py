# -*- coding: latin-1 -*-
# Extender.py - BoberProxy (updated: tabs, template controls, custom codeblock)
from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorController, IProxyListener, IExtensionStateListener

from javax import swing
from javax.swing import SortOrder, RowSorter, JTable, ListSelectionModel
from javax.swing.table import TableRowSorter, AbstractTableModel

from java.awt import (
    GridBagLayout, GridBagConstraints, Insets, Font, FlowLayout,
    Color, Dimension, BorderLayout
)
from java.awt.event import MouseAdapter
from java.util.regex import Pattern
from java.lang import Integer, Exception as JavaException

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


class LogStore:
    """Keeps the log entries in display order and assigns stable row indices."""

    def __init__(self):
        self.entries = []
        self._counter = 0

    def add(self, ts, host, method, path, status,
            total_len, body_len, messageInfo):

        self._counter += 1

        e = LogEntry(
            index=self._counter,
            ts=ts,
            host=host,
            method=method,
            path=path,
            status=status,
            total_len=total_len,
            body_len=body_len,
            messageInfo=messageInfo
        )

        self.entries.insert(0, e)
        return e

    def clear(self):
        self.entries = []
        self._counter = 0


class LogTableModel(AbstractTableModel):

    COLUMNS = [
        "#", "Time", "Host", "Method", "Path",
        "Status", "Total Len", "Body Len"
    ]

    def __init__(self, logStore):
        AbstractTableModel.__init__(self)
        self.logStore = logStore
        self.displayed = []   # List[LogEntry]

    # ---------- JTable API ----------

    def getRowCount(self):
        return len(self.displayed)

    def getColumnCount(self):
        return len(self.COLUMNS)

    def getColumnName(self, col):
        return self.COLUMNS[col]

    def getValueAt(self, row, col):
        try:
            e = self.displayed[row]
            values = (
                Integer(e.index),
                e.ts,
                e.host,
                e.method,
                e.path,
                Integer(e.status) if e.status != "" else Integer(0),
                Integer(e.total_len) if e.total_len != "" else Integer(0),
                Integer(e.body_len) if e.body_len not in ("", None) else None,
            )
            return values[col]
        except:
            return ""

    def getColumnClass(self, col):
        if col in (0, 5, 6, 7):
            return Integer
        return str


    def isCellEditable(self, row, col):
        return False

    # ---------- Data control ----------

    def rebuild(self, filter_fn=None):
        # Rebuild the displayed slice from the backing store to keep filtering centralized.
        if filter_fn:
            self.displayed = [
                e for e in self.logStore.entries
                if filter_fn(e)
            ]
        else:
            self.displayed = list(self.logStore.entries)

        self.fireTableDataChanged()


    def add_entry_top(self, entry, show):
        if not show:
            return

        self.displayed.insert(0, entry)

        # Swing értesítés
        self.fireTableRowsInserted(0, 0)


    def clear(self):
        self.displayed = []
        self.fireTableDataChanged()


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


def _start_custom_worker(target):
    """Claim one process-wide worker, including other Jython interpreters.

    A bootstrap Java class monitor makes check/start atomic across interpreters.
    A dedicated ThreadGroup remains identifiable if custom code renames its
    thread. This is lifecycle coordination, not a sandbox for arbitrary code.
    """
    try:
        from java.lang import Thread, ThreadGroup, Runnable, Class
        from synchronize import apply_synchronized
    except ImportError:
        # CPython logic harness only; the production runtime uses the JVM gate.
        import threading as native_threads
        with CUSTOM_START_LOCK:
            if any(t.name == CUSTOM_GATE_NAME and t.is_alive() for t in native_threads.enumerate()):
                return None
            thread = threading.Thread(target=target, name=CUSTOM_GATE_NAME)
            thread.setDaemon(True)
            thread.start()
            return CustomWorkerHandle(thread)

    class Worker(Runnable):
        def run(self):
            target()

    def claim():
        for thread in Thread.getAllStackTraces().keySet():
            group = thread.getThreadGroup()
            if thread.isAlive() and group is not None and group.getName() == CUSTOM_GATE_NAME:
                return None
        group = ThreadGroup(CUSTOM_GATE_NAME)
        thread = Thread(group, Worker(), CUSTOM_GATE_NAME)
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
class FilterDialog(object):
    def __init__(self, parent):
        self.parent = parent
        self.dialog = swing.JDialog()
        self.dialog.setTitle("Display filter")
        # use simple JPanel as content
        p = swing.JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(4,4,4,4)
        c.fill = GridBagConstraints.HORIZONTAL
        row = 0
        # header
        c.gridx = 0; c.gridy = row; c.gridwidth = 3
        p.add(swing.JLabel("Select the options you want to filter by"), c)
        c.gridwidth = 1; row += 1

        # Build one control row per supported display filter.
        self.controls = {}
        for fname in DISPLAY_FILTER_FIELDS:
            cb = swing.JCheckBox("", False)
            mode = swing.JComboBox(["eq","not eq"])
            vals = swing.JTextField("", 40)
            c.gridx = 0; c.gridy = row; c.weightx = 0.0
            p.add(cb, c)
            c.gridx = 1; c.weightx = 0.0
            p.add(swing.JLabel(fname), c)
            c.gridx = 2; c.weightx = 0.0
            p.add(mode, c)
            c.gridx = 3; c.weightx = 1.0
            p.add(vals, c)
            self.controls[fname] = (cb, mode, vals)
            row += 1

        try:
            pref = p.getPreferredSize()
            p.setPreferredSize(Dimension(pref.width, max(pref.height, 300)))
        except:
            pass
        # majd setContentPane(p), pack(), stb.

        # set dialog content and sizing so components are visible
        try:
            self.dialog.setContentPane(p)
            self.dialog.pack()
            try:
                self.dialog.setModal(True)
            except:
                pass
            try:
                # position relative to parent component if available
                try:
                    self.dialog.setLocationRelativeTo(self.parent._component)
                except:
                    self.dialog.setLocationRelativeTo(None)
            except:
                pass
            # optional: set default close operation if available in Jython context
            try:
                self.dialog.setDefaultCloseOperation(swing.JDialog.DISPOSE_ON_CLOSE)
            except:
                pass
        except Exception:
            pass

        # buttons row: Apply / Reset / Cancel
        btnPanel = swing.JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0))
        applyBtn = swing.JButton("Apply", actionPerformed=self._on_apply)
        resetBtn = swing.JButton("Reset", actionPerformed=self._on_reset)
        cancelBtn = swing.JButton("Cancel", actionPerformed=lambda e: self.dialog.dispose())
        btnPanel.add(applyBtn); btnPanel.add(resetBtn); btnPanel.add(cancelBtn)
        c.gridx = 0; c.gridy = row; c.gridwidth = 4; c.weightx = 1.0
        p.add(btnPanel, c)


    def load_from_parent(self):
        # populate controls with current parent display_filters
        try:
            for fname, (cb, mode, vals) in self.controls.items():
                cfg = self.parent.display_filters.get(fname, {"active": False, "mode": "eq", "values": []})
                try:
                    cb.setSelected(bool(cfg.get("active", False)))
                except:
                    pass
                try:
                    mode.setSelectedItem(str(cfg.get("mode","eq")))
                except:
                    pass
                try:
                    vals.setText(",".join(cfg.get("values",[])))
                except:
                    pass
        except:
            pass

    def _on_apply(self, evt=None):
        try:
            # build new config and set to parent
            for fname, (cb, mode, vals) in self.controls.items():
                active = bool(cb.isSelected())
                m = str(mode.getSelectedItem()) if mode.getSelectedItem() else "eq"
                vtxt = str(vals.getText() or "").strip()
                vals_list = [x.strip() for x in vtxt.split(",") if x.strip()]
                self.parent.display_filters[fname] = {"active": active, "mode": m, "values": vals_list}
            # close dialog
            self.dialog.dispose()
            # apply on parent UI thread
            try:
                swing.SwingUtilities.invokeLater(lambda: self.parent._refresh_table_display())
            except:
                self.parent._refresh_table_display()
        except Exception as e:
            try:
                self.parent.customStatusArea.setText("Filter apply error: %s" % e)
            except:
                pass
        
    def _on_reset(self, evt=None):
        """
        Reset all filter controls to inactive / empty and update parent.display_filters to defaults (inactive).
        """
        try:
            # Clear UI controls
            for fname, (cb, mode, vals) in self.controls.items():
                try:
                    cb.setSelected(False)
                except:
                    pass
                try:
                    mode.setSelectedItem("eq")
                except:
                    pass
                try:
                    vals.setText("")
                except:
                    pass

            # Reset parent's filter config to default inactive entries
            try:
                for fname in self.controls.keys():
                    self.parent.display_filters[fname] = {"active": False, "mode": "eq", "values": []}
            except:
                pass

            # Refresh parent display on UI thread
            try:
                swing.SwingUtilities.invokeLater(lambda: self.parent._refresh_table_display())
            except:
                try:
                    self.parent._refresh_table_display()
                except:
                    pass

        except Exception as e:
            try:
                self.parent.customStatusArea.setText("Filter reset error: %s" % e)
            except:
                pass


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
        self.table.setAutoCreateRowSorter(True)

        # 5 Selection listener
        self.table.getSelectionModel().addListSelectionListener(
            self.on_table_select
        )
        #------------------NEW---------------------------

        self._init_display_filters()

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
        self.table.getSelectionModel().addListSelectionListener(self.on_table_select)

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
        try:
            view_row = self.table.getSelectedRow()
            if view_row < 0:
                return ""

            model_row = self.table.convertRowIndexToModel(view_row)

            if not (0 <= model_row < len(self.logTableModel.displayed)):
                return ""

            entry = self.logTableModel.displayed[model_row]
            msg = entry.messageInfo

            reqb = msg.getRequest()
            if not reqb:
                return ""

            return self.helpers.bytesToString(reqb)

        except Exception as e:
            print("_get_request_text_from_selected error:", e)
            return ""


    def _load_template_from_viewer(self, event=None):
        try:
            txt = self._get_request_text_from_selected()
            # set into editor (prefer setMessage)
            try:
                if hasattr(self, "reqTemplateEditor"):
                    # create bytes via helpers
                    b = None
                    try:
                        b = self.helpers.stringToBytes(txt)
                    except:
                        b = txt.encode("latin-1", "replace")
                    self.reqTemplateEditor.setMessage(b, True)
                self.set_status("Loaded request into Request Template")
                self.tabbed.setSelectedIndex(1)
            except:
                pass
        except:
            pass

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

    def _load_check_from_viewer(self, event=None):
        try:
            txt = self._get_request_text_from_selected()
            try:
                if hasattr(self, "checkPageEditor"):
                    b = None
                    try:
                        b = self.helpers.stringToBytes(txt)
                    except:
                        b = txt.encode("latin-1", "replace")
                    self.checkPageEditor.setMessage(b, True)
                self.set_status("Loaded request into CheckPageTemplate")
                self.tabbed.setSelectedIndex(2)
            except:
                pass
        except:
            pass

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


    def _row_matches_filters(self, entry):
        """
        entry: LogEntry
        """
        try:
            method = entry.method or ""
            host = entry.host or ""
            path = entry.path or ""
            status = str(entry.status or "")
            body_len = entry.body_len
            msg = entry.messageInfo
        except:
            return True

        field_map = {
            "Host": host,
            "Method": method,
            "Path": path,
            "Status": status,
        }

        try:
            for fname, cfg in self.display_filters.items():
                if not cfg.get("active"):
                    continue

                mode = cfg.get("mode", "eq")
                vals = cfg.get("values", [])
                if not vals:
                    return False

                matched = False
                cell = str(field_map.get(fname, "")).strip()

                # --- BodyLen ---
                if fname == "BodyLen":
                    try:
                        if body_len == "" or body_len is None:
                            matched = False
                        else:
                            actual = int(body_len)
                            for v in vals:
                                try:
                                    if int(v) == actual:
                                        matched = True
                                        break
                                except:
                                    pass
                    except:
                        matched = False

                # --- ResponseContent ---
                elif fname == "ResponseContent":
                    try:
                        resp = msg.getResponse()
                        hay = ""
                        if resp:
                            hay = self.helpers.bytesToString(resp)
                        for v in vals:
                            if not v:
                                continue
                            try:
                                pat = Pattern.compile(v, Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
                                if pat.matcher(hay).find():
                                    matched = True
                                    break
                            except:
                                pass
                    except:
                        matched = False

                # --- Path partial ---
                elif fname == "Path":
                    for v in vals:
                        if v and v in cell:
                            matched = True
                            break

                # --- Default exact ---
                else:
                    for v in vals:
                        if v and cell == v:
                            matched = True
                            break

                # --- apply mode ---
                if mode == "eq":
                    if not matched:
                        return False
                else:
                    if matched:
                        return False

            return True

        except:
            return True


    def _refresh_table_display(self):
        try:
            self.logTableModel.rebuild(self._row_matches_filters)
        except Exception as e:
            self.customStatusArea.append(
                "refresh error: %s\n" % e
            )



    def set_status(self, txt):
        try:
            self.statusLabel.setText(txt)
        except:
            pass

    def clear_log(self, evt=None):
        try:
            self.logStore.clear()
            self.logTableModel.clear()
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

            removed = 0

            for r in model_rows:
                try:
                    entry = self.logTableModel.displayed[r]
                    # törlés a LogStore-ból (objektum alapon!)
                    if entry in self.logStore.entries:
                        self.logStore.entries.remove(entry)
                        removed += 1
                except:
                    pass

            # tábla újraépítése (filterek megtartása)
            try:
                self.logTableModel.rebuild(self._row_matches_filters)
            except:
                self.logTableModel.rebuild()

            self._log("Cleared %d selected" % removed)

        except Exception as e:
            try:
                self._log("clear_selected error: %s\n" % str(e))
            except:
                pass


    def toggle_pause(self, evt=None):
        self.paused = bool(self.pauseBtn.isSelected())
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


    def add_selected_to_sitemap(self, event=None):
        view_rows = self.table.getSelectedRows()
        if not view_rows:
            swing.JOptionPane.showMessageDialog(None, "No rows selected.")
            return

        count = 0

        for view_row in view_rows:
            try:
                model_row = self.table.convertRowIndexToModel(view_row)

                if not (0 <= model_row < len(self.logTableModel.displayed)):
                    continue

                entry = self.logTableModel.displayed[model_row]
                msg = entry.messageInfo

                self.callbacks_ref.addToSiteMap(msg)

                try:
                    url = self.helpers.analyzeRequest(msg).getUrl()
                    if url:
                        self.callbacks_ref.includeInScope(url)
                except:
                    pass

                count += 1

            except Exception as e:
                self._log("add_selected_to_sitemap ERROR: %s\n" % str(e))

        self._log("Added %d selected to Site map" % count)


    def on_table_select(self, event):
        row = self.table.getSelectedRow()
        if row < 0:
            return

        model_row = self.table.convertRowIndexToModel(row)
        try:
            entry = self.logTableModel.displayed[model_row]
            msg = entry.messageInfo
        except:
            return

        self.controller.setMessageInfo(msg)
        self.reqViewer.setMessage(msg.getRequest(), True)
        self.respViewer.setMessage(msg.getResponse(), False)


    # append_log_row (filter-aware)
    # append_log_row (LogStore-alapú, de UI-kompatibilis)
    def append_log_row(self, toolFlag, host, method, path,
                    status, total_length, messageInfo, isRequest):

        if self.paused:
            return

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        body_len = ""
        try:
            if not isRequest and messageInfo.getResponse():
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

        show = True
        try:
            if hasattr(self, "_row_matches_filters"):
                show = self._row_matches_filters(entry)
        except:
            pass

        self.logTableModel.add_entry_top(entry, show)

        try:
            self.set_status("Logged: %s" % path)
        except:
            pass



    def should_log(self, toolFlag, messageIsRequest, messageInfo):
        if self.paused:
            return False
        if messageIsRequest:
            return False
        resp = messageInfo.getResponse()
        if resp is None:
            return False
        try:
            analyzed = self.helpers.analyzeResponse(resp)
            status = None
            try:
                status = analyzed.getStatusCode()
            except:
                status = None
        except:
            analyzed = None
            status = None
        any_checked = any(cb.isSelected() for cb in self.statusChecks.values())
        if any_checked:
            ok = False
            for label, cb in self.statusChecks.items():
                if not cb.isSelected(): continue
                try:
                    base = int(label[0])
                    if status is not None and status >= base*100 and status < (base+1)*100:
                        ok = True
                        break
                except:
                    pass
            if not ok:
                return False
        val_text = str(self.sizeField.getText()).strip()
        if val_text:
            blocked_values = []
            for part in val_text.split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    blocked_values.append(int(part))
                except:
                    pass
            if not blocked_values:
                return False
            len_type = str(self.lenTypeCombo.getSelectedItem())
            try:
                if len_type == "Total len":
                    actual = len(resp)
                else:
                    if analyzed is not None:
                        body_off = analyzed.getBodyOffset()
                        actual = len(resp) - body_off
                    else:
                        actual = len(resp)
            except:
                actual = len(resp)
            comp = str(self.compCombo.getSelectedItem())
            if comp == "Min Len":
                if actual < min(blocked_values):
                    return False
            elif comp == "Max Len":
                if actual > max(blocked_values):
                    return False
            elif comp == "Not eq Len":
                if actual in blocked_values:
                    return False

        pattern_text = str(self.regexField.getText()).strip()
        if pattern_text:
            try:
                pat = Pattern.compile(pattern_text)
                hay = self.helpers.bytesToString(resp) if resp else ""
                m = pat.matcher(hay)
                if not m.find():
                    return False
            except:
                return False
        return True


    # COOKIE and CSRF HELPERS
    def _on_clear_cookies(self, evt=None):
        try:
            self.cookieManager.clear()
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
            self.csrfManager.clear()
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
        def close_timer():
            if self._custom_test_timer is not None:
                self._custom_test_timer.stop()
                self._custom_test_timer = None
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
        if not response_bytes:
            return

        # --- COOKIE UPDATE ---
        if getattr(self, "autoUpdateCookies", False):
            try:
                text = self.callbacks.getHelpers().bytesToString(response_bytes)
                self.cookieManager.update_from_response(text)
            except Exception as e:
                print("[CookieUpdate] error:", e)

        # The document listener validates/compiles on edits, not on responses.
        if getattr(self, "autoUpdateCsrf", False):
            try:
                ok, new_token = self.csrfManager.update_from_response(response_bytes)
                status, detail = self.csrfManager.get_status()
                if ok or status in ("REGEX_INVALID", "REGEX_NO_CAPTURE", "DECODE_ERROR"):
                    message = ("CSRF token updated." if ok else
                               "CSRF %s: %s" % (status, detail or ""))
                    swing.SwingUtilities.invokeLater(lambda: self.customStatusArea.setText(message))
            except (Exception, JavaException) as error:
                print("[CSRFUpdate] ERROR:", error)


    def _send_http_request(self, host, port, https, request_bytes):
        if self._http_sender is None:
            self._http_sender = HttpRequestSender(self.callbacks, self.helpers)
        return self._http_sender.send(host, port, https, request_bytes)

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
        """Follow minimal GET redirects with one shared scheduling deadline.

        Every received response is updated once, including the last allowed
        hop. This cannot interrupt an already-blocking synchronous Burp call.
        """
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
                if getattr(self, "autoUpdateCookies", False):
                    text = _wire_text(new_request, self.helpers)
                    injected = self.cookieManager.inject_into_request(text)
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


    def proxy_flow_process_request(self, raw_request_bytes, orig_host, orig_port, orig_https):
        """Return an explicit result, preserving whether a send was attempted."""
        with self._workflow_lock:
            self._workflow_counter += 1
            workflow_id = self._workflow_counter
        sent_or_uncertain = False
        try:
            deadline_ms = _monotonic_ms() + WORKFLOW_TIMEOUT_MS
            if not raw_request_bytes:
                return ProxyWorkflowResult(ProxyWorkflowResult.NO_MATCH, workflow_id=workflow_id)

            req_text = _wire_text(raw_request_bytes, self.helpers)

            # --- extract payload param names ---
            try:
                pname1 = str(self.payloadParamField.getText()).strip()
            except:
                pname1 = getattr(self, "payload_param_name", "q")
            try:
                pname2 = str(self.payloadParam2Field.getText()).strip()
            except:
                pname2 = getattr(self, "payload_param2_name", "w")

            incoming_payload1, incoming_payload2 = _extract_raw_payloads(req_text, pname1, pname2)

            # --- If no payloads at all, do not interfere (let proxy forward original) ---
            if not incoming_payload1 and not incoming_payload2:
                return ProxyWorkflowResult(ProxyWorkflowResult.NO_MATCH, workflow_id=workflow_id)

            # Capture both templates before any user code or network operation.
            try:
                use_cpt = bool(getattr(self, "useCheckPageTemplate", False)) or bool(getattr(self, "checkPageTemplateCheckbox", False) and self.checkPageTemplateCheckbox.isSelected())
            except:
                use_cpt = False
            follow_redirects = bool(self.autoFollowRTChk.isSelected() and self.autoFollowRTChk.isEnabled())
            request_template = self.reqTemplateEditor.getMessage()
            template_error = self._template_preflight_error(request_template)
            if template_error:
                return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id,
                                           error_code="RT_TEMPLATE_" + template_error)
            check_template = None
            if use_cpt:
                check_template = self.checkPageEditor.getMessage()
                template_error = self._template_preflight_error(check_template)
                if template_error:
                    return ProxyWorkflowResult(ProxyWorkflowResult.ERROR_BEFORE_SEND, workflow_id=workflow_id,
                                               error_code="CP_TEMPLATE_" + template_error)

            custom_settings = self._capture_custom_settings()
            build_errors = []
            request_bytes = self.build_request_from_template(
                get_editor_message=lambda: request_template,
                helpers=self.helpers, cookie_manager=self.cookieManager, csrf_manager=self.csrfManager,
                auto_update_cookies=getattr(self, "autoUpdateCookies", False),
                auto_update_csrf=getattr(self, "autoUpdateCsrf", False),
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
        try:
            # get editor content
            try:
                editor_msg = template_bytes
                if editor_msg is None:
                    editor_msg = self.checkPageEditor.getMessage() if hasattr(self, "checkPageEditor") else None
            except:
                editor_msg = None

            # call existing template builder (keeps behavior consistent)
            try:
                request_bytes = self.build_request_from_template(
                    get_editor_message=lambda: editor_msg,
                    helpers=self.helpers,
                    cookie_manager=self.cookieManager,
                    csrf_manager=self.csrfManager,
                    auto_update_cookies=getattr(self, "autoUpdateCookies", False),
                    auto_update_csrf=getattr(self, "autoUpdateCsrf", False),
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
        self.callbacks = callbacks
        callbacks.setExtensionName("BoberProxy")
        self.helpers = callbacks.getHelpers()

        self.controller = SimpleMessageController()
        try:
            self.msgEditor = callbacks.createMessageEditor(self.controller, False)
        except Exception as e:
            print("createMessageEditor failed (ignored):", e)
            self.msgEditor = None

        self.ui = LoggerUI(callbacks, self.controller, self.msgEditor, callbacks)
        callbacks.addSuiteTab(self.ui)

        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        # register proxy listener so we can intercept proxy messages when Proxy Mode ON
        try:
            callbacks.registerProxyListener(self)
        except Exception as e:
            print("registerProxyListener failed (ignored):", e)

        print("BoberProxy loaded (stabilization K05)")


    def extensionUnloaded(self):
        ui = getattr(self, "ui", None)
        if ui is not None:
            ui.close_custom_runtime()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        try:
            host = method = path = ""
            status = None
            length = None
            try:
                if messageIsRequest:
                    analyzed = self.helpers.analyzeRequest(messageInfo)
                    method = analyzed.getMethod()
                    url = analyzed.getUrl()
                    if url:
                        host = url.getHost()
                        q = url.getQuery()
                        path = url.getPath() + (("?" + q) if q else "")
                    reqb = messageInfo.getRequest()
                    length = len(reqb) if reqb else 0
                else:
                    respb = messageInfo.getResponse()
                    if respb:
                        analyzedResp = self.helpers.analyzeResponse(respb)
                        try:
                            status = analyzedResp.getStatusCode()
                        except:
                            status = None
                        length = len(respb)
                    try:
                        analyzedReq = self.helpers.analyzeRequest(messageInfo)
                        method = analyzedReq.getMethod()
                        url = analyzedReq.getUrl()
                        if url:
                            host = url.getHost()
                            q = url.getQuery()
                            path = url.getPath() + (("?" + q) if q else "")
                    except:
                        pass
            except:
                pass

            try:
                should = self.ui.should_log(toolFlag, messageIsRequest, messageInfo)
            except:
                should = True

            if should:
                # attach transformed payload info into log entry (as 7th element) — non-invasive
                def _append():
                    try:
                        # For requests, show the outgoing_payload_from_custom (if set) in the detail view only when selected.
                        self.ui.append_log_row(toolFlag, host, method, path, status, length, messageInfo, messageIsRequest)
                        # Optionally annotate latest row's status label if transform exists
                    except Exception as e:
                        print("append invoke error:", e)
                swing.SwingUtilities.invokeLater(_append)
        except Exception as e:
            print("processHttpMessage error:", e)


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
        """
        Proxy listener: single-entry request-branch implementation.
        Build the final request (RequestTemplate or CheckPage) synchronously,
        then replace the proxied request and let Burp forward it.
        """
        try:
            # ====================================================
            # RESPONSE BRANCH – update cookie / csrf from server
            # ====================================================
            if not messageIsRequest:
                # State collection is independent of the current Proxy action.
                # Preserve manual rules and decisions made by previous listeners.
                msg_info = interceptedMessage.getMessageInfo()
                if msg_info is not None and getattr(self, "ui", None) is not None:
                    response_bytes = msg_info.getResponse()
                    if response_bytes:
                        self.ui._update_cookies_and_csrf(response_bytes)
                return


            # UI readiness + proxy mode enabled?
            try:
                if not getattr(self, "ui", None):
                    return
                if not getattr(self.ui, "_proxy_mode_active", False):
                    return
            except:
                return

            # get message info and raw request bytes and service
            try:
                msg_info = interceptedMessage.getMessageInfo()
                if not msg_info:
                    return
                raw_req = msg_info.getRequest()
                if not raw_req:
                    return
                service = msg_info.getHttpService()
                if not service:
                    return
            except:
                return

            # get orig_hos, torig_port, orig_https            
            orig_host  = service.getHost()
            orig_port  = service.getPort()
            orig_https = (service.getProtocol().lower() == "https")


            # run the unified proxy-workflow on this raw request (implemented on UI)
            try:
                result = self.ui.proxy_flow_process_request(raw_req, orig_host, orig_port, orig_https)
            except (Exception, JavaException) as error:
                # An unclassified failure cannot prove that nothing was sent.
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP)
                print("[BoberProxy] WORKFLOW_RESULT_UNAVAILABLE (%s)" % type(error).__name__)
                return

            if not isinstance(result, ProxyWorkflowResult):
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
                return
            if result.status != ProxyWorkflowResult.READY or not result.request_bytes:
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP)
                print("[BoberProxy] WORKFLOW_INVALID_READY_RESULT")
                return

            # Replace the proxy's request with our final request and let Burp forward it
            try:
                msg_info.setRequest(result.request_bytes)
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DONT_INTERCEPT)
            except (Exception, JavaException) as error:
                interceptedMessage.setInterceptAction(interceptedMessage.ACTION_DROP)
                print("[BoberProxy] PROXY_REPLACE_FAILED (%s)" % type(error).__name__)
            return

        except (Exception, JavaException) as e:
            try:
                print("processProxyMessage outer exception:", e)
            except:
                pass
