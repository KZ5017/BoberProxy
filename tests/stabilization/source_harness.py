# -*- coding: utf-8 -*-
"""Load selected real source blocks without starting Burp or the Swing UI.

Runs under CPython 3 and Jython 2.7. The extension file is never rewritten.
Burp helpers/interfaces are doubles; this is not a Burp integration harness.
"""
from __future__ import print_function

import codecs
import os
import re
import sys
import threading
import time
import traceback

try:
    from urllib.parse import urljoin, urlparse
except ImportError:
    from urlparse import urljoin, urlparse

PY2 = sys.version_info[0] == 2
try:
    text_type = unicode
except NameError:
    text_type = str
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE = os.path.join(ROOT, 'BoberProxy.py')


def as_bytes(value):
    if isinstance(value, bytes):
        return value
    return value.encode('latin-1')


def as_text(value):
    if isinstance(value, bytes):
        return value.decode('latin-1')
    if isinstance(value, text_type):
        return value
    # Real Java byte[] has signed integers. A helper double must return text,
    # rather than accidentally pass the array through to the tested manager.
    return bytearray((int(part) & 0xff for part in value)).decode('latin-1')


class Field(object):
    def __init__(self, value):
        self.value = value

    def getText(self):
        return self.value

    def setText(self, value):
        self.value = value


class Check(object):
    def __init__(self, selected=False, enabled=True):
        self.selected = selected
        self.enabled = enabled

    def isEnabled(self):
        return self.enabled

    def isSelected(self):
        return self.selected


class Response(object):
    def __init__(self, data):
        self.data = data

    def getResponse(self):
        return self.data


class Editor(object):
    def __init__(self, message):
        self.message = message

    def getMessage(self):
        return self.message


class APIType(object):
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class APIMethod(object):
    def __init__(self, types):
        self.types = types

    def getName(self):
        return 'makeHttpRequest'

    def getParameterTypes(self):
        return [APIType(name) for name in self.types]


class APIClass(object):
    def __init__(self, signatures):
        self.signatures = signatures

    def getMethods(self):
        return [APIMethod(types) for types in self.signatures]


class RequestInfo(object):
    def __init__(self, data):
        self.data = data

    def getHeaders(self):
        return as_text(self.data).split('\r\n\r\n', 1)[0].split('\r\n')

    def getBodyOffset(self):
        return self.data.index(as_bytes('\r\n\r\n')) + 4

    def getStatusCode(self):
        return int(as_text(self.data).split('\r\n', 1)[0].split()[1])

    def getUrl(self):
        # The real analyzeRequest(byte[]) overload has no full service URL.
        raise ValueError('Full URL unavailable without HTTP service')


class Helpers(object):
    def bytesToString(self, value):
        return as_text(value)

    def stringToBytes(self, value):
        return as_bytes(value)

    def analyzeRequest(self, value):
        return RequestInfo(value)

    def analyzeResponse(self, value):
        return RequestInfo(value)

    def buildHttpMessage(self, headers, body):
        # No framing normalization is claimed; real helper tests are separate.
        return as_bytes('\r\n'.join(headers) + '\r\n\r\n') + body

    def buildHttpService(self, *args):
        return args


class Callbacks(object):
    UNSET = object()

    def __init__(self, response=UNSET, legacy=False, both=False):
        self.response = as_bytes('HTTP/1.1 200 OK\r\n\r\n') if response is self.UNSET else response
        self.legacy = legacy
        self.both = both
        self.calls = []

    def getClass(self):
        signatures = []
        if not self.legacy or self.both:
            signatures.append(('burp.IHttpService', '[B'))
        if self.legacy or self.both:
            signatures.append(('java.lang.String', 'int', 'boolean', '[B'))
        return APIClass(signatures)

    def makeHttpRequest(self, *args):
        self.calls.append(args)
        if self.legacy:
            if len(args) == 2:
                raise TypeError('Simulated legacy-only API signature')
            return self.response
        return Response(self.response)

    def getHelpers(self):
        return Helpers()


class FakeTime(object):
    def __init__(self):
        self.sleeps = []

    def sleep(self, duration):
        self.sleeps.append(duration)

    def time(self):
        return time.time()


class CapturedOutput(object):
    def __init__(self):
        self.parts = []
        self.previous = None

    def write(self, value):
        self.parts.append(value)

    def flush(self):
        pass

    def __enter__(self):
        self.previous = sys.stdout
        sys.stdout = self
        return self

    def __exit__(self, *args):
        sys.stdout = self.previous

    def text(self):
        return ''.join(self.parts)


class ModelBase(object):
    def fireTableDataChanged(self):
        pass

    def fireTableRowsInserted(self, first, last):
        pass


class SwingUtilitiesDouble(object):
    @staticmethod
    def isEventDispatchThread():
        return True

    @staticmethod
    def invokeLater(callback):
        callback()


class SwingDouble(object):
    SwingUtilities = SwingUtilitiesDouble


class PatternDouble(object):
    """Portable basic-pattern model only; native probes use actual Java Pattern."""
    CASE_INSENSITIVE, DOTALL = re.IGNORECASE, re.DOTALL
    @staticmethod
    def compile(value, flags=0):
        compiled = re.compile(value, flags)
        class Compiled(object):
            def matcher(self, text):
                class Matcher(object):
                    def find(self):
                        return compiled.search(text) is not None
                return Matcher()
        return Compiled()


def load_namespace():
    with codecs.open(SOURCE, 'r', 'latin-1') as handle:
        source = handle.read()
    wanted = set(['LogEntry', 'LogStore', 'LogTableModel', 'CsrfManager',
                  'CookieManager', 'LoggerUI', '_exec_in_namespace',
                  'HttpSendResult', 'HttpRequestSender', 'ProxyWorkflowResult', 'BurpExtender'])
    wanted.update(['TemplateBuildError', '_wire_text', '_custom_value', '_extract_raw_payloads'])
    wanted.update(['RedirectResult', '_monotonic_ms', '_redirect_host_header',
                   '_redirect_base', '_redirect_destination'])
    wanted.update(['_custom_timeout', '_custom_failure', '_custom_error_detail', 'CustomWorkerHandle',
                   '_start_custom_worker', 'CustomJob', 'CustomExecutor'])
    wanted.update(['RuntimeConfig', '_session_cookie_copy', '_session_pattern_state',
                   '_session_csrf_copy', 'SessionContext', 'SessionCoordinator'])
    wanted.update(['FilterInputError', '_filter_text', '_filter_numbers', '_filter_pattern', '_filter_diagnostic',
                   'CaptureFilterPlan', 'DisplayFilterPlan', 'FilterJob', 'FilterWorker'])
    starts = list(re.finditer(r'^(?:class|def)\s+(\w+)\b', source, re.M))
    blocks = []
    for i, match in enumerate(starts):
        if match.group(1) in wanted:
            end = starts[i + 1].start() if i + 1 < len(starts) else len(source)
            blocks.append(source[match.start():end])
    namespace = dict(re=re, time=time, traceback=traceback,
                     urljoin=urljoin, urlparse=urlparse,
                     ITab=type('ITab', (object,), {}),
                     IBurpExtender=type('IBurpExtender', (object,), {}),
                     IHttpListener=type('IHttpListener', (object,), {}),
                     IProxyListener=type('IProxyListener', (object,), {}),
                     IExtensionStateListener=type('IExtensionStateListener', (object,), {}),
                     AbstractTableModel=ModelBase, Integer=int, JavaException=Exception,
                     swing=SwingDouble, JavaThrowable=Exception, Pattern=PatternDouble,
                     DISPLAY_FILTER_FIELDS=('Host','Method','Path','Status','BodyLen','ResponseContent'))
    for name in ['TEMPLATE_PAYLOAD_MARKER_1', 'TEMPLATE_PAYLOAD_MARKER_2',
                 'TEMPLATE_CSRF_MARKER']:
        match = re.search(r'^' + name + r'\s*=\s*("[^"\n]*")', source, re.M)
        if match is None:
            raise AssertionError('Source contract changed: ' + name)
        namespace[name] = match.group(1)[1:-1]
    real_threads = []

    class CompatibleThread(threading.Thread):
        def __init__(self, *args, **kwargs):
            threading.Thread.__init__(self, *args, **kwargs)
            real_threads.append(self)

        def isAlive(self):
            return self.is_alive()

        def setDaemon(self, value):
            self.daemon = value

    class ThreadingBridge(object):
        Lock = staticmethod(threading.Lock)
        Condition = staticmethod(threading.Condition)
        local = staticmethod(threading.local)
        Thread = CompatibleThread

    namespace['threading'] = ThreadingBridge
    namespace['_probe_threads'] = real_threads
    namespace['CUSTOM_GATE_NAME'] = 'BoberProxy.custom.v1'
    namespace['CUSTOM_START_LOCK'] = threading.Lock()
    match = re.search(r'^WORKFLOW_TIMEOUT_MS\s*=\s*(\d+)', source, re.M)
    if match is not None:
        namespace['WORKFLOW_TIMEOUT_MS'] = int(match.group(1))
    code = compile('\n'.join(blocks), SOURCE + ':selected-blocks', 'exec')
    eval(code, namespace)
    return namespace


def new_ui(namespace):
    ui = object.__new__(namespace['LoggerUI'])
    ui.helpers = Helpers()
    ui.callbacks = Callbacks()
    ui._http_sender = None
    ui._workflow_counter = 0
    ui._workflow_lock = threading.Lock()
    ui.reqTemplateEditor = Editor(as_bytes('POST /workflow/action HTTP/1.1\r\nHost: demo\r\n\r\none=p4yl04dm4rk3r&two=53c0undm4rk3r'))
    ui.checkPageEditor = Editor(as_bytes('POST /workflow/check HTTP/1.1\r\nHost: demo\r\n\r\ncsrf=c5rfm4rk3r&one=p4yl04dm4rk3r&two=53c0undm4rk3r'))
    ui.cookieManager = namespace['CookieManager']()
    ui.csrfManager = namespace['CsrfManager']()
    ui.csrfRegexArea = Field(r'token="([^"]*)"')
    # Field doubles have no Swing document events. Mirror initial validation.
    if hasattr(ui, '_on_csrf_regex_changed'):
        ui._on_csrf_regex_changed()
    ui.autoUpdateCookies = False
    ui.autoUpdateCsrf = False
    ui.payloadParamField = Field('q')
    ui.payloadParam2Field = Field('w')
    ui.custom_codeblock_status = False
    ui.useCheckPageTemplate = False
    ui.autoFollowRTChk = Check()
    ui.timeoutField = Field('500')
    ui.customStatusArea = Field('')
    ui._log = lambda text: ui.customStatusArea.setText(text)
    ui.paused = False
    if hasattr(ui, '_init_custom_runtime'):
        ui._init_custom_runtime()
    if hasattr(ui, '_init_session_runtime'):
        ui._init_session_runtime()
    if hasattr(ui, '_init_filter_runtime'):
        ui._init_filter_runtime()
    return ui
