# -*- coding: utf-8 -*-
"""Scoped SI00 observers and finite file-command API sends; never main code."""
from __future__ import print_function
import hashlib
import json
import os
import re
import threading
from urlparse import urlsplit
from burp import IHttpListener, IProxyListener, ISessionHandlingAction
from java.lang import System, Throwable
from si00_cookie_probe import ProbeCookie


HOSTS = ('127.0.0.1', 'localhost')
PORTS = (18780, 18781, 18782)


def load_config(path):
    with open(path, 'r') as handle: config = json.load(handle)
    if not re.match(r'^BP_SI00_WIRE_[a-f0-9]{12}$', config.get('cookie_name', '')):
        raise ValueError('Invalid synthetic cookie namespace')
    return config


class RuleAction(ISessionHandlingAction):
    def __init__(self, owner, phase): self.owner, self.phase = owner, phase
    def getActionName(self): return 'BoberProxy SI00 ' + self.phase
    def performAction(self, currentRequest, macroItems):
        self.owner.observe('rule-' + self.phase, currentRequest, True, macro_items=macroItems)


class WireProbe(IHttpListener, IProxyListener):
    def __init__(self, callbacks, directory, instance, config):
        self.callbacks, self.helpers = callbacks, callbacks.getHelpers()
        self.directory, self.instance, self.config = directory, instance, config
        self.closed = False
        self.lock = threading.Lock()
        self.records, self.sequence, self.dropped = [], 0, 0
        self.seen = set()
        self.owned_domains = set()
        self.actions = [RuleAction(self, 'before cookie'), RuleAction(self, 'after cookie')]
        self.trace_path = os.path.join(directory, 'si00-wire-trace.jsonl')
        self.command_path = os.path.join(directory, 'si00-wire-command.json')
        self.result_path = os.path.join(directory, 'si00-wire-result.json')
        self.state_path = os.path.join(directory, 'si00-wire-state.json')

    def _text(self, data):
        return self.helpers.bytesToString(data) if data is not None else ''

    def scope(self, message):
        service = message.getHttpService()
        if service is None or str(service.getHost()).lower() not in HOSTS or service.getPort() not in PORTS:
            return None
        text = self._text(message.getRequest())
        first = text.split('\r\n', 1)[0].split(' ')
        if len(first) != 3: return None
        url = urlsplit(first[1])
        if not url.path.startswith('/si00/'): return None
        match = re.search(r'(?:^|&)run=(si00-[A-Za-z0-9_-]{1,64})(?:&|$)', url.query)
        if match is None: return None
        return dict(run=match.group(1), method=first[0], target=first[1], text=text,
                    host=str(service.getHost()).lower(), port=int(service.getPort()))

    def jar(self):
        result = []
        for cookie in self.callbacks.getCookieJarContents():
            domain = cookie.getDomain()
            if (cookie.getName() != self.config['cookie_name'] or domain is None
                    or str(domain).lower().lstrip('.') not in HOSTS):
                continue
            expiry = cookie.getExpiration()
            path, value = cookie.getPath(), cookie.getValue()
            result.append(dict(domain=str(domain), path=str(path) if path is not None else None,
                               value=str(value) if value is not None else None,
                               expiration_ms=int(expiry.getTime()) if expiry is not None else None))
        return sorted(result, key=lambda row: (row['domain'], row['path'] or ''))

    def emit(self, record):
        with self.lock:
            self.sequence += 1
            if len(self.records) >= 2048:
                self.dropped += 1
                return
            record.update(instance=self.instance, sequence=self.sequence, nano=int(System.nanoTime()))
            self.records.append(record)

    def observe(self, phase, message, is_request, tool=None, macro_items=None):
        if self.closed: return
        try:
            scope = self.scope(message)
            if scope is None: return
            text = scope.pop('text')
            cookies, other_count = [], 0
            for line in text.split('\r\n\r\n', 1)[0].split('\r\n')[1:]:
                name, separator, value = line.partition(':')
                if not separator or name.lower() != 'cookie': continue
                for pair in value.split(';'):
                    key, separator, value = pair.strip().partition('=')
                    if not separator: continue
                    if key == self.config['cookie_name']: cookies.append(value)
                    else: other_count += 1
            response = self._text(message.getResponse()) if not is_request else ''
            tokens = []
            if macro_items is not None:
                for item in macro_items:
                    if self.scope(item) is not None:
                        tokens.extend(re.findall(r'name="si00_token" value="([A-Za-z0-9_.-]+)"',
                                                 self._text(item.getResponse())))
            scope.update(phase=phase, is_request=bool(is_request), tool=tool,
                message_identity=int(System.identityHashCode(message)),
                request_sha256=hashlib.sha256(text.encode('latin-1')).hexdigest(),
                response_sha256=hashlib.sha256(response.encode('latin-1')).hexdigest() if response else None,
                own_cookie_values=cookies, other_cookie_count=other_count, jar=self.jar(),
                macro_count=len(macro_items) if macro_items is not None else None, macro_tokens=tokens)
            self.emit(scope)
        except (BaseException, Throwable) as error:
            self.emit(dict(phase='observer-error', error_type=type(error).__name__))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self.observe('http-listener', messageInfo, messageIsRequest, tool=int(toolFlag))

    def processProxyMessage(self, messageIsRequest, interceptedMessage):
        self.observe('proxy-listener', interceptedMessage.getMessageInfo(), messageIsRequest)

    def flush(self):
        with self.lock:
            records, self.records = self.records, []
        if records:
            with open(self.trace_path, 'a') as handle:
                for record in records: handle.write(json.dumps(record) + '\n')

    def save_state(self, state):
        with open(self.state_path, 'w') as handle:
            json.dump(dict(instance=self.instance, state=state, cookie_name=self.config['cookie_name'],
                           action_names=[a.getActionName() for a in self.actions],
                           trace_dropped=self.dropped, command_count=len(self.seen)), handle, indent=2)

    def execute(self, command):
        if self.closed: raise ValueError('PROBE_CLOSED')
        if command.get('instance') != self.instance: raise ValueError('WRONG_INSTANCE')
        identifier = command.get('id', '')
        if not re.match(r'^[a-f0-9]{32}$', identifier): raise ValueError('INVALID_COMMAND_ID')
        if identifier in self.seen: raise ValueError('DUPLICATE_COMMAND_NO_REPLAY')
        if len(self.seen) >= 128: raise ValueError('FINITE_COMMAND_LIMIT')
        self.seen.add(identifier)  # Reserve before any possibly accepted operation.
        kind = command.get('operation')
        if kind == 'inspect': return dict(jar=self.jar())
        if kind == 'seed':
            domain = command.get('host', '127.0.0.1')
            path = command.get('path', '/')
            value = command.get('value', 'API_SEED')
            if domain not in HOSTS or path not in ('/', '/si00/deep/') or not re.match(r'^[A-Za-z0-9_.-]{0,80}$', value):
                raise ValueError('INVALID_SYNTHETIC_COOKIE')
            existing = [row for row in self.jar() if row['domain'].lstrip('.') == domain]
            if domain not in self.owned_domains and existing:
                raise ValueError('COOKIE_NAMESPACE_ALREADY_PRESENT')
            self.owned_domains.add(domain)
            self.callbacks.updateCookieJar(ProbeCookie(domain, path, self.config['cookie_name'], value))
            return dict(jar=self.jar())
        if kind == 'send':
            host, port = command.get('host', '127.0.0.1'), command.get('port', 18780)
            path = command.get('path', '')
            if host not in HOSTS or port not in PORTS or any(c in path for c in '\r\n'):
                raise ValueError('NON_FIXTURE_DESTINATION')
            parts = urlsplit(path)
            if parts.scheme or parts.netloc or not parts.path.startswith('/si00/') or not re.search(
                    r'(?:^|&)run=si00-[A-Za-z0-9_-]{1,64}(?:&|$)', parts.query):
                raise ValueError('UNTAGGED_FIXTURE_PATH')
            if port == 18782: raise ValueError('TLS_NOT_ENABLED_IN_FIRST_GATE')
            text = 'GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n' % (path, host, port)
            service = self.helpers.buildHttpService(host, port, False)
            self.emit(dict(phase='api-call-start', target=path))
            result = self.callbacks.makeHttpRequest(service, self.helpers.stringToBytes(text))
            response = self._text(result.getResponse())
            self.emit(dict(phase='api-call-return', target=path))
            body = response.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in response else ''
            return dict(response_first_line=response.split('\r\n', 1)[0],
                        response_json=json.loads(body) if body.startswith('{') else None, jar=self.jar())
        if kind == 'cleanup': return self.cleanup()
        raise ValueError('UNKNOWN_FINITE_OPERATION')

    def cleanup(self):
        # Native collection of responses on these exact test hosts is also ours.
        for row in list(self.jar()):
            domain = row['domain'].lower().lstrip('.')
            if any(c['domain'].lower().lstrip('.') == domain and c['path'] == row['path'] for c in self.jar()):
                self.callbacks.updateCookieJar(ProbeCookie(domain, row['path'], self.config['cookie_name'], None))
        remaining = self.jar()
        return dict(cleanup_complete=not remaining, remaining=remaining)

    def run(self):
        self.save_state('ready')
        self.callbacks.printOutput('SI00_WIRE READY (tagged loopback 18780-18782 only; no automatic requests)\n'
                                   + self.state_path)
        try:
            while not self.closed:
                command = None
                if os.path.isfile(self.command_path):
                    try:
                        with open(self.command_path, 'r') as handle: candidate = json.load(handle)
                        if candidate.get('instance') == self.instance and candidate.get('id') not in self.seen:
                            command = candidate
                    except (IOError, ValueError): pass  # Controller may be replacing JSON; no HTTP retry.
                if command is not None:
                    result = dict(instance=self.instance, id=command.get('id'), passed=False)
                    try:
                        result['result'] = self.execute(command)
                        result['passed'] = True
                    except (BaseException, Throwable) as error:
                        result['error_type'] = type(error).__name__
                        # Fixed local validation codes only; never render host exceptions.
                        codes = ('PROBE_CLOSED', 'WRONG_INSTANCE', 'INVALID_COMMAND_ID',
                                 'DUPLICATE_COMMAND_NO_REPLAY', 'FINITE_COMMAND_LIMIT',
                                 'INVALID_SYNTHETIC_COOKIE', 'COOKIE_NAMESPACE_ALREADY_PRESENT',
                                 'NON_FIXTURE_DESTINATION', 'UNTAGGED_FIXTURE_PATH',
                                 'TLS_NOT_ENABLED_IN_FIRST_GATE', 'UNKNOWN_FINITE_OPERATION')
                        if isinstance(error, ValueError) and str(error) in codes:
                            result['error_code'] = str(error)
                    self.flush()
                    result['trace_dropped'] = self.dropped
                    with open(self.result_path, 'w') as handle: json.dump(result, handle, indent=2)
                self.flush()
                threading.Event().wait(0.05)
        finally:
            self.flush()
            try:
                result = self.cleanup()
            except (BaseException, Throwable) as error:
                result = dict(cleanup_complete=False)
                self.callbacks.printError('SI00_WIRE_OWNED_CLEANUP_FAILED (' + type(error).__name__ + ')')
            self.save_state('closed' if result['cleanup_complete'] else 'owned-cleanup-incomplete')
