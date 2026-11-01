"""SI00 loopback fixture, redacting unrelated cookie/header values in captures."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import re
import socketserver
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs
from target_server import FixtureHandler, FixtureServer, FixtureState


class SessionState(FixtureState):
    def __init__(self, capture, cookie_name):
        super().__init__(capture)
        self.cookie_name, self.tokens = cookie_name, {}

    def record(self, run, method, target, headers, raw, body):
        if not run.startswith('si00-'): raise ValueError('SI00 run required')
        safe, other_cookies = [], 0
        for key, value in headers:
            if key.lower() == 'cookie':
                own = []
                for pair in value.split(';'):
                    name, sep, val = pair.strip().partition('=')
                    if not sep: continue
                    if name == self.cookie_name: own.append(pair.strip())
                    else: other_cookies += 1
                if own: safe.append((key, '; '.join(own)))
            elif key.lower() in ('host', 'content-type', 'content-length', 'connection', 'x-bober-test-run'):
                safe.append((key, value))
        with self.lock:
            self.sequence += 1
            event = dict(sequence=self.sequence, time_ns=time.time_ns(), run=run, method=method,
                         target=target, headers=safe, other_cookie_count=other_cookies,
                         request_sha256=hashlib.sha256(raw).hexdigest(),
                         body_base64=base64.b64encode(body).decode('ascii'))
            self.events.setdefault(run, []).append(event)
            self.events[run] = self.events[run][-200:]
            self.event_counts[run] = self.event_counts.get(run, 0) + 1
            self.capture.write(json.dumps(event) + '\n')
            return event

    def token(self, run):
        with self.lock:
            number = self.tokens.get(run, 0) + 1
            self.tokens[run] = number
            return 'SI00.%s.%d' % (run, number)


class SessionHandler(FixtureHandler):
    def handle_extra_route(self, url, method, event, headers, body, run):
        if not url.path.startswith('/si00/'): return False
        name = self.server.state.cookie_name
        query = parse_qs(url.query, keep_blank_values=True)
        if url.path == '/si00/health':
            self.json_response(dict(fixture='BoberProxy-SI00', cookie_name=name))
        elif url.path.endswith('/echo') or url.path == '/si00/check':
            fields = parse_qs(body.decode('latin-1'),keep_blank_values=True) if body else query
            session = self.server.state.snapshot(run)['session']
            own_values = [part.strip().partition('=')[2] for key,value in event['headers'] if key.lower()=='cookie'
                          for part in value.split(';') if part.strip().partition('=')[0]==name]
            self.json_response(dict(request=event,
                cookie_ok=bool(session and session[0] in own_values),
                token_ok=bool(session and fields.get('csrf',[''])[0]==session[1])))
        elif url.path == '/si00/cookie':
            case = query.get('kind', ['root'])[0]
            values = dict(root='ROOT; Path=/', deep='DEEP; Path=/si00/deep/',
                          empty='; Path=/', deleted='deleted; Path=/',
                          expired='PAST; Path=/si00/expired/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
                          expired_root='PAST; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
                          short='SHORT; Path=/; Max-Age=1',
                          secure='SECURE; Path=/si00/secure/; Secure')
            if case not in values:
                self.respond(400)
            else:
                self.respond(200, b'SI00 cookie response', [('Set-Cookie', name + '=' + values[case])])
        elif url.path == '/si00/token':
            token = self.server.state.token(run)
            page = ('<form action="/si00/echo"><input name="si00_token" value="%s"></form>' % token).encode('ascii')
            self.respond(200, page, [('Content-Type', 'text/html'), ('Set-Cookie', name + '=MACRO; Path=/')])
        elif url.path == '/si00/start':
            self.respond(302, headers=[('Location', '/si00/deep/echo?run=' + run),
                                       ('Set-Cookie', name + '=REDIRECT; Path=/')])
        elif url.path == '/si00/action' and method == 'POST':
            sid,token=self.server.state.action(run)
            page=('<input name="csrfmiddlewaretoken" value="%s">' % token).encode('ascii')
            self.respond(200,page,[('Content-Type','text/html'),('Set-Cookie',name+'='+sid+'; Path=/')])
        else:
            self.respond(404)
        return True


class SessionServer(FixtureServer):
    def __init__(self, port, capture, cookie_name):
        self.state = SessionState(capture, cookie_name)
        try:
            socketserver.ThreadingTCPServer.__init__(self, ('127.0.0.1', port), SessionHandler)
        except BaseException:
            self.state.close()
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, choices=[18780, 18781, 18782], default=18780)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--tls-cert',type=Path)
    parser.add_argument('--tls-key',type=Path)
    args = parser.parse_args()
    config = json.loads((Path(__file__).resolve().parent / 'runtime/si00-wire-config.json').read_text())
    if not re.fullmatch(r'BP_SI00_WIRE_[a-f0-9]{12}', config['cookie_name']): raise ValueError('Invalid namespace')
    if args.port==18782 and not (args.tls_cert and args.tls_key): raise ValueError('Port18782 requires TLS')
    server = SessionServer(args.port, args.capture, config['cookie_name'])
    if args.tls_cert and args.tls_key:
        try:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.tls_cert,args.tls_key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
        except BaseException:
            server.server_close()
            server.state.close()
            raise
    print(json.dumps(dict(status='ready', fixture='BoberProxy-SI00', port=args.port,
                          cookie_name=config['cookie_name'])), flush=True)
    try: server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt: pass
    finally:
        server.server_close()
        server.state.close()


if __name__ == '__main__': main()
