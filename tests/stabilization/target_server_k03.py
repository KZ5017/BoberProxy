"""Two loopback targets for K03 redirects and independent operation counts."""
from __future__ import annotations

import argparse
import json
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs

from target_server import FixtureHandler, FixtureServer


def state_values(run: str, hop: int):
    return 'sid.%s.h%d' % (run, hop), 'csrf.%s.h%d' % (run, hop)


class RedirectHandler(FixtureHandler):
    def handle_extra_route(self, url, method, event, headers, body, run):
        if not url.path.startswith('/k03/'):
            return False
        event['tls_version'] = self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else None
        query = parse_qs(url.query, keep_blank_values=True)
        case = query.get('case', ['relative'])[0]
        hop = int(query.get('hop', ['0'])[0])
        if not 0 <= hop <= 20:
            self.respond(400)
            return True
        if url.path == '/k03/check':
            fields = parse_qs(body.decode('latin-1'), keep_blank_values=True)
            case = fields.get('one', ['relative'])[0]
            expected_hop = 0 if case == 'off' else (10 if case == 'chain10' else 1)
            sid, token = state_values(run, expected_hop)
            self.json_response(dict(request=event, cookie_ok=('sid=' + sid) in headers.get('cookie', '').split('; '),
                                    token_ok=fields.get('csrf', [''])[0] == token,
                                    expected_hop=expected_hop, expected_token=token))
            return True
        if url.path == '/k03/a/start':
            self.server.state.action(run)
            hop = 0
        elif url.path != '/k03/a/next':
            self.respond(404)
            return True
        if case == 'slow-rt' and hop == 0 or case == 'slow-hop' and hop == 1:
            time.sleep(0.20)  # finite; the native API's inability to abort is observable
        sid, token = state_values(run, hop)
        page = ('<input name="csrfmiddlewaretoken" value="%s">' % token).encode('ascii')
        cookies = [('Set-Cookie', 'sid=%s; Path=/' % sid), ('Content-Type', 'text/html')]
        count = 10 if case == 'chain10' else (11 if case == 'chain11' else 1)
        if hop >= count and case != 'loop':
            self.respond(200, page, cookies)
            return True
        if case == 'invalid':
            location = 'http://127.0.0.1:65536/invalid'
        elif case == 'loop' and hop:
            location = '?case=loop&hop=1'
        elif case == 'cross-port':
            location = 'http://127.0.0.1:%d/k03/a/next?case=cross-port&hop=1' % self.server.other_port
        elif case == 'cross-scheme':
            location = 'https://127.0.0.1:%d/k03/a/next?case=cross-scheme&hop=1' % self.server.tls_port
        else:
            location = ('next' if hop == 0 else '') + '?case=%s&hop=%d' % (case, hop + 1)
        # Redirect GETs intentionally drop the synthetic tracing header along
        # with other non-preserved headers. Carry the run tag in the URL.
        location += ('&' if '?' in location else '?') + 'run=' + run
        self.respond(302, page, cookies + [('Location', location)])
        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=18766)
    parser.add_argument('--other-port', type=int, default=18767)
    parser.add_argument('--tls-port', type=int, default=18768)
    parser.add_argument('--tls-cert', type=Path)
    parser.add_argument('--tls-key', type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent / 'runtime'
    servers, threads = [], []
    try:
        specifications = [(args.port, args.other_port, None), (args.other_port, args.port, None)]
        if args.tls_cert and args.tls_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.tls_cert, args.tls_key)
            specifications.append((args.tls_port, args.port, context))
        for port, other, context in specifications:
            server = FixtureServer(port, directory / ('k03-requests-%d.jsonl' % port), RedirectHandler)
            server.other_port = other
            server.tls_port = args.tls_port
            if context is not None:
                server.socket = context.wrap_socket(server.socket, server_side=True)
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        print(json.dumps(dict(status='ready', host='127.0.0.1', ports=[s.server_address[1] for s in servers],
                              tls=bool(args.tls_cert and args.tls_key))), flush=True)
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
            server.state.close()
        for thread in threads:
            thread.join(2)


if __name__ == '__main__':
    main()
