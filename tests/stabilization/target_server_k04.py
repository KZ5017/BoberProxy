"""Loopback-only K04 cookie/CSRF cases, using the byte-capturing fixture."""
import argparse
import json
from pathlib import Path
from urllib.parse import parse_qs

from target_server import FixtureHandler, FixtureServer


PORT = 18769
CASES = {
    'seed': (['sid=SEED'], 'SEED'),
    'deleted-prefix': (['sid=deletedButValid'], 'PREFIX'),
    'deleted-literal': (['sid=deleted'], 'DELETED'),
    'empty-value': (['sid='], 'EMPTYCOOKIE'),
    'max-zero': (['sid=old; Max-Age=0'], 'ZERO'),
    'readd': (['sid=READD'], 'READD'),
    'max-negative': (['sid=old; Max-Age=-5'], 'NEG'),
    'expires-past': (['sid=old; Expires=Wed, 09 Jun 2021 10:18:14 GMT'], 'PAST'),
    'precedence-positive': (['sid=POS; Max-Age=60; Expires=Wed, 09 Jun 2021 10:18:14 GMT'], 'POS'),
    'precedence-delete': (['sid=old; Max-Age=0; Expires=Wed, 09 Jun 2099 10:18:14 GMT'], 'PREDELETE'),
    'invalid-age-past': (['sid=old; Max-Age=bad; Expires=Wed, 09 Jun 2021 10:18:14 GMT'], 'BADAGE'),
    'invalid-expires': (['sid=INVALID_DATE; Expires=Wed, 31 Feb 2021 10:18:14 GMT'], 'BADDATE'),
    'headers': (['sid=HEADERS', 'multi=SECOND', 'malformed', '=bad'], 'HEADERS'),
    'no-match': ([], None),
    'empty-token': ([], ''),
    'positive-short': (['sid=SHORT; Max-Age=1'], 'SHORT'),
    'high-bytes': (['sid=\xff\x80'], '\xff\x80'),
    'clear-control': ([], None),
}


class SessionHandler(FixtureHandler):
    def handle_extra_route(self, url, method, event, headers, body, run):
        if not url.path.startswith('/k04/'):
            return False
        query = parse_qs(url.query, keep_blank_values=True)
        case = query.get('case', ['seed'])[0]
        if url.path == '/k04/check':
            self.json_response(dict(request=event))
            return True
        if url.path not in ('/k04/action', '/k04/passive', '/k04/hop'):
            self.respond(404)
            return True
        if url.path == '/k04/action':
            self.server.state.action(run)
        if case in ('chain10', 'chain11'):
            hop = int(query.get('hop', ['0'])[0])
            limit = 10 if case == 'chain10' else 11
            if not 0 <= hop <= 11:
                self.respond(400)
                return True
            cookies = ['sid=H%d' % hop] if hop < 10 else ['sid=; Max-Age=0']
            token = 'H%d' % hop
            status = 302 if hop < limit else 200
            extra = [('Location', '/k04/hop?case=%s&hop=%d&run=%s' % (case, hop + 1, run))] if status == 302 else []
        elif case in CASES:
            cookies, token = CASES[case]
            status, extra = 200, []
        else:
            self.respond(400, b'Unknown K04 case')
            return True
        extra += [('Set-Cookie', cookie) for cookie in cookies]
        extra += [('Content-Type', 'text/html; charset=iso-8859-1')]
        if case == 'headers':
            extra += [('X-Set-Cookie-Info', 'fake=SHOULD_NOT_APPEAR'), ('Set-Cookie2', 'fake2=NO')]
        page = ('<input name="csrfmiddlewaretoken" value="%s">' % token).encode('latin-1') if token is not None else b'no csrf field'
        self.respond(status, page, extra)
        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--capture', type=Path, default=Path(__file__).parent / 'runtime/k04-requests.jsonl')
    args = parser.parse_args()
    server = FixtureServer(args.port, args.capture, handler_class=SessionHandler)
    print(json.dumps(dict(status='ready', fixture='K04', port=server.server_address[1])), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.state.close()


if __name__ == '__main__':
    main()
