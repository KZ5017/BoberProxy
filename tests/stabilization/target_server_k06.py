"""Loopback K06 fixture: exact bytes plus controllable response gates."""
import argparse
import json
import re
import threading
from pathlib import Path
from urllib.parse import parse_qs
from target_server import FixtureHandler, FixtureServer

PORT = 18770
LABEL = re.compile(r'^[A-Za-z0-9_.-]{1,80}$')


class Handler(FixtureHandler):
    def handle_extra_route(self, url, method, event, headers, body, run):
        if not url.path.startswith('/k06/'):
            return False
        state = self.server.state
        query = parse_qs(url.query, keep_blank_values=True)
        case = query.get('case', [''])[0]
        if url.path == '/k06/control':
            op = query.get('op', ['events'])[0]
            if op == 'health':
                self.json_response(dict(fixture='K06-gated-v1', port=self.server.server_address[1]))
            elif op == 'events':
                with state.gate_lock:
                    snapshot = list(state.stages)
                self.json_response(dict(stages=snapshot))
            elif op in ('arm', 'release') and LABEL.fullmatch(case):
                step = query.get('step', [''])[0]
                if step not in ('action', 'check'):
                    raise ValueError('Unknown gate step')
                key = (case, step)
                with state.gate_lock:
                    if op == 'arm':
                        if key in state.gates or len(state.gates) >= 128:
                            raise ValueError('Duplicate/full gate')
                        state.gates[key] = threading.Event()
                    else:
                        if key not in state.gates:
                            raise ValueError('Unknown gate')
                        state.gates[key].set()
                self.json_response(dict(ok=True, op=op, case=case, step=step))
            else:
                raise ValueError('Invalid control operation')
            return True
        if not LABEL.fullmatch(case):
            raise ValueError('Invalid K06 case')
        step = url.path.rsplit('/', 1)[-1]
        if step not in ('action', 'check', 'check-alt', 'passive'):
            self.respond(404)
            return True
        if step != 'passive' and method != 'POST':
            raise ValueError('Template must POST')
        fields = parse_qs(body.decode('latin-1'), keep_blank_values=True)
        observation = dict(case=case, step=step, stage='received', event=event,
                           cookie=headers.get('cookie', ''), csrf=fields.get('csrf', [None])[0])
        with state.gate_lock:
            state.stages.append(observation)
            gate = state.gates.get((case, step))
        if gate is not None and not gate.wait(25):
            with state.gate_lock:
                state.stages.append(dict(case=case, step=step, stage='gate-timeout'))
            self.respond(500, b'K06 fixture gate timed out')
            return True
        value = 'K06_' + case
        if step in ('check', 'check-alt'):
            cookie_ok = 'sid=' + value in [part.strip() for part in headers.get('cookie', '').split(';')]
            token_ok = fields.get('csrf') == [value]
            value = 'K06_FINAL_' + case
            page = json.dumps(dict(case=case, step=step, cookie_ok=cookie_ok, token_ok=token_ok,
                csrf_field="<input name='csrfmiddlewaretoken' value='%s'>" % value)).encode('ascii')
        else:
            page = ('<input name="csrfmiddlewaretoken" value="%s">' % value).encode('ascii')
        with state.gate_lock:
            state.stages.append(dict(case=case, step=step, stage='responding'))
        self.respond(200, page, [('Content-Type', 'text/html'), ('Set-Cookie', 'sid=' + value)])
        return True


def create_server(port, capture):
    server = FixtureServer(port, capture, Handler)
    server.state.gate_lock = threading.Lock()
    server.state.gates = {}
    server.state.stages = []
    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--capture', type=Path, default=Path(__file__).parent / 'runtime/k06-requests.jsonl')
    args = parser.parse_args()
    server = create_server(args.port, args.capture)
    print(json.dumps(dict(fixture='K06-gated-v1', port=server.server_address[1])), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        for gate in server.state.gates.values():
            gate.set()
        server.server_close()
        server.state.close()


if __name__ == '__main__':
    main()
