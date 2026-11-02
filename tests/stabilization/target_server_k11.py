"""K11 loopback fixture; full byte capture, rotating state and finite gates."""
import argparse
from pathlib import Path
import threading
import time
from urllib.parse import parse_qs
from target_server import FixtureHandler, FixtureServer


class K11Handler(FixtureHandler):
    def session_page(self, run, suffix, status=200, location=None):
        state = self.server.state
        with state.lock:
            sid, token = 'sid.'+run+'.'+suffix, 'csrf.'+run+'.'+suffix
            state.sessions[run] = (sid,token)
        body = ('<input name="csrfmiddlewaretoken" value="%s">' % token).encode('ascii')
        headers = [('Content-Type','text/html'),('Set-Cookie','sid='+sid+'; Path=/')]
        if location is not None: headers.append(('Location',location))
        self.respond(status,body,headers)

    def handle_extra_route(self, url, method, event, headers, body, run):
        state = self.server.state
        if url.path == '/k11/control':
            query=parse_qs(url.query)
            case=query.get('case',[''])[0]
            with self.server.gate_lock:
                gate=self.server.gates.setdefault(case,threading.Event())
                if query.get('op')==['release']: gate.set()
                entered=case in self.server.entered
            self.json_response(dict(entered=entered,released=gate.is_set()))
            return True
        if url.path in ('/k11/held-action','/k11/slow-action'):
            state.action(run)
            if url.path == '/k11/held-action':
                with self.server.gate_lock:
                    gate = self.server.gates.setdefault(run,threading.Event())
                    self.server.entered.add(run)
                gate.wait(5)  # Always finite; no gate can strand the fixture.
            else: time.sleep(.2)
            self.session_page(run,'action')
            return True
        if url.path == '/k11/redirect/start':
            state.action(run)
            self.session_page(run,'start',302,'next?run='+run)
            return True
        if url.path == '/k11/redirect/next':
            self.session_page(run,'final')
            return True
        if url.path == '/k11/loop':
            if method=='POST': state.action(run)
            self.session_page(run,'loop',302,'/k11/loop?run='+run)
            return True
        if url.path.startswith('/k11/hops/'):
            hop = int(url.path.rsplit('/',1)[1])
            if method=='POST': state.action(run)
            self.session_page(run,str(hop),302,'/k11/hops/%d?run=%s' % (hop+1,run))
            return True
        return False

class K11Server(FixtureServer):
    request_queue_size = 256
    def __init__(self, port, capture):
        self.gate_lock, self.gates, self.entered = threading.Lock(),{},set()
        super().__init__(port,capture,K11Handler)


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=18790)
    parser.add_argument('--capture',type=Path,required=True)
    args=parser.parse_args()
    server=K11Server(args.port,args.capture)
    print('K11_TARGET READY 127.0.0.1:%d' % server.server_address[1],flush=True)
    try: server.serve_forever(poll_interval=.1)
    except KeyboardInterrupt: pass
    finally:
        server.server_close()
        server.state.close()
