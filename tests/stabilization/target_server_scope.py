# -*- coding: utf-8 -*-
"""Owned TG05 loopback A/B(+TLS) fixture. Synthetic tagged runs only."""
import argparse, base64, json, re, socket, ssl, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, urlencode

class Fixture:
    def __init__(self, capture):
        self.lock=threading.RLock();self.runs={};self.capture=capture
    def state(self, kind, run):
        key=(kind,run)
        if key not in self.runs:
            self.runs[key]=dict(kind=kind,run=run,version=0,actions=0,checks=0,nexts=0,event_count=0,events=[],seeded=False)
        return self.runs[key]
    def values(self, state):
        return 'sid.%s.%s.%d'%(state['kind'],state['run'],state['version']), 'csrf.%s.%s.%d'%(state['kind'],state['run'],state['version'])
    def record(self, state, event):
        with self.lock:
            state['event_count']+=1
            if len(state['events'])<200:state['events'].append(event)
            with open(self.capture,'ab') as f:f.write((json.dumps(event,sort_keys=True)+'\n').encode())

class Server(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=128
    allow_reuse_address=True

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def parse_request(self):
        original=self.rfile;record=[]
        class Recording:
            def readline(self,*args):
                value=original.readline(*args);record.append(value);return value
        self.rfile=Recording()
        try:return BaseHTTPRequestHandler.parse_request(self)
        finally:
            self.rfile=original
            self.request_head=self.raw_requestline+b''.join(record)
    def send(self,status,body=b'',headers=()):
        self.send_response(status)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Connection','close')
        for k,v in headers:self.send_header(k,v)
        self.end_headers()
        try:self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError):pass
        self.close_connection=True
    def do_GET(self):self.handle_target()
    def do_POST(self):self.handle_target()
    def handle_target(self):
        parsed=urlsplit(self.path);query=parse_qs(parsed.query)
        if parsed.path=='/health':return self.send(200,b'TG05 READY')
        run=self.headers.get('X-Bober-TG') or query.get('run',[''])[0]
        if not re.fullmatch(r'tg-[A-Za-z0-9_-]{1,100}',run):return self.send(404,b'tag required')
        fixture=self.server.fixture;kind=self.server.kind
        with fixture.lock:state=fixture.state(kind,run)
        if parsed.path=='/control/state':
            with fixture.lock:body=json.dumps(state,sort_keys=True).encode()
            return self.send(200,body,[('Content-Type','application/json')])
        length=int(self.headers.get('Content-Length','0'))
        if not 0<=length<=1024*1024:return self.send(413)
        body=self.rfile.read(length)
        event=dict(kind=kind,run=run,method=self.command,target=self.path,
                   headers=list(self.headers.items()),raw_base64=base64.b64encode(self.request_head+body).decode(),
                   body_base64=base64.b64encode(body).decode(),monotonic=time.monotonic())
        fixture.record(state,event)
        with fixture.lock:
            if parsed.path=='/scope/seed':state['seeded']=True
            if parsed.path=='/scope/action':
                state['actions']+=1
                prior_sid,_=fixture.values(state)
                state['incoming_session_ok']=not state['seeded'] or ('sid='+prior_sid) in self.headers.get('Cookie','')
                state['version']+=1
            if parsed.path=='/scope/next':state['nexts']+=1;state['version']+=1
            if parsed.path=='/scope/check':state['checks']+=1
            sid,token=fixture.values(state)
        cookie=('Set-Cookie','sid='+sid+'; Path=/scope'+('; Secure' if kind=='T' else ''))
        html=('<html><input name="csrfmiddlewaretoken" value="'+token+'"> token="'+token+'"</html>').encode()
        mode=query.get('case',['normal'])[0]
        suffix='?'+urlencode(dict(run=run,case='normal'))
        if parsed.path=='/scope/action' and mode=='hold':time.sleep(.6)
        if parsed.path=='/scope/action' and mode=='close':
            self.close_connection=True
            try:self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            return
        if parsed.path=='/scope/action' and mode in ('relative','foreign','foreign-host','foreign-tls','outside-path','bad-location','non-http'):
            location=dict(relative='/scope/next'+suffix,
                          foreign='http://127.0.0.1:18811/scope/next'+suffix,
                          **{'foreign-host':'http://localhost:18810/scope/next'+suffix,
                             'foreign-tls':'https://127.0.0.1:18812/scope/next'+suffix,
                             'outside-path':'/outside'+suffix,
                             'bad-location':'http://[broken','non-http':'mailto:tg@example.test'})[mode]
            return self.send(302,html,[cookie,('Location',location),('Content-Type','text/html')])
        if parsed.path=='/scope/check':
            form=parse_qs(body.decode('ascii'))
            accepted=('sid='+sid) in self.headers.get('Cookie','') and form.get('csrf',[''])[0]==token
            return self.send(200 if accepted else 409,json.dumps(dict(accepted=accepted,kind=kind,run=run,actions=state['actions'],checks=state['checks'],nexts=state['nexts'],request=event)).encode(),[('Content-Type','application/json')])
        if parsed.path=='/scope/empty':return self.send(204)
        if parsed.path=='/scope/bytes':return self.send(200,bytes(range(256)),[('Content-Type','application/octet-stream')])
        return self.send(200,html,[cookie,('Content-Type','text/html')])

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--capture',required=True)
    parser.add_argument('--cert');parser.add_argument('--key')
    args=parser.parse_args()
    fixture=Fixture(args.capture);servers=[]
    try:
        for kind,port in [('A',18810),('B',18811)]+([('T',18812)] if args.cert and args.key else []):
            server=Server(('127.0.0.1',port),Handler);servers.append(server)
            server.fixture=fixture;server.kind=kind
            if kind=='T':
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(args.cert,args.key)
                server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            print('TG05 %s READY 127.0.0.1:%d'%(kind,port),flush=True)
        threading.Event().wait()
    finally:
        for server in servers:server.server_close()

if __name__=='__main__':main()
