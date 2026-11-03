# -*- coding: utf-8 -*-
"""CPython TG05 client/controller. One send per request; no traffic retry.

Only its scoped file-command acknowledgments may be polled. Run this controller
only against the loaded live TG05 entry; never alongside its standalone smoke.
"""
import base64, concurrent.futures, hashlib, http.client, json, os, socket, ssl, threading, time, uuid
from pathlib import Path
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[2]
RUNTIME=Path(__file__).resolve().parent/'runtime'
PORTS=dict(A=18810,B=18811,T=18812)
class Client:
    def __init__(self):
        self.session=json.loads((RUNTIME/'tg-control-session.json').read_text())
        self.source=hashlib.sha256((ROOT/'BoberProxy.py').read_bytes()).hexdigest()
        assert self.session['source_sha256']==self.source,'Loaded source mismatch'
    def command(self, action='state', **values):
        identifier=uuid.uuid4().hex
        row=dict(self.session,id=identifier,action=action,**values)
        path=RUNTIME/'tg-command.json'; temp=RUNTIME/('tg-command-'+identifier+'.tmp')
        temp.write_text(json.dumps(row)); os.replace(temp,path)
        until=time.monotonic()+12
        while time.monotonic()<until:
            try: ack=json.loads((RUNTIME/'tg-ack.json').read_text())
            except (OSError,ValueError): time.sleep(.03);continue
            if ack.get('id')==identifier and ack.get('instance')==self.session['instance']:
                assert ack['source_sha256']==self.source and ack['ok'],ack
                return ack['state']
            time.sleep(.03)
        raise TimeoutError('TG05 command acknowledgment timeout')
    def runid(self, label): return 'tg-'+label+'-'+uuid.uuid4().hex[:12]
    def request(self, run, kind='A', path=None, q=None, timeout=8, headers=()):
        port=PORTS[kind]; scheme='https' if kind=='T' else 'http'
        path=path or '/scope/entry?'+urlencode(dict(q=q,w=run))
        request_line=(('https' if kind=='T' else 'http')+'://127.0.0.1:%d'%port+path)
        with socket.create_connection(('127.0.0.1',8080),timeout) as sock:
            stream=sock
            if kind=='T':
                sock.sendall(('CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n'%(port,port)).encode())
                header=b''
                while not header.endswith(b'\r\n\r\n'): header+=sock.recv(1)
                assert b' 200 ' in header,header
                stream=ssl._create_unverified_context().wrap_socket(sock,server_hostname='127.0.0.1')
                request_line=path
            raw=('GET '+request_line+' HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Bober-TG: '%port+run+
                 '\r\nConnection: close\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers)+'\r\n').encode('ascii')
            start=time.monotonic();stream.sendall(raw)
            response=http.client.HTTPResponse(stream);response.begin();body=response.read()
            return dict(status=response.status,headers=response.getheaders(),body=body.decode('latin-1'),
                        body_base64=base64.b64encode(body).decode(),elapsed=time.monotonic()-start)
    def target(self,run,kind='A'):
        cls=http.client.HTTPSConnection if kind=='T' else http.client.HTTPConnection
        options=dict(context=ssl._create_unverified_context()) if kind=='T' else {}
        conn=cls('127.0.0.1',PORTS[kind],timeout=3,**options)
        try:
            conn.request('GET','/control/state?'+urlencode(dict(run=run)))
            response=conn.getresponse(); assert response.status==200
            return json.loads(response.read())
        finally:conn.close()
    def settle(self,timeout=4):
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            state=self.command()
            if not state['owner'] and not state['waiting'] and not state['records']:return state
            time.sleep(.05)
        raise AssertionError(('Session did not drain',state))

def save_report(path, report):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2,ensure_ascii=True)
