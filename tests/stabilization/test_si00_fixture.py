"""Finite direct loopback self-check of the new SI00 fixture, never Burp."""
import hashlib
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from probe_proxy import exchange, snapshot
from target_server_si00 import SessionServer


class FixtureTests(unittest.TestCase):
    def setUp(self):
        runtime=Path(__file__).resolve().parent/'runtime'
        self.temporary=tempfile.TemporaryDirectory(prefix='si00-fixture-selftest-',dir=runtime)
        self.path=Path(self.temporary.name).resolve()
        self.assertIn(runtime.resolve(),self.path.parents)
        self.name='BP_SI00_WIRE_012345abcdef'
        self.server=SessionServer(0,self.path/'capture.jsonl',self.name)
        self.port=self.server.server_address[1]
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.02},daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown()
        self.thread.join(3)
        self.server.server_close()
        self.server.state.close()
        self.temporary.cleanup()
    def request(self,path,**kw): return exchange(path,target_port=self.port,proxy_port=None,**kw)
    def test_health_identifies_namespace(self):
        self.assertEqual(self.request('/si00/health?run=si00-health')['json']['cookie_name'],self.name)
    def test_unknown_cookie_value_is_not_captured_or_returned(self):
        reply=self.request('/si00/echo?run=si00-private',headers=[('Cookie',self.name+'=OWN; OTHER=DO_NOT_KEEP')])
        self.assertEqual(reply['json']['request']['other_cookie_count'],1)
        self.assertNotIn('DO_NOT_KEEP',json.dumps(reply))
        self.assertNotIn('DO_NOT_KEEP',(self.path/'capture.jsonl').read_text())
    def test_raw_query_and_once_counter(self):
        path='/si00/echo?run=si00-query&value=%252F+%2B'
        self.request(path)
        observed=snapshot('si00-query',self.port)
        self.assertEqual(observed['event_count'],1)
        self.assertEqual(observed['recent_events'][0]['target'],path)
        self.assertEqual(observed['action_count'],0)
    def test_cookie_attributes_and_token_change(self):
        reply=self.request('/si00/cookie?run=si00-cookie&kind=secure')
        self.assertTrue(any(key.lower()=='set-cookie' and 'Secure' in value for key,value in reply['headers']))
        first=self.request('/si00/token?run=si00-token')['body_base64']
        second=self.request('/si00/token?run=si00-token')['body_base64']
        self.assertNotEqual(first,second)
        self.assertEqual(snapshot('si00-token',self.port)['action_count'],0)
    def test_actual_request_hash(self):
        raw=b'GET /si00/echo?run=si00-hash HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
        with socket.create_connection(('127.0.0.1',self.port),timeout=2) as conn:
            conn.sendall(raw)
            while conn.recv(4096): pass
        event=snapshot('si00-hash',self.port)['recent_events'][0]
        self.assertEqual(event['request_sha256'],hashlib.sha256(raw).hexdigest())
    def test_workflow_cookie_token_and_action_once(self):
        run='si00-workflow'
        first=self.request('/si00/action?run='+run,method='POST',body=b'one=RAW')
        observed=snapshot(run,self.port)
        self.assertEqual(observed['action_count'],1)
        sid,token=observed['session']
        final=self.request('/si00/check?run='+run,method='POST',body=('csrf='+token).encode('ascii'),
                           headers=[('Cookie',self.name+'='+sid)])
        self.assertTrue(final['json']['cookie_ok'] and final['json']['token_ok'])
        self.assertEqual(snapshot(run,self.port)['event_count'],2)
    def test_root_expiration_and_short_lifetime_headers(self):
        response=self.request('/si00/cookie?run=si00-expired&kind=expired_root')
        header=next(value for key,value in response['headers'] if key.lower()=='set-cookie')
        self.assertIn('Path=/;',header)
        self.assertIn('Max-Age=0',header)
        response=self.request('/si00/cookie?run=si00-short&kind=short')
        self.assertTrue(any(key.lower()=='set-cookie' and 'Max-Age=1' in value for key,value in response['headers']))


if __name__=='__main__': unittest.main(verbosity=2)
