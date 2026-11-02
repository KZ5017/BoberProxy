"""Direct socket checks for the new K11 fixture; does not use Burp."""
import base64
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import time
import unittest
from probe_proxy import exchange, snapshot
from target_server_k11 import K11Server


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='BoberProxy-k11-fixture-')
        self.server=K11Server(0,Path(self.temp.name)/'capture.jsonl')
        self.port=self.server.server_address[1]
        self.worker=threading.Thread(target=self.server.serve_forever,kwargs=dict(poll_interval=.01),daemon=True)
        self.worker.start()
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.server.state.close()
        self.worker.join(2); self.temp.cleanup()
    def send(self,path,run='k11-fixture',**kwargs):
        return exchange(path,proxy_port=None,target_port=self.port,headers=[('X-Bober-Test-Run',run)],**kwargs)
    def test_relative_redirect_rotates_final_state_without_extra_action(self):
        self.assertEqual(self.send('/k11/redirect/start',method='POST')['status'],302)
        self.assertEqual(self.send('/k11/redirect/next')['status'],200)
        data=snapshot('k11-fixture',self.port)
        self.assertEqual(data['event_count'],2); self.assertEqual(data['action_count'],1)
        self.assertTrue(data['session'][1].endswith('.final'))
    def test_hops_and_loop_are_explicit_finite_individual_requests(self):
        for path in ('/k11/loop','/k11/hops/0','/k11/hops/10'):
            self.assertEqual(self.send(path)['status'],302)
    def test_controlled_hold_and_raw_capture(self):
        run='k11-held-fixture'
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(self.send,'/k11/held-action',run,method='POST',body=b'one=%252F+%2B')
            end=time.monotonic()+2
            while time.monotonic()<end:
                data=exchange('/k11/control?case='+run,proxy_port=None,target_port=self.port)['json']
                if data['entered']: break
                time.sleep(.01)
            self.assertTrue(data['entered'])
            exchange('/k11/control?op=release&case='+run,proxy_port=None,target_port=self.port)
            self.assertEqual(future.result()['status'],200)
        observed=snapshot(run,self.port)
        self.assertEqual(observed['event_count'],1)
        self.assertEqual(observed['action_count'],1)
        self.assertEqual(base64.b64decode(observed['recent_events'][0]['body_base64']),b'one=%252F+%2B')
    def test_slow_action_is_counted_once_before_delay(self):
        began=time.monotonic()
        self.assertEqual(self.send('/k11/slow-action',method='POST')['status'],200)
        self.assertGreaterEqual(time.monotonic()-began,.2)
        self.assertEqual(snapshot('k11-fixture',self.port)['action_count'],1)


if __name__=='__main__': unittest.main(verbosity=2)
