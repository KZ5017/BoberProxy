"""A gate must hold a real response and capture the request exactly once."""
import base64
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from probe_proxy import exchange
from target_server_k06 import create_server


class FixtureTests(unittest.TestCase):
    def test_gated_action_and_real_checkpage(self):
        server = create_server(0, Path(__file__).parent / 'runtime/k06-selftest.jsonl')
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        def direct(path, **kw):
            return exchange(path, target_port=port, proxy_port=None, **kw)
        try:
            direct('/k06/control?op=arm&case=SELF&step=action')
            with ThreadPoolExecutor(1) as pool:
                future = pool.submit(direct, '/k06/action?case=SELF', method='POST', body=b'one=%252F+%2B')
                try:
                    end = time.monotonic() + 2
                    while time.monotonic() < end:
                        stages = direct('/k06/control?op=events')['json']['stages']
                        if stages:
                            break
                        time.sleep(0.005)
                    self.assertEqual(len(stages), 1)
                    self.assertEqual(stages[0]['stage'], 'received')
                    self.assertEqual(base64.b64decode(stages[0]['event']['body_base64']), b'one=%252F+%2B')
                    self.assertFalse(future.done())
                finally:
                    direct('/k06/control?op=release&case=SELF&step=action')
                response = future.result(3)
                self.assertIn(('Set-Cookie', 'sid=K06_SELF'), response['headers'])
            checked = direct('/k06/check?case=SELF', method='POST', body=b'csrf=K06_SELF',
                             headers=[('Cookie', 'sid=K06_SELF')])['json']
            self.assertTrue(checked['cookie_ok'] and checked['token_ok'])
        finally:
            for gate in server.state.gates.values():
                gate.set()
            server.shutdown()
            server.server_close()
            thread.join(2)
            server.state.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
