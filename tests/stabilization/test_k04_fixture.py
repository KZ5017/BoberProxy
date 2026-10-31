"""Verify synthetic response data and byte capture independently of Burp."""
import base64
import tempfile
import threading
import unittest
from pathlib import Path

from probe_proxy import exchange, snapshot
from target_server import FixtureServer
from target_server_k04 import SessionHandler


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.server = FixtureServer(0, Path(self.directory.name) / 'capture.jsonl', SessionHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server.state.close()
        self.thread.join(2)
        self.directory.cleanup()

    def test_multiple_headers_and_invalid_lookalikes_are_served(self):
        reply = exchange('/k04/action?case=headers', target_port=self.port, proxy_port=None,
                         method='POST', headers=[('X-Bober-Test-Run', 'selfcheck')])
        headers = reply['headers']
        self.assertEqual(sum(name.lower() == 'set-cookie' for name, value in headers), 4)
        self.assertIn(('X-Set-Cookie-Info', 'fake=SHOULD_NOT_APPEAR'), headers)
        state = snapshot('selfcheck', self.port)
        self.assertEqual((state['action_count'], state['event_count']), (1, 1))

    def test_tenth_hop_deletes_cookie_and_keeps_token(self):
        reply = exchange('/k04/hop?case=chain10&hop=10&run=selfcheck', target_port=self.port, proxy_port=None)
        self.assertEqual(reply['status'], 200)
        self.assertIn(('Set-Cookie', 'sid=; Max-Age=0'), reply['headers'])
        self.assertIn(b'H10', base64.b64decode(reply['body_base64']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
