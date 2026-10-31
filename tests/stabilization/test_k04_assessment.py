"""Guard against false acceptance by the traffic-assessment helper."""
import base64
import tempfile
import threading
import unittest
from pathlib import Path

from probe_k04_session import body_fields, cookie_map, run_case
from target_server import FixtureServer
from target_server_k04 import SessionHandler


class AssessmentTests(unittest.TestCase):
    def test_empty_cookie_is_distinct_from_absent(self):
        self.assertEqual(cookie_map(dict(headers=[('Cookie', 'sid=; other=x')]))['sid'], '')
        self.assertIsNone(cookie_map(dict(headers=[])).get('sid'))

    def test_form_parser_keeps_empty_and_high_byte_token(self):
        for token in (b'', b'\xff\x80'):
            event = dict(body_base64=base64.b64encode(b'csrf=' + token).decode())
            self.assertEqual(body_fields(event)['csrf'], [token.decode('latin-1')])

    def test_direct_unrewritten_request_cannot_pass_workflow_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            server = FixtureServer(0, Path(directory) / 'capture.jsonl', SessionHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report = run_case('seed', 'SEED', 'SEED', initial_sid='template', initial_token='c5rfm4rk3r',
                                  proxy_port=None, target_port=server.server_address[1])
                self.assertFalse(report['passed'])
                self.assertFalse(report['checks']['rt_target'])
                self.assertFalse(report['checks']['client_received_checkpage'])
            finally:
                server.shutdown()
                server.server_close()
                server.state.close()
                thread.join(2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
