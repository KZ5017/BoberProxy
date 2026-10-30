"""Validate the redirect fixture before treating its counters as evidence."""
import threading
import unittest
from pathlib import Path

from probe_proxy import exchange, snapshot
from target_server import FixtureServer
from target_server_k03 import RedirectHandler, state_values


class RedirectFixtureTests(unittest.TestCase):
    def setUp(self):
        self.server = FixtureServer(0, Path(__file__).parent / 'runtime/k03-selftest.jsonl', RedirectHandler)
        self.server.other_port = 18767
        self.server.tls_port = 18768
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server.state.close()
        self.thread.join(2)

    def test_relative_route_rotates_cookie_and_token_and_counts_only_post(self):
        run = 'k03-fixture-relative'
        headers = [('X-Bober-Test-Run', run)]
        first = exchange('/k03/a/start?case=relative', method='POST', headers=headers, target_port=self.port, proxy_port=None)
        self.assertEqual(first['status'], 302)
        self.assertIn(('Location', 'next?case=relative&hop=1&run=' + run), first['headers'])
        # Production intentionally drops the tracing header on redirect GETs.
        location = dict(first['headers'])['Location']
        last = exchange('/k03/a/' + location, target_port=self.port, proxy_port=None)
        self.assertEqual(last['status'], 200)
        self.assertEqual(snapshot(run, self.port)['event_count'], 2)
        sid, token = state_values(run, 1)
        result = exchange('/k03/check', method='POST', body=('csrf=%s&one=relative' % token).encode(),
                          headers=headers + [('Cookie', 'sid=' + sid)], target_port=self.port, proxy_port=None)
        self.assertTrue(result['json']['token_ok'])
        self.assertTrue(result['json']['cookie_ok'])
        self.assertEqual(snapshot(run, self.port)['action_count'], 1)

    def test_chain_last_response_and_limit_input_are_distinct(self):
        for case, expected in (('chain10', 200), ('chain11', 302)):
            response = exchange('/k03/a/next?case=%s&hop=10' % case, target_port=self.port, proxy_port=None)
            self.assertEqual(response['status'], expected)

    def test_invalid_location_is_not_followed_by_the_fixture(self):
        response = exchange('/k03/a/start?case=invalid', method='POST', target_port=self.port, proxy_port=None,
                            headers=[('X-Bober-Test-Run', 'k03-fixture-invalid')])
        self.assertEqual(response['status'], 302)
        self.assertIn(('Location', 'http://127.0.0.1:65536/invalid?run=k03-fixture-invalid'), response['headers'])
        self.assertEqual(snapshot('k03-fixture-invalid', self.port)['event_count'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
