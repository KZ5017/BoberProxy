"""Verify wire capture and fixture behavior before trusting Burp results."""
from __future__ import annotations

import base64
import http.client
import json
import socket
import threading
import unittest
from pathlib import Path

from probe_proxy import exchange, snapshot
from target_server import FixtureServer


class FixtureWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FixtureServer(0, Path(__file__).parent / "runtime" / "selftest.jsonl")
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
        cls.server.state.close()

    def send_raw(self, raw):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as conn:
            conn.sendall(raw)
            response = http.client.HTTPResponse(conn)
            response.begin()
            return response.status, response.read()

    def test_capture_is_exact_including_header_case_and_binary_body(self):
        body = bytes(range(256))
        raw = (b"POST /echo?q=%252F+%2B HTTP/1.1\r\nHoSt: fixture\r\n"
               b"X-Bober-Test-Run: fixture-raw\r\nContent-Length: 256\r\n\r\n" + body)
        status, content = self.send_raw(raw)
        event = json.loads(content)["request"]
        self.assertEqual(status, 200)
        self.assertEqual(base64.b64decode(event["raw_base64"]), raw)
        self.assertEqual(base64.b64decode(event["body_base64"]), body)

    def test_session_check_needs_the_action_cookie_and_token(self):
        run = "fixture-session"
        headers = [("X-Bober-Test-Run", run)]
        exchange("/workflow/action", method="POST", body=b"one=ONE&two=TWO", headers=headers,
                 target_port=self.port, proxy_port=None)
        state = snapshot(run, self.port)
        sid, token = state["session"]
        bad = exchange("/workflow/check", method="POST", body=b"csrf=WRONG", headers=headers,
                       target_port=self.port, proxy_port=None)["json"]
        good = exchange("/workflow/check", method="POST", body=("csrf=" + token).encode("ascii"),
                        headers=headers + [("Cookie", "sid=" + sid)],
                        target_port=self.port, proxy_port=None)["json"]
        self.assertEqual(state["action_count"], 1)
        self.assertFalse(bad["token_ok"])
        self.assertFalse(bad["cookie_ok"])
        self.assertTrue(good["token_ok"])
        self.assertTrue(good["cookie_ok"])

    def test_unsupported_chunked_capture_is_explicitly_rejected(self):
        status, _ = self.send_raw(b"POST /echo HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        self.assertEqual(status, 501)

    def test_connection_close_after_accept_is_counted_once(self):
        with self.assertRaises(http.client.RemoteDisconnected):
            exchange("/accept-then-close", method="POST", body=b"ONE",
                     headers=[("X-Bober-Test-Run", "fixture-close")],
                     target_port=self.port, proxy_port=None)
        self.assertEqual(snapshot("fixture-close", self.port)["action_count"], 1)

    def test_control_queries_are_not_application_events(self):
        run = "fixture-control"
        exchange("/__control/reset?run=" + run, method="POST", target_port=self.port, proxy_port=None)
        self.assertEqual(snapshot(run, self.port)["recent_events"], [])
        self.assertEqual(snapshot(run, self.port)["action_count"], 0)
        self.assertEqual(snapshot(run, self.port)["event_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
