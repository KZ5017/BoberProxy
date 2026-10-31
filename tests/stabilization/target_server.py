"""Loopback-only HTTP/1.x fixture with exact incoming-byte capture (CPython 3).

The server accepts Content-Length requests, not chunked requests. This fixture
is deliberately separate from production code and does not modify Burp.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import socket
import socketserver
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HOST = "127.0.0.1"
DEFAULT_PORT = 18765
MAX_BODY = 2 * 1024 * 1024
MAX_HEADERS = 64 * 1024
RUN_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")


class FixtureState:
    def __init__(self, capture: Path):
        capture.parent.mkdir(parents=True, exist_ok=True)
        self.capture_path = capture
        self.capture = capture.open("a", encoding="utf-8", buffering=1)
        self.lock = threading.Lock()
        self.sequence = 0
        self.events: dict[str, list[dict]] = {}
        self.event_counts: dict[str, int] = {}
        self.actions: dict[str, int] = {}
        self.sessions: dict[str, tuple[str, str]] = {}

    def record(self, run: str, method: str, target: str,
               headers: list[tuple[str, str]], raw: bytes, body: bytes) -> dict:
        with self.lock:
            self.sequence += 1
            event = dict(sequence=self.sequence, time_ns=time.time_ns(), run=run,
                         method=method, target=target, headers=headers,
                         raw_base64=base64.b64encode(raw).decode("ascii"),
                         body_base64=base64.b64encode(body).decode("ascii"))
            # A bounded memory view; the full fixture capture remains on disk.
            recent = self.events.setdefault(run, [])
            self.event_counts[run] = self.event_counts.get(run, 0) + 1
            recent.append(event)
            if len(recent) > 200:
                del recent[:-200]
            self.capture.write(json.dumps(event, ensure_ascii=True) + "\n")
            return event

    def snapshot(self, run: str) -> dict:
        with self.lock:
            return dict(run=run, action_count=self.actions.get(run, 0),
                        event_count=self.event_counts.get(run, 0),
                        recent_events=list(self.events.get(run, [])),
                        session=self.sessions.get(run))

    def reset(self, run: str) -> None:
        with self.lock:
            self.events.pop(run, None)
            self.event_counts.pop(run, None)
            self.actions.pop(run, None)
            self.sessions.pop(run, None)
            self.capture.write(json.dumps(dict(control="reset", run=run)) + "\n")

    def action(self, run: str) -> tuple[str, str]:
        with self.lock:
            number = self.actions.get(run, 0) + 1
            self.actions[run] = number
            session = ("sid.%s.%d" % (run, number), "csrf.%s.%d" % (run, number))
            self.sessions[run] = session
            return session

    def close(self) -> None:
        self.capture.close()


class FixtureHandler(socketserver.StreamRequestHandler):
    def handle_extra_route(self, url, method, event, headers, body, run):
        return False

    def respond(self, status: int, body: bytes = b"", headers=()) -> None:
        reasons = {200: "OK", 204: "No Content", 302: "Found", 303: "See Other",
                   307: "Temporary Redirect", 308: "Permanent Redirect",
                   400: "Bad Request", 404: "Not Found", 413: "Content Too Large",
                   431: "Request Header Fields Too Large", 501: "Not Implemented"}
        lines = ["HTTP/1.1 %d %s" % (status, reasons.get(status, "Fixture")),
                 "Content-Length: %d" % len(body), "Connection: close"]
        lines.extend("%s: %s" % (key, value) for key, value in headers)
        self.wfile.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)

    def json_response(self, obj: dict) -> None:
        self.respond(200, json.dumps(obj, ensure_ascii=True).encode("ascii"),
                     [("Content-Type", "application/json")])

    def handle(self) -> None:
        self.connection.settimeout(5)
        try:
            self.handle_one()
        except (ValueError, UnicodeError):
            self.respond(400, b"Malformed fixture request")
        except (TimeoutError, ConnectionError, OSError):
            # Timeout/disconnect is a client outcome, not a server crash.
            return

    def handle_one(self) -> None:
        first = self.rfile.readline(8193)
        if not first:
            return
        if len(first) > 8192 or not first.endswith(b"\r\n"):
            self.respond(400)
            return
        pieces = first[:-2].decode("latin-1").split(" ")
        if len(pieces) != 3 or pieces[2] not in ("HTTP/1.0", "HTTP/1.1"):
            self.respond(400)
            return
        method, target, _ = pieces
        raw_headers = bytearray(first)
        headers = []
        while True:
            line = self.rfile.readline(MAX_HEADERS + 1)
            raw_headers.extend(line)
            if len(raw_headers) > MAX_HEADERS:
                self.respond(431)
                return
            if line == b"\r\n":
                break
            if not line or not line.endswith(b"\r\n") or b":" not in line:
                self.respond(400)
                return
            key, value = line[:-2].decode("latin-1").split(":", 1)
            headers.append((key, value.strip()))
        lower = {key.lower(): value for key, value in headers}
        if "transfer-encoding" in lower:
            self.respond(501, b"Fixture supports Content-Length only")
            return
        lengths = [value for key, value in headers if key.lower() == "content-length"]
        if len(lengths) > 1:
            self.respond(400, b"Duplicate Content-Length unsupported by fixture")
            return
        length = int(lengths[0]) if lengths else 0
        if not 0 <= length <= MAX_BODY:
            self.respond(413)
            return
        body = self.rfile.read(length)
        if len(body) != length:
            return
        raw = bytes(raw_headers) + body
        url = urlsplit(target)
        query = parse_qs(url.query, keep_blank_values=True)
        run = lower.get("x-bober-test-run", query.get("run", ["untagged"])[0])
        if not RUN_PATTERN.fullmatch(run):
            raise ValueError("Invalid fixture run tag")
        state = self.server.state
        if url.path == "/__control/events" and method == "GET":
            self.json_response(state.snapshot(query.get("run", [run])[0]))
            return
        if url.path == "/__control/reset" and method == "POST":
            state.reset(query.get("run", [run])[0])
            self.json_response(dict(reset=True))
            return
        if url.path == "/health":
            self.json_response(dict(fixture="BoberProxy-K00", status="ready", port=self.server.server_address[1]))
            return
        event = state.record(run, method, target, headers, raw, body)
        if self.handle_extra_route(url, method, event, lower, body, run):
            return
        if url.path in ("/echo", "/entry"):
            self.json_response(dict(request=event))
        elif url.path == "/workflow/action" and method == "POST":
            sid, token = state.action(run)
            page = ('<input name="csrfmiddlewaretoken" value="%s">' % token).encode("ascii")
            self.respond(200, page, [("Content-Type", "text/html"),
                                     ("Set-Cookie", "sid=%s; Path=/" % sid)])
        elif url.path == "/workflow/check":
            fields = parse_qs(body.decode("latin-1"), keep_blank_values=True) if body else query
            snapshot = state.snapshot(run)
            session = snapshot["session"]
            cookie = lower.get("cookie", "")
            self.json_response(dict(request=event, action_count=snapshot["action_count"],
                                    cookie_ok=bool(session and "sid=" + session[0] in cookie.split("; ")),
                                    token_ok=bool(session and fields.get("csrf", [""])[0] == session[1])))
        elif url.path == "/accept-then-close":
            state.action(run)
            # Intentionally no response, to detect unsafe automatic retries.
        elif url.path == "/redirect":
            location = query.get("to", ["/echo"])[0]
            status = int(query.get("code", ["302"])[0])
            if status not in (302, 303, 307, 308) or "\r" in location or "\n" in location:
                raise ValueError("Invalid redirect fixture")
            self.respond(status, headers=[("Location", location)])
        elif url.path == "/delay":
            delay = min(2000, max(0, int(query.get("ms", ["0"])[0])))
            time.sleep(delay / 1000)
            self.json_response(dict(delay_ms=delay, request=event))
        elif url.path == "/bytes":
            size = min(MAX_BODY, max(0, int(query.get("size", ["256"])[0])))
            self.respond(200, (bytes(range(256)) * ((size + 255) // 256))[:size],
                         [("Content-Type", "application/octet-stream")])
        elif url.path == "/empty":
            self.respond(204)
        else:
            self.respond(404, b"Unknown fixture route")


class FixtureServer(socketserver.ThreadingTCPServer):
    # Parallel Burp connections must not exhaust socketserver's default backlog5.
    request_queue_size = 128
    # Windows SO_REUSEADDR permits competing listeners on one test port.
    # A stale fixture must fail loudly instead of serving another revision.
    allow_reuse_address = not hasattr(socket, 'SO_EXCLUSIVEADDRUSE')
    daemon_threads = True
    block_on_close = True

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, port: int, capture: Path, handler_class=FixtureHandler):
        self.state = FixtureState(capture)
        try:
            super().__init__((HOST, port), handler_class)
        except BaseException:
            self.state.close()
            raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--capture", type=Path,
                        default=Path(__file__).parent / "runtime" / "requests.jsonl")
    args = parser.parse_args()
    server = FixtureServer(args.port, args.capture)
    print(json.dumps(dict(status="ready", host=HOST, port=server.server_address[1],
                          capture=str(args.capture.resolve()))), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.state.close()


if __name__ == "__main__":
    main()
