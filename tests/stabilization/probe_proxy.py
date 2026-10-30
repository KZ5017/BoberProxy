"""Send explicitly via Burp, never via environment proxy/bypass settings."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import socket
import time
import uuid
from pathlib import Path


def exchange(path: str, *, method="GET", body=b"", headers=(), target_port=18765,
             proxy_port: int | None = 8080, timeout=5) -> dict:
    if not path.startswith("/") or any(c in path for c in "\r\n"):
        raise ValueError("Fixture path required")
    endpoint = ("127.0.0.1", proxy_port if proxy_port is not None else target_port)
    request_target = "http://127.0.0.1:%d%s" % (target_port, path) if proxy_port is not None else path
    lines = ["%s %s HTTP/1.1" % (method, request_target),
             "Host: 127.0.0.1:%d" % target_port, "Connection: close"]
    for key, value in headers:
        if any(c in key + value for c in "\r\n"):
            raise ValueError("Invalid fixture header")
        lines.append("%s: %s" % (key, value))
    if body or method == "POST":
        lines.append("Content-Length: %d" % len(body))
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    started = time.perf_counter()
    with socket.create_connection(endpoint, timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(raw)
        response = http.client.HTTPResponse(conn)
        response.begin()
        content = response.read()
        result = dict(status=response.status, headers=response.getheaders(),
                      body_base64=base64.b64encode(content).decode("ascii"),
                      seconds=round(time.perf_counter() - started, 6))
    try:
        result["json"] = json.loads(content)
    except (ValueError, UnicodeError):
        pass
    return result


def snapshot(run: str, target_port: int) -> dict:
    return exchange("/__control/events?run=" + run, target_port=target_port,
                    proxy_port=None)["json"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["health", "passive", "rt", "checkpage"], default="passive")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--target-port", type=int, default=18765)
    parser.add_argument("--direct", action="store_true", help="Fixture self-check only, no Burp integration")
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    via = None if args.direct else args.proxy_port
    if args.scenario == "health":
        response = exchange("/health", target_port=args.target_port, proxy_port=via, timeout=args.timeout)
        print(json.dumps(response, indent=2))
        return 0 if response["status"] == 200 else 1
    if args.direct and args.scenario != "passive":
        parser.error("RT/CheckPage need the loaded and configured Burp extension")
    run = "k00-" + uuid.uuid4().hex[:12] if args.scenario == "passive" else "k00-workflow"
    exchange("/__control/reset?run=" + run, method="POST", proxy_port=None, target_port=args.target_port)
    transport_error = None
    try:
        response = exchange("/entry?q=%252F+%2B&w=TWO", headers=[("X-Bober-Test-Run", run)],
                            target_port=args.target_port, proxy_port=via, timeout=args.timeout)
    except (OSError, ValueError, http.client.HTTPException) as error:
        # Never retry a possibly accepted operation. Read target evidence directly.
        transport_error = dict(type=type(error).__name__, message=str(error))
        response = dict(status=None, seconds=None)
    observed = snapshot(run, args.target_port)
    events = observed["recent_events"]
    checks = {"http_200": response["status"] == 200,
              "no_transport_error": transport_error is None}
    if args.scenario == "passive":
        checks.update(one_request=len(events) == 1,
                      raw_query_preserved=bool(events and events[0]["target"] == "/entry?q=%252F+%2B&w=TWO"),
                      original_method=bool(events and events[0]["method"] == "GET"))
    else:
        checks.update(action_once=observed["action_count"] == 1,
                      action_payload=bool(events and base64.b64decode(events[0]["body_base64"]) == b"one=%252F+%2B&two=TWO"))
        if args.scenario == "rt":
            checks["one_action_only"] = len(events) == 1 and events[0]["target"] == "/workflow/action"
        else:
            session = observed.get("session")
            expected_body = (("csrf=" + session[1]).encode("ascii") + b"&one=%252F+%2B&two=TWO") if session else None
            checks.update(two_steps=len(events) == 2,
                          cookie_updated=response.get("json", {}).get("cookie_ok") is True,
                          csrf_updated=response.get("json", {}).get("token_ok") is True,
                          checkpage_last=bool(events and events[-1]["target"] == "/workflow/check"),
                          checkpage_method=bool(events and events[-1]["method"] == "POST"),
                          checkpage_payload=bool(events and expected_body is not None and
                                                 base64.b64decode(events[-1]["body_base64"]) == expected_body))
    root = Path(__file__).resolve().parents[2]
    report = dict(kind="direct-fixture-self-check" if args.direct else "external-burp-traffic",
                  scenario=args.scenario, run=run, checks=checks,
                  passed=all(checks.values()), response=response, observed=observed,
                  transport_error=transport_error,
                  source_on_disk_sha256=hashlib.sha256((root / "BoberProxy.py").read_bytes()).hexdigest(),
                  note="Loaded Burp source hash and UI settings require separate confirmation.")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(scenario=args.scenario, passed=report["passed"], checks=checks,
                          response_seconds=response["seconds"]), indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
