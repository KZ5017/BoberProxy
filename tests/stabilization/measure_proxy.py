"""Bounded, sequential loopback traffic measurement; not a full EDT/heap test."""
import argparse
import base64
import hashlib
import http.client
import json
import statistics
import time
import uuid
from pathlib import Path

from probe_proxy import exchange, snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--count', type=int, default=1000)
    parser.add_argument('--rate', type=float, default=100)
    parser.add_argument('--proxy-port', type=int, default=8080)
    parser.add_argument('--target-port', type=int, default=18765)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.count <= 1000 or not 0 < args.rate <= 100:
        parser.error('K00 probe is capped at 1000 requests and 100 requests/s')
    run = 'k00-perf-' + uuid.uuid4().hex[:12]
    timings = []
    expected = bytes(range(256)) * 4
    errors = []
    started = time.perf_counter()
    for i in range(args.count):
        due = started + i / args.rate
        time.sleep(max(0, due - time.perf_counter()))
        try:
            response = exchange('/bytes?size=1024', headers=[('X-Bober-Test-Run', run)],
                                proxy_port=args.proxy_port, target_port=args.target_port)
            timings.append(response['seconds'])
            if response['status'] != 200 or base64.b64decode(response['body_base64']) != expected:
                errors.append(dict(index=i, error='Unexpected response bytes/status'))
                break
        except (OSError, ValueError, http.client.HTTPException) as error:
            errors.append(dict(index=i, error=repr(error)))
            break
    elapsed = time.perf_counter() - started
    observed = snapshot(run, args.target_port)
    root = Path(__file__).resolve().parents[2]
    ordered = sorted(timings)
    report = dict(kind='bounded-external-burp-traffic-no-edt-or-heap-instrumentation',
                  source_on_disk_sha256=hashlib.sha256((root / 'BoberProxy.py').read_bytes()).hexdigest(),
                  run=run, requested_count=args.count, target_rate=args.rate,
                  completed_count=len(timings), server_event_count=observed['event_count'],
                  elapsed_seconds=elapsed, errors=errors, timings_seconds=timings,
                  median_seconds=statistics.median(timings) if timings else None,
                  p95_seconds=ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))] if ordered else None,
                  max_seconds=max(timings) if timings else None,
                  passed=not errors and len(timings) == args.count and observed['event_count'] == args.count)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key not in ('timings_seconds',)}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
